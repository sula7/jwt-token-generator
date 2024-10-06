package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"

	"jwt-token-generator/internal/entity"
	privErr "jwt-token-generator/internal/error"
)

func (s *Service) GenerateTokenPair(
	ctx context.Context,
	userId uuid.UUID,
	ipAddr string,
) (*entity.AuthJwtToken, error) {
	isUserExist, err := s.storage.IsUserExist(ctx, userId)
	if err != nil {
		if errors.Is(err, privErr.ErrUserNotFound) {
			return nil, privErr.ErrUserNotFound
		}

		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if !isUserExist {
		return nil, privErr.ErrUserNotFound
	}

	tokensPair, err := s.generateTokensPair(userId, ipAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens pair: %w", err)
	}

	if err = s.storage.SaveTokens(ctx, tokensPair.AccessToken, tokensPair.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to save tokens: %w", err)
	}

	return tokensPair.ToAuthJwtToken(), nil
}

func (s *Service) RefreshToken(
	ctx context.Context,
	token string,
	userId uuid.UUID,
	ipAddr string,
) (*entity.AuthJwtToken, error) {
	isUserExist, err := s.storage.IsUserExist(ctx, userId)
	if err != nil {
		if errors.Is(err, privErr.ErrUserNotFound) {
			return nil, privErr.ErrUserNotFound
		}

		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if !isUserExist {
		return nil, privErr.ErrUserNotFound
	}

	rawToken, err := s.parseToken(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !rawToken.Valid {
		return nil, privErr.ErrInvalidToken
	}

	refreshToken, err := s.extractToken(rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to extract token: %w", err)
	}

	if refreshToken.IsExpired() {
		return nil, privErr.ErrExpiredToken
	}

	storedRefreshToken, err := s.storage.GetTokenById(ctx, refreshToken.TokenId)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if storedRefreshToken.ExpiresAt.Equal(refreshToken.ExpiresAt) {
		return nil, privErr.ErrInvalidToken
	}

	if storedRefreshToken.UserId != refreshToken.UserId {
		return nil, privErr.ErrInvalidToken
	}

	if storedRefreshToken.IpAddress != refreshToken.IpAddress {
		if err = s.notifyUserByEmail(ctx); err != nil {
			return nil, fmt.Errorf("failed to notify user about ip difference by email: %w", err)
		}
	}

	tokensPair, err := s.generateTokensPair(userId, ipAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens pair: %w", err)
	}

	if err = s.storage.SaveTokens(ctx, tokensPair.AccessToken, tokensPair.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to save tokens: %w", err)
	}

	if err = s.storage.RemoveTokenById(ctx, refreshToken.TokenId); err != nil {
		return nil, fmt.Errorf("failed to remove token: %w", err)
	}

	return tokensPair.ToAuthJwtToken(), nil
}

func (s *Service) generateTokensPair(userId uuid.UUID, ipAddr string) (*entity.AccessRefreshToken, error) {
	accessToken, err := s.generateAccessToken(userId, ipAddr)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken(userId, ipAddr)
	if err != nil {
		return nil, err
	}

	accessToken.RefreshTokenId = refreshToken.TokenId
	refreshToken.AccessTokenId = accessToken.TokenId

	return &entity.AccessRefreshToken{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *Service) generateAccessToken(userId uuid.UUID, ipAddr string) (*entity.AccessToken, error) {
	tokenId, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("failed to generate uuid_v4: %w", err)
	}
	now := time.Now()
	expiresAt := now.Add(s.config.AccessTokenTtl)
	claims := jwt.MapClaims{
		"jti": tokenId,
		"sub": userId,
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
		"ip":  ipAddr,
	}

	at := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	value, err := at.SignedString([]byte(s.config.TokenSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	token := &entity.AccessToken{
		TokenId:   tokenId,
		UserId:    userId,
		IpAddress: ipAddr,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		Value:     value,
	}

	return token, nil
}

func (s *Service) generateRefreshToken(userId uuid.UUID, ipAddr string) (*entity.RefreshToken, error) {
	tokenId, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("failed to generate uuid_v4: %w", err)
	}
	now := time.Now()
	expiresAt := now.Add(s.config.RefreshTokenTtl)
	claims := jwt.MapClaims{
		"jti": tokenId,
		"sub": userId,
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
		"ip":  ipAddr,
	}

	at := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	value, err := at.SignedString([]byte(s.config.TokenSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	token := &entity.RefreshToken{
		TokenId:   tokenId,
		UserId:    userId,
		IpAddress: ipAddr,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		Value:     value,
	}

	return token, nil
}

func (s *Service) parseToken(tokenStr string) (*jwt.Token, error) {
	tkn, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, privErr.ErrUnexpectedTokenSignMethod
		}
		return []byte(s.config.TokenSecret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, privErr.ErrExpiredToken
		}
	}

	return tkn, nil
}

func (s *Service) extractToken(token *jwt.Token) (*entity.RefreshToken, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}

	var err error
	refreshToken := &entity.RefreshToken{}
	jtiRaw, ok := claims["jti"].(string)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}
	refreshToken.TokenId, err = uuid.FromString(jtiRaw)
	if err != nil {
		return nil, privErr.ErrInvalidToken
	}

	subRaw, ok := claims["sub"].(string)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}
	refreshToken.UserId, err = uuid.FromString(subRaw)
	if err != nil {
		return nil, privErr.ErrInvalidToken
	}

	expRaw, ok := claims["exp"].(float64)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}
	refreshToken.ExpiresAt = time.Unix(int64(expRaw), 0)

	refreshToken.IpAddress, ok = claims["ip"].(string)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}

	return refreshToken, nil
}

func (s *Service) notifyUserByEmail(_ context.Context) error {
	log.Warn().Msg("notify user by email is not implemented")
	return nil
}

func (s *Service) TokenTruncater(ctx context.Context) {
	log.Debug().Msg("starting token truncater")

	log.Debug().Msg("truncating tokens")
	if err := s.storage.RemoveExpiredAccessTokens(ctx); err != nil {
		log.Error().Err(err).Msg("failed to remove expired access tokens")
	}

	if err := s.storage.RemoveExpiredRefreshTokens(ctx); err != nil {
		log.Error().Err(err).Msg("failed to remove expired refresh tokens")
	}

	ticket := time.NewTicker(time.Hour / 2)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("stopping token truncater")
			return
		case <-ticket.C:
			log.Debug().Msg("truncating tokens")
			if err := s.storage.RemoveExpiredAccessTokens(ctx); err != nil {
				log.Error().Err(err).Msg("failed to remove expired access tokens")
			}

			if err := s.storage.RemoveExpiredRefreshTokens(ctx); err != nil {
				log.Error().Err(err).Msg("failed to remove expired refresh tokens")
			}
		}
	}
}
