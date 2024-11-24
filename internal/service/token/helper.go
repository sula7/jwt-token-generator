package token

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

func (s *Service) extractRefreshToken(token *jwt.Token) (*entity.RefreshToken, error) {
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

func (s *Service) extractAccessToken(token *jwt.Token) (*entity.AccessToken, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}

	var err error
	accessToken := &entity.AccessToken{}
	jtiRaw, ok := claims["jti"].(string)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}
	accessToken.TokenId, err = uuid.FromString(jtiRaw)
	if err != nil {
		return nil, privErr.ErrInvalidToken
	}

	subRaw, ok := claims["sub"].(string)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}
	accessToken.UserId, err = uuid.FromString(subRaw)
	if err != nil {
		return nil, privErr.ErrInvalidToken
	}

	expRaw, ok := claims["exp"].(float64)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}
	accessToken.ExpiresAt = time.Unix(int64(expRaw), 0)

	accessToken.IpAddress, ok = claims["ip"].(string)
	if !ok {
		return nil, privErr.ErrInvalidToken
	}

	return accessToken, nil
}

func (s *Service) notifyUserByEmail(_ context.Context) error {
	log.Warn().Msg("notify user by email is not implemented")
	return nil
}
