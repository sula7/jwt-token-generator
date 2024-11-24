package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
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

	refreshToken, err := s.extractRefreshToken(rawToken)
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

	if err = s.storage.RemoveTokenPairByRefreshId(ctx, refreshToken.TokenId); err != nil {
		return nil, fmt.Errorf("failed to remove token: %w", err)
	}

	return tokensPair.ToAuthJwtToken(), nil
}

func (s *Service) ExpireTokenPair(ctx context.Context, userId uuid.UUID, token, ipAddr string) error {
	isUserExist, err := s.storage.IsUserExist(ctx, userId)
	if err != nil {
		if errors.Is(err, privErr.ErrUserNotFound) {
			return privErr.ErrUserNotFound
		}

		return fmt.Errorf("failed to find user: %w", err)
	}

	if !isUserExist {
		return privErr.ErrUserNotFound
	}

	rawToken, err := s.parseToken(token)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if !rawToken.Valid {
		return privErr.ErrInvalidToken
	}

	accToken, err := s.extractAccessToken(rawToken)
	if err != nil {
		return fmt.Errorf("failed to extract access token: %w", err)
	}

	log.Debug().Msg("extracted access token")

	err = s.storage.RemoveTokenPairByAccessId(ctx, accToken.UserId, accToken.TokenId)
	if err != nil {
		return fmt.Errorf("failed to remove token pair: %w", err)
	}

	log.Debug().Msg("removed token pair")

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
