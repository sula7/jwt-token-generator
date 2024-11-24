package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"

	"jwt-token-generator/internal/entity"
	privErr "jwt-token-generator/internal/error"
)

func (s *Storage) SaveTokens(
	ctx context.Context,
	accessToken *entity.AccessToken,
	refreshToken *entity.RefreshToken,
) error {
	queryAccessToken := `
			INSERT INTO access_tokens (token_id, refresh_token_id, user_id, ip_address, issued_at, expires_at)
		  	VALUES ($1, $2, $3, $4, $5, $6)`
	queryRefreshToken := `
			INSERT INTO refresh_tokens (token_id, access_token_id, user_id, ip_address, issued_at, expires_at)
		  	VALUES ($1, $2, $3, $4, $5, $6)`

	batch := &pgx.Batch{}
	batch.Queue(
		queryAccessToken,
		accessToken.TokenId,
		accessToken.RefreshTokenId,
		accessToken.UserId,
		accessToken.IpAddress,
		accessToken.IssuedAt,
		accessToken.ExpiresAt,
	)
	batch.Queue(
		queryRefreshToken,
		refreshToken.TokenId,
		refreshToken.AccessTokenId,
		refreshToken.UserId,
		refreshToken.IpAddress,
		refreshToken.IssuedAt,
		refreshToken.ExpiresAt,
	)

	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}

	br := tx.SendBatch(ctx, batch)
	if err = br.Close(); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("failed to commit and rollback tx: %w", errors.Join(err, rbErr))
		}
		return fmt.Errorf("failed to close batch operation: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("failed to commit and rollback tx: %w", errors.Join(err, rbErr))
		}
		return fmt.Errorf("failed to commit tx: %w", err)
	}

	return nil
}

func (s *Storage) GetTokenById(ctx context.Context, tokenId uuid.UUID) (*entity.RefreshToken, error) {
	query := `
			SELECT token_id, access_token_id, user_id, ip_address, issued_at, expires_at
			FROM refresh_tokens
			WHERE token_id = $1`

	rt := &entity.RefreshToken{}
	err := s.conn.QueryRow(ctx, query, tokenId).Scan(
		&rt.TokenId,
		&rt.AccessTokenId,
		&rt.UserId,
		&rt.IpAddress,
		&rt.IssuedAt,
		&rt.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, privErr.ErrTokenNotFound
		}

		return nil, fmt.Errorf("failed to exec query and scan: %w", err)
	}

	return rt, nil
}

func (s *Storage) RemoveTokenPairByRefreshId(ctx context.Context, refreshTokenId uuid.UUID) error {
	queryAccessToken := `
			DELETE FROM access_tokens
			WHERE refresh_token_id = $1`
	queryRefreshToken := `
			DELETE FROM refresh_tokens
			WHERE token_id = $1`

	batch := &pgx.Batch{}
	batch.Queue(queryAccessToken, refreshTokenId)
	batch.Queue(queryRefreshToken, refreshTokenId)

	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}

	br := tx.SendBatch(ctx, batch)
	if err = br.Close(); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("failed to close batch operation: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("failed to commit tx: %w", err)
	}

	return nil
}

func (s *Storage) RemoveTokenPairByAccessId(ctx context.Context, userId, accessTokenId uuid.UUID) error {
	queryAccessToken := `
			DELETE FROM access_tokens
			WHERE token_id = $1 AND user_id = $2`
	queryRefreshToken := `
			DELETE FROM refresh_tokens
			WHERE access_token_id = $1 AND user_id = $2`

	batch := &pgx.Batch{}
	batch.Queue(queryAccessToken, accessTokenId, userId)
	batch.Queue(queryRefreshToken, accessTokenId, userId)

	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}

	br := tx.SendBatch(ctx, batch)
	if err = br.Close(); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("failed to commit and rollback tx: %w", errors.Join(err, rbErr))
		}
		return fmt.Errorf("failed to close batch operation: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("failed to commit and rollback tx: %w", errors.Join(err, rbErr))
		}
		return fmt.Errorf("failed to commit tx: %w", err)
	}

	return nil
}

func (s *Storage) RemoveExpiredAccessTokens(ctx context.Context) error {
	query := `
				DELETE FROM access_tokens
				WHERE expires_at < now()`

	if _, err := s.conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to exec query: %w", err)
	}

	return nil
}

func (s *Storage) RemoveExpiredRefreshTokens(ctx context.Context) error {
	query := `
				DELETE FROM refresh_tokens
				WHERE expires_at < now()`

	if _, err := s.conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to exec query: %w", err)
	}

	return nil
}
