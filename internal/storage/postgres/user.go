package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/gofrs/uuid/v5"

	privErr "jwt-token-generator/internal/error"
)

func (s *Storage) IsUserExist(ctx context.Context, id uuid.UUID) (bool, error) {
	query := `SELECT true FROM users WHERE id = $1`

	var isUserExist bool
	err := s.conn.QueryRow(ctx, query, id).Scan(&isUserExist)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, privErr.ErrUserNotFound
		}

		return false, fmt.Errorf("failed to run query and scan: %w", err)
	}

	return isUserExist, nil
}
