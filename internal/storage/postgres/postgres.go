package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	conn *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*Storage, error) {
	conn, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err = conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Storage{conn: conn}, nil
}

func (s *Storage) Close() error {
	if s != nil {
		s.conn.Close()
	}

	return nil
}
