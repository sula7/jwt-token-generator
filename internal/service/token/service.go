package token

import (
	"jwt-token-generator/internal/config"
	"jwt-token-generator/internal/storage/postgres"
)

type Service struct {
	config  *config.Config
	storage *postgres.Storage
}

func NewService(cfg *config.Config, pg *postgres.Storage) *Service {
	return &Service{config: cfg, storage: pg}
}
