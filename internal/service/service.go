package service

import (
	"jwt-token-generator/internal/config"
	"jwt-token-generator/internal/storage/postgres"
)

type Service struct {
	config  *config.Config
	storage *postgres.Storage
}

func New(cfg *config.Config, pg *postgres.Storage) *Service {
	return &Service{config: cfg, storage: pg}
}
