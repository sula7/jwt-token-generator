package main

import (
	"context"

	"github.com/rs/zerolog/log"

	"jwt-token-generator/internal/config"
	"jwt-token-generator/internal/server"
	"jwt-token-generator/internal/service/token"
	"jwt-token-generator/internal/storage/postgres"
)

func main() {
	config.Zerolog()
	log.Info().Msg("starting")
	defer log.Info().Msg("finishing...")

	cfg, err := config.New()
	if err != nil {
		log.Error().Err(err).Msg("failed to init config")
		return
	}

	ctx := context.Background()
	pg, err := postgres.New(ctx, cfg.PostgresDsn)
	if err != nil {
		log.Error().Err(err).Msg("failed to init postgres")
		return
	}

	defer pg.Close()

	tokenSvc := token.NewService(cfg, pg)
	go tokenSvc.TokenTruncater(ctx)

	if err = server.Start(cfg, tokenSvc); err != nil {
		log.Error().Err(err).Msg("failed to start server")
		return
	}
}
