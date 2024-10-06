package config

import (
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/env"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Config struct {
	PostgresDsn     string        `env:"POSTGRES_DSN,required"`
	ListenAddr      string        `env:"LISTEN_ADDR" envDefault:":8080"`
	TokenSecret     string        `env:"TOKEN_SECRET,required"`
	AccessTokenTtl  time.Duration `env:"ACCESS_TOKEN_TTL" envDefault:"30m"`
	RefreshTokenTtl time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"2h"`
}

func New() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

func Zerolog() {
	level, _ := os.LookupEnv("LOG_LEVEL")
	if len(level) == 0 {
		level = "info"
	}

	zeroLvl, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Fatal().Msgf("failed to init logger: %v", err)
	}

	zerolog.SetGlobalLevel(zeroLvl)
	log.Info().Msgf("log level is set to %s", level)
}
