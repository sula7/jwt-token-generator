package server

import (
	"github.com/gin-gonic/gin"

	"jwt-token-generator/internal/config"
	"jwt-token-generator/internal/service"
)

type Server struct {
	config  *config.Config
	service *service.Service
}

func Start(cfg *config.Config, svc *service.Service) error {
	s := &Server{config: cfg, service: svc}

	g := gin.New()
	g.GET("/:user_id/token", s.handleGenerateTokens)
	g.POST("/:user_id/token/refresh", s.handleRefreshToken)

	return g.Run(cfg.ListenAddr)
}
