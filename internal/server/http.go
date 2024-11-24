package server

import (
	"github.com/gin-gonic/gin"

	"jwt-token-generator/internal/config"
	"jwt-token-generator/internal/service/token"
)

type Server struct {
	config   *config.Config
	tokenSvc *token.Service
}

func Start(cfg *config.Config, tokenSvc *token.Service) error {
	s := &Server{config: cfg, tokenSvc: tokenSvc}

	g := gin.New()
	g.GET("/:user_id/token", s.handleGenerateTokens)
	g.DELETE("/:user_id/token", s.handleLogout)
	g.POST("/:user_id/token/refresh", s.handleRefreshToken)

	return g.Run(cfg.ListenAddr)
}
