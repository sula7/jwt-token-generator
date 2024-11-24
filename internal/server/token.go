package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"

	privErr "jwt-token-generator/internal/error"
)

func (s *Server) handleGenerateTokens(c *gin.Context) {
	userId, err := uuid.FromString(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "wrong user id format"})
		return
	}

	log.Debug().Str("user_id", userId.String()).Msg("got user uuid")

	authJwtToken, err := s.tokenSvc.GenerateTokenPair(c.Request.Context(), userId, c.RemoteIP())
	if err != nil {
		if errors.Is(err, privErr.ErrUserNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
			return
		}

		log.Error().Err(err).Msg("failed to generate tokens")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	log.Debug().Msg("generated pair of tokens")

	c.JSON(http.StatusOK, gin.H{"access_token": authJwtToken.AccessToken, "refresh_token": authJwtToken.RefreshToken})
}

func (s *Server) handleRefreshToken(c *gin.Context) {
	userId, err := uuid.FromString(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "wrong user id format"})
		return
	}

	log.Debug().Str("user_id", userId.String()).Msg("got user uuid")

	authParts := strings.Split(c.GetHeader("Authorization"), " ")
	if len(authParts) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "wrong token header"})
		return
	}

	authJwtToken, err := s.tokenSvc.RefreshToken(
		c.Request.Context(),
		authParts[1],
		userId,
		c.RemoteIP(),
	)
	if err != nil {
		if errors.Is(err, privErr.ErrUserNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
			return
		}

		if errors.Is(err, privErr.ErrUnexpectedTokenSignMethod) || errors.Is(err, privErr.ErrInvalidToken) ||
			errors.Is(err, privErr.ErrTokenNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token"})
			return
		}

		if errors.Is(err, privErr.ErrExpiredToken) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "expired token"})
			return
		}

		log.Error().Err(err).Msg("failed to generate tokens")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	log.Debug().Msg("refreshed token")

	c.JSON(http.StatusOK, gin.H{"access_token": authJwtToken.AccessToken, "refresh_token": authJwtToken.RefreshToken})
}

func (s *Server) handleLogout(c *gin.Context) {
	userId, err := uuid.FromString(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "wrong user id format"})
		return
	}

	log.Debug().Str("user_id", userId.String()).Msg("got user uuid")

	authParts := strings.Split(c.GetHeader("Authorization"), " ")
	if len(authParts) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "wrong token header"})
		return
	}

	err = s.tokenSvc.ExpireTokenPair(c.Request.Context(), userId, authParts[1], c.RemoteIP())
	if err != nil {
		if errors.Is(err, privErr.ErrUserNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
			return
		}

		if errors.Is(err, privErr.ErrUnexpectedTokenSignMethod) || errors.Is(err, privErr.ErrInvalidToken) ||
			errors.Is(err, privErr.ErrTokenNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token"})
			return
		}

		if errors.Is(err, privErr.ErrExpiredToken) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "expired token"})
			return
		}

		log.Error().Err(err).Msg("failed to logout user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
}
