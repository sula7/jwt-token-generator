package entity

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type (
	AccessToken struct {
		TokenId        uuid.UUID
		RefreshTokenId uuid.UUID
		UserId         uuid.UUID
		IpAddress      string
		IssuedAt       time.Time
		ExpiresAt      time.Time
		Value          string
	}

	RefreshToken struct {
		TokenId       uuid.UUID
		AccessTokenId uuid.UUID
		UserId        uuid.UUID
		IpAddress     string
		IssuedAt      time.Time
		ExpiresAt     time.Time
		Value         string
	}

	AccessRefreshToken struct {
		AccessToken  *AccessToken
		RefreshToken *RefreshToken
	}

	AuthJwtToken struct {
		AccessToken  string
		RefreshToken string
	}
)

func (e *AccessRefreshToken) ToAuthJwtToken() *AuthJwtToken {
	return &AuthJwtToken{AccessToken: e.AccessToken.Value, RefreshToken: e.RefreshToken.Value}
}

func (e *RefreshToken) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}
