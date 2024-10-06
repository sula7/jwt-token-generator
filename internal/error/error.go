package error

import "errors"

var (
	ErrUserNotFound              = errors.New("user not found")
	ErrUnexpectedTokenSignMethod = errors.New("unexpected token sign method")
	ErrInvalidToken              = errors.New("invalid token")
	ErrExpiredToken              = errors.New("expired token")
	ErrTokenNotFound             = errors.New("token not found")
)
