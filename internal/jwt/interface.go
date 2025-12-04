package jwt

import "time"

type TokenManager interface {
	GenerateTokenPair(userID, email, role, orgID string) (string, string, error)
	ValidateToken(tokenString string) (*Claims, error)
	RefreshAccessToken(refreshTokenString string) (string, error)
	GetTokenExpiry(tokenType string) time.Duration
}
