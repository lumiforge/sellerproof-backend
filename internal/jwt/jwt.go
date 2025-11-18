package jwt

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims представляет структуру claims в JWT токене
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	OrgID  string `json:"org_id"`
	jwt.RegisteredClaims
}

// JWTManager управляет JWT токенами
type JWTManager struct {
	secretKey     string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// NewJWTManager создает новый JWT менеджер
func NewJWTManager() *JWTManager {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		secretKey = "default-secret-key-change-in-production"
	}

	return &JWTManager{
		secretKey:     secretKey,
		accessExpiry:  time.Hour * 24,     // 24 часа
		refreshExpiry: time.Hour * 24 * 7, // 7 дней
	}
}

// GenerateTokenPair генерирует пару access и refresh токенов
func (j *JWTManager) GenerateTokenPair(userID, email, role, orgID string) (string, string, error) {
	// Генерация access токена
	accessToken, err := j.generateToken(userID, email, role, orgID, j.accessExpiry)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Генерация refresh токена
	refreshToken, err := j.generateToken(userID, email, role, orgID, j.refreshExpiry)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// generateToken генерирует JWT токен с указанным сроком действия
func (j *JWTManager) generateToken(userID, email, role, orgID string, expiry time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		OrgID:  orgID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secretKey))
}

// ValidateToken валидирует JWT токен и возвращает claims
func (j *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// RefreshAccessToken генерирует новый access токен из refresh токена
func (j *JWTManager) RefreshAccessToken(refreshTokenString string) (string, error) {
	claims, err := j.ValidateToken(refreshTokenString)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Генерируем новый access токен с теми же claims
	accessToken, err := j.generateToken(claims.UserID, claims.Email, claims.Role, claims.OrgID, j.accessExpiry)
	if err != nil {
		return "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	return accessToken, nil
}

// GetTokenExpiry возвращает время истечения токена
func (j *JWTManager) GetTokenExpiry(tokenType string) time.Duration {
	switch tokenType {
	case "access":
		return j.accessExpiry
	case "refresh":
		return j.refreshExpiry
	default:
		return j.accessExpiry
	}
}

// ExtractTokenFromHeader извлекает токен из Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is empty")
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", fmt.Errorf("authorization header format must be Bearer {token}")
	}

	return authHeader[len(bearerPrefix):], nil
}
