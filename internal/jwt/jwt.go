package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/config"
	app_errors "github.com/lumiforge/sellerproof-backend/internal/errors"
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
func NewJWTManager(cfg *config.Config) *JWTManager {
	if cfg.JWTSecretKey == "" {
		return nil
	}
	return &JWTManager{
		secretKey:     cfg.JWTSecretKey,
		accessExpiry:  time.Hour * 24,     // 24 часа
		refreshExpiry: time.Hour * 24 * 7, // 7 дней
	}
}

// GenerateTokenPair генерирует пару access и refresh токенов
func (j *JWTManager) GenerateTokenPair(userID, email, role, orgID string) (string, string, error) {
	// Генерация access токена
	accessToken, err := j.generateToken(userID, email, role, orgID, j.accessExpiry)
	if err != nil {
		return "", "", app_errors.ErrFailedToGenerateAccessToken
	}

	// Генерация refresh токена
	refreshToken, err := j.generateToken(userID, email, role, orgID, j.refreshExpiry)
	if err != nil {
		return "", "", app_errors.ErrFailedToGenerateRefreshToken
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
			return nil, app_errors.ErrUnexpectedSigningMethod
		}
		return []byte(j.secretKey), nil
	})

	if err != nil {
		return nil, app_errors.ErrFailedToParseToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, app_errors.ErrInvalidToken
	}

	return claims, nil
}

// RefreshAccessToken генерирует новый access токен из refresh токена
func (j *JWTManager) RefreshAccessToken(refreshTokenString string) (string, error) {
	claims, err := j.ValidateToken(refreshTokenString)
	if err != nil {
		return "", app_errors.ErrInvalidRefreshToken
	}

	// Генерируем новый access токен с теми же claims
	accessToken, err := j.generateToken(claims.UserID, claims.Email, claims.Role, claims.OrgID, j.accessExpiry)
	if err != nil {
		return "", app_errors.ErrFailedToGenerateNewTokens
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
		return "", app_errors.ErrAuthHeaderEmpty
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", app_errors.ErrAuthHeaderWrongFormat
	}

	return authHeader[len(bearerPrefix):], nil
}
