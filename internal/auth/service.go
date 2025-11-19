package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/lumiforge/sellerproof-backend/internal/email"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	jwtmanager "github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

// Service реализует бизнес-логику аутентификации
type Service struct {
	db         ydb.Database
	jwtManager *jwtmanager.JWTManager
	rbac       *rbac.RBAC
	email      *email.Client
}

// NewService создает новый auth сервис
func NewService(db ydb.Database, jwtManager *jwtmanager.JWTManager, rbacManager *rbac.RBAC, emailClient *email.Client) *Service {
	return &Service{
		db:         db,
		jwtManager: jwtManager,
		rbac:       rbacManager,
		email:      emailClient,
	}
}

// RegisterRequest запрос на регистрацию
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
}

// RegisterResponse ответ на регистрацию
type RegisterResponse struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

// Register регистрирует нового пользователя
func (s *Service) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	// Валидация email
	if !email.ValidateEmail(req.Email) {
		return nil, fmt.Errorf("invalid email format")
	}

	// Проверка, что email не занят
	existingUser, err := s.db.GetUserByEmail(ctx, req.Email)
	// TODO: Remove this log after debugging
	log.Println("GetUserByEmail result", "err", err, "existingUser", existingUser)

	if err == nil && existingUser != nil {
		return nil, fmt.Errorf("email already exists")
	}

	// Хеширование пароля
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Генерация кода верификации
	verificationCode, err := email.GenerateVerificationCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification code: %w", err)
	}

	// Создание пользователя
	passwordHashStr := string(passwordHash)
	user := &ydb.User{
		UserID:                uuid.New().String(),
		Email:                 req.Email,
		PasswordHash:          &passwordHashStr,
		FullName:              &req.FullName,
		EmailVerified:         false,
		VerificationCode:      &verificationCode,
		VerificationExpiresAt: &time.Time{},
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
		IsActive:              true,
	}
	*user.VerificationExpiresAt = time.Now().Add(24 * time.Hour)

	err = s.db.CreateUser(ctx, user)
	if err != nil {
		// Check if error is due to duplicate email (UNIQUE constraint violation)
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique constraint") {
			return nil, fmt.Errorf("email already exists")
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Отправка email верификации
	if s.email.IsConfigured() {
		emailMessage, err := s.email.SendVerificationEmail(ctx, req.Email, verificationCode)
		if err != nil {
			// Логируем ошибку, но не прерываем регистрацию
			slog.Error("Failed to send verification email", "error", err, "email", req.Email)
		} else {
			// Сохраняем лог email в базу
			emailType := string(email.EmailTypeVerification)
			status := string(emailMessage.Status)
			emailLog := &ydb.EmailLog{
				EmailID:          emailMessage.ID,
				UserID:           user.UserID,
				EmailType:        &emailType,
				Recipient:        &req.Email,
				Status:           &status,
				PostboxMessageID: &emailMessage.MessageID,
				SentAt:           emailMessage.SentAt,
				ErrorMessage:     emailMessage.Error,
			}
			s.db.CreateEmailLog(ctx, emailLog)
		}
	}

	// Создание персональной организации для пользователя
	orgName := fmt.Sprintf("%s's Organization", req.FullName)
	settings := make(map[string]string)
	org := &ydb.Organization{
		OrgID:     uuid.New().String(),
		Name:      &orgName,
		OwnerID:   &user.UserID,
		Settings:  &settings,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = s.db.CreateOrganization(ctx, org)
	if err != nil {
		slog.Error("Failed to create organization", "error", err, "user_id", user.UserID)
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	// Создание членства в организации с ролью admin
	role := string(rbac.RoleAdmin)
	status := "active"
	membership := &ydb.Membership{
		MembershipID: uuid.New().String(),
		UserID:       user.UserID,
		OrgID:        org.OrgID,
		Role:         &role,
		Status:       &status,
		InvitedBy:    &user.UserID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err = s.db.CreateMembership(ctx, membership)
	if err != nil {
		slog.Error("Failed to create membership", "error", err, "user_id", user.UserID)
	}

	// Создание триальной подписки
	planID := "free"
	storageLimitGB := int64(1)
	videoCountLimit := int64(10)
	isActive := true
	trialEndsAt := time.Now().Add(7 * 24 * time.Hour)
	subscription := &ydb.Subscription{
		SubscriptionID:  uuid.New().String(),
		UserID:          user.UserID,
		OrgID:           org.OrgID,
		PlanID:          &planID,
		StorageLimitGB:  &storageLimitGB,
		VideoCountLimit: &videoCountLimit,
		IsActive:        &isActive,
		TrialEndsAt:     &trialEndsAt,
		StartedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(30 * 24 * time.Hour), // 30 дней
		BillingCycle:    "monthly",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	err = s.db.CreateSubscription(ctx, subscription)
	if err != nil {
		slog.Error("Failed to create subscription", "error", err, "user_id", user.UserID)
	}

	return &RegisterResponse{
		UserID:  user.UserID,
		Message: "Registration successful. Please check your email for verification.",
	}, nil
}

// VerifyEmailRequest запрос на верификацию email
type VerifyEmailRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// VerifyEmailResponse ответ на верификацию email
type VerifyEmailResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// VerifyEmail подтверждает email пользователя
func (s *Service) VerifyEmail(ctx context.Context, req *VerifyEmailRequest) (*VerifyEmailResponse, error) {
	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Проверка кода верификации
	if user.VerificationCode == nil || *user.VerificationCode != req.Code {
		return nil, fmt.Errorf("invalid verification code")
	}

	// Проверка срока действия кода
	if user.VerificationExpiresAt == nil || time.Now().After(*user.VerificationExpiresAt) {
		return nil, fmt.Errorf("verification code expired")
	}

	// Обновление статуса верификации
	user.EmailVerified = true
	emptyStr := ""
	user.VerificationCode = &emptyStr // Очищаем код
	user.UpdatedAt = time.Now()

	err = s.db.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &VerifyEmailResponse{
		Message: "Email verified successfully",
		Success: true,
	}, nil
}

// LoginRequest запрос на вход
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse ответ на вход
type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    int64     `json:"expires_at"`
	User         *UserInfo `json:"user"`
}

// UserInfo информация о пользователе
type UserInfo struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	FullName      string `json:"full_name"`
	Role          string `json:"role"`
	OrgID         string `json:"org_id"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
}

// Login выполняет вход пользователя
func (s *Service) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Проверка пароля
	if user.PasswordHash == nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	err = bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.Password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Проверка, что пользователь активен
	if !user.IsActive {
		return nil, fmt.Errorf("user account is deactivated")
	}

	// Получение членства в организации
	membership, err := s.db.GetMembership(ctx, user.UserID, user.UserID) // Владелец организации
	if err != nil {
		return nil, fmt.Errorf("failed to get user membership: %w", err)
	}

	// Генерация JWT токенов
	role := ""
	if membership.Role != nil {
		role = *membership.Role
	}
	accessToken, refreshToken, err := s.jwtManager.GenerateTokenPair(
		user.UserID,
		user.Email,
		role,
		membership.OrgID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Сохранение refresh токена в базу
	tokenHash := s.hashToken(refreshToken)
	expiresAt := time.Now().Add(s.jwtManager.GetTokenExpiry("refresh"))
	createdAt := time.Now()
	refreshTokenRecord := &ydb.RefreshToken{
		TokenID:   uuid.New().String(),
		UserID:    user.UserID,
		TokenHash: &tokenHash,
		ExpiresAt: &expiresAt,
		CreatedAt: &createdAt,
		IsRevoked: false,
	}

	err = s.db.CreateRefreshToken(ctx, refreshTokenRecord)
	if err != nil {
		slog.Error("Failed to save refresh token", "error", err, "user_id", user.UserID)
	}

	fullName := ""
	if user.FullName != nil {
		fullName = *user.FullName
	}
	role = ""
	if membership.Role != nil {
		role = *membership.Role
	}
	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.jwtManager.GetTokenExpiry("access")).Unix(),
		User: &UserInfo{
			UserID:        user.UserID,
			Email:         user.Email,
			FullName:      fullName,
			Role:          role,
			OrgID:         membership.OrgID,
			EmailVerified: user.EmailVerified,
			CreatedAt:     user.CreatedAt.Unix(),
			UpdatedAt:     user.UpdatedAt.Unix(),
		},
	}, nil
}

// RefreshTokenRequest запрос на обновление токена
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenResponse ответ на обновление токена
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// RefreshToken обновляет access токен
func (s *Service) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	// Валидация refresh токена
	claims, err := s.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Проверка токена в базе
	tokenHash := s.hashToken(req.RefreshToken)
	tokenRecord, err := s.db.GetRefreshToken(ctx, tokenHash)
	if err != nil || tokenRecord == nil || tokenRecord.IsRevoked {
		return nil, fmt.Errorf("refresh token not found or revoked")
	}

	// Генерация новой пары токенов
	accessToken, refreshToken, err := s.jwtManager.GenerateTokenPair(
		claims.UserID,
		claims.Email,
		claims.Role,
		claims.OrgID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new tokens: %w", err)
	}

	// Отзыв старого токена
	s.db.RevokeRefreshToken(ctx, tokenHash)

	// Сохранение нового refresh токена
	newTokenHash := s.hashToken(refreshToken)
	newExpiresAt := time.Now().Add(s.jwtManager.GetTokenExpiry("refresh"))
	newCreatedAt := time.Now()
	newTokenRecord := &ydb.RefreshToken{
		TokenID:   uuid.New().String(),
		UserID:    claims.UserID,
		TokenHash: &newTokenHash,
		ExpiresAt: &newExpiresAt,
		CreatedAt: &newCreatedAt,
		IsRevoked: false,
	}

	err = s.db.CreateRefreshToken(ctx, newTokenRecord)
	if err != nil {
		slog.Error("Failed to save new refresh token", "error", err, "user_id", claims.UserID)
	}

	return &RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.jwtManager.GetTokenExpiry("access")).Unix(),
	}, nil
}

// LogoutRequest запрос на выход
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// LogoutResponse ответ на выход
type LogoutResponse struct {
	Message string `json:"message"`
}

// Logout выполняет выход пользователя
func (s *Service) Logout(ctx context.Context, req *LogoutRequest) (*LogoutResponse, error) {
	// Отзыв refresh токена
	tokenHash := s.hashToken(req.RefreshToken)
	err := s.db.RevokeRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return &LogoutResponse{
		Message: "Logout successful",
	}, nil
}

// GetProfileRequest запрос на получение профиля
type GetProfileRequest struct {
	UserID string `json:"user_id"`
}

// GetProfileResponse ответ с информацией о профиле
type GetProfileResponse struct {
	User *UserInfo `json:"user"`
}

// GetProfile получает профиль пользователя
func (s *Service) GetProfile(ctx context.Context, userID string) (*GetProfileResponse, error) {
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Получение членства в организации
	membership, err := s.db.GetMembership(ctx, user.UserID, user.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user membership: %w", err)
	}

	fullName := ""
	if user.FullName != nil {
		fullName = *user.FullName
	}
	role := ""
	if membership.Role != nil {
		role = *membership.Role
	}
	return &GetProfileResponse{
		User: &UserInfo{
			UserID:        user.UserID,
			Email:         user.Email,
			FullName:      fullName,
			Role:          role,
			OrgID:         membership.OrgID,
			EmailVerified: user.EmailVerified,
			CreatedAt:     user.CreatedAt.Unix(),
			UpdatedAt:     user.UpdatedAt.Unix(),
		},
	}, nil
}

// hashToken хеширует токен для хранения в базе
func (s *Service) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash)
}

// ValidateToken валидирует JWT токен и возвращает claims
func (s *Service) ValidateToken(tokenString string) (*jwt.Claims, error) {
	return s.jwtManager.ValidateToken(tokenString)
}

// CheckPermission проверяет разрешение пользователя
func (s *Service) CheckPermission(ctx context.Context, userID, orgID string, permission rbac.Permission) (bool, error) {
	// Получение роли пользователя
	membership, err := s.db.GetMembership(ctx, userID, orgID)
	if err != nil {
		return false, fmt.Errorf("failed to get user membership: %w", err)
	}

	roleStr := ""
	if membership.Role != nil {
		roleStr = *membership.Role
	}
	role := rbac.Role(roleStr)
	return s.rbac.CheckPermissionWithRole(role, permission), nil
}
