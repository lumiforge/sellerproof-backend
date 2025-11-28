package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"

	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/lumiforge/sellerproof-backend/internal/config"
	"github.com/lumiforge/sellerproof-backend/internal/email"
	jwtmanager "github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/validation"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

// Service реализует бизнес-логику аутентификации
type Service struct {
	db         ydb.Database
	jwtManager *jwtmanager.JWTManager
	rbac       *rbac.RBAC
	email      *email.Client
	config     *config.Config
}

// NewService создает новый auth сервис
func NewService(db ydb.Database, jwtManager *jwtmanager.JWTManager, rbacManager *rbac.RBAC, emailClient *email.Client, cfg *config.Config) *Service {

	return &Service{
		db:         db,
		jwtManager: jwtManager,
		rbac:       rbacManager,
		email:      emailClient,
		config:     cfg,
	}
}

// Register регистрирует нового пользователя
func (s *Service) Register(ctx context.Context, req *models.RegisterRequest) (*models.RegisterResponse, error) {
	// Валидация обязательных полей
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return nil, fmt.Errorf("password is required")
	}
	if req.FullName == "" {
		return nil, fmt.Errorf("full_name is required")
	}
	if req.OrganizationName == "" && req.InviteCode == "" {
		return nil, fmt.Errorf("organization_name or invite_code is required")
	}

	// Валидация email используя validation package
	if err := validation.ValidateEmail(req.Email, "email"); err != nil {
		return nil, err
	}

	// Валидация пароля
	if len(req.Password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters long")
	}
	if len(req.Password) > 72 {
		return nil, fmt.Errorf("password must be less than 73 characters long")
	}

	// Валидация имени
	if len(req.FullName) < 2 {
		return nil, fmt.Errorf("full_name must be at least 2 characters long")
	}
	if len(req.FullName) > 100 {
		return nil, fmt.Errorf("full_name must be less than 101 characters long")
	}

	// Валидация организации
	if req.OrganizationName != "" && len(req.OrganizationName) > 200 {
		return nil, fmt.Errorf("organization_name must be less than 201 characters long")
	}

	// Валидация безопасности используя validation package
	// Для имени отключаем Unicode проверку, чтобы разрешить кириллицу
	emailOptions := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)

	passwordOptions := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)

	// Для имени и организации отключаем Unicode проверку, чтобы разрешить кириллицу
	nameOptions := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)

	// Проверка email на инъекции
	if err := validation.ValidateInputWithError(req.Email, "email", emailOptions); err != nil {
		return nil, err
	}

	// Проверка пароля на инъекции
	if err := validation.ValidateInputWithError(req.Password, "password", passwordOptions); err != nil {
		return nil, err
	}

	// Проверка имени на инъекции (без Unicode проверки)
	if err := validation.ValidateInputWithError(req.FullName, "full_name", nameOptions); err != nil {
		return nil, err
	}

	// Проверка организации на инъекции (без Unicode проверки)
	if req.OrganizationName != "" {
		if err := validation.ValidateInputWithError(req.OrganizationName, "organization_name", nameOptions); err != nil {
			return nil, err
		}
	}

	// Если передан код приглашения, проверяем его валидность ДО создания пользователя
	var invitation *ydb.Invitation
	if req.InviteCode != "" {
		inv, err := s.db.GetInvitationByCode(ctx, req.InviteCode)
		if err != nil {
			return nil, fmt.Errorf("invalid invite code")
		}
		if inv.Status != "pending" {
			return nil, fmt.Errorf("invitation is not pending")
		}
		if time.Now().After(inv.ExpiresAt) {
			return nil, fmt.Errorf("invitation has expired")
		}
		// Проверяем, что email регистрации совпадает с приглашением
		if !strings.EqualFold(inv.Email, req.Email) {
			return nil, fmt.Errorf("registration email does not match invitation email")
		}
		invitation = inv
	}

	// Проверка, что email не занят
	existingUser, err := s.db.GetUserByEmail(ctx, req.Email)

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
		PasswordHash:          passwordHashStr,
		FullName:              req.FullName,
		EmailVerified:         false,
		VerificationCode:      verificationCode,
		VerificationExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
		IsActive:              true,
	}

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
			errorMessage := ""
			if emailMessage.Error != "" {
				errorMessage = emailMessage.Error
			}
			emailLog := &ydb.EmailLog{
				EmailID:          emailMessage.ID,
				UserID:           user.UserID,
				EmailType:        emailType,
				Recipient:        req.Email,
				Status:           status,
				PostboxMessageID: emailMessage.MessageID,
				SentAt:           emailMessage.SentAt,
				DeliveredAt:      time.Time{}, // Zero value for non-nullable time
				ErrorMessage:     errorMessage,
			}
			s.db.CreateEmailLog(ctx, emailLog)
		}
	}

	// ЛОГИКА ВЕТВЛЕНИЯ: Приглашение ИЛИ Новая организация

	if invitation != nil {
		// СЦЕНАРИЙ 1: Регистрация по приглашению (вступление в существующую организацию)

		// Создание членства в организации на основе приглашения
		membership := &ydb.Membership{
			MembershipID: uuid.New().String(),
			UserID:       user.UserID,
			OrgID:        invitation.OrgID,
			Role:         invitation.Role,
			Status:       "active",
			InvitedBy:    invitation.InvitedBy,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		err = s.db.CreateMembership(ctx, membership)
		if err != nil {
			slog.Error("Failed to create membership from invite", "error", err, "user_id", user.UserID)
			// Не возвращаем ошибку, так как юзер уже создан. Админ может добавить вручную или юзер через accept.
		} else {
			// Обновляем статус приглашения
			_ = s.db.UpdateInvitationStatusWithAcceptTime(ctx, invitation.InvitationID, "accepted", time.Now())
		}

	} else {
		// СЦЕНАРИЙ 2: Создание новой организации (старая логика)

		orgName := req.OrganizationName
		if orgName == "" {
			// Fallback, хотя валидация выше не должна пустить сюда с пустым именем
			orgName = req.FullName
		}
		settings := make(map[string]string)
		settingsJSON, err := json.Marshal(settings)
		if err != nil {
			slog.Error("Failed to marshal settings", "error", err)
			// Не критично, продолжаем
			settingsJSON = []byte("{}")
		}
		settingsStr := string(settingsJSON)
		org := &ydb.Organization{
			OrgID:     uuid.New().String(),
			Name:      orgName,
			OwnerID:   user.UserID,
			Settings:  settingsStr,
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
			Role:         role,
			Status:       status,
			InvitedBy:    user.UserID,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		err = s.db.CreateMembership(ctx, membership)
		if err != nil {
			slog.Error("Failed to create membership", "error", err, "user_id", user.UserID)
		}

		// Создание триальной подписки (ТОЛЬКО ДЛЯ НОВЫХ ОРГАНИЗАЦИЙ)
		planID := "free"
		storageLimitMB := s.config.StorageLimitFree
		videoCountLimit := s.config.VideoCountLimitFree
		// Fallback на случай, если конфиг не загрузился корректно
		if storageLimitMB == 0 {
			storageLimitMB = 1024
		}
		if videoCountLimit == 0 {
			videoCountLimit = 10
		}
		isActive := true
		trialEndsAt := time.Now().Add(7 * 24 * time.Hour)
		subscription := &ydb.Subscription{
			SubscriptionID:  uuid.New().String(),
			UserID:          user.UserID,
			OrgID:           org.OrgID,
			PlanID:          planID,
			StorageLimitMB:  storageLimitMB,
			VideoCountLimit: videoCountLimit,
			IsActive:        isActive,
			TrialEndsAt:     trialEndsAt,
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
	}

	return &models.RegisterResponse{
		UserID:  user.UserID,
		Message: "Registration successful. Please check your email for verification.",
	}, nil
}

// VerifyEmail подтверждает email пользователя
func (s *Service) VerifyEmail(ctx context.Context, req *models.VerifyEmailRequest) (*models.VerifyEmailResponse, error) {

	if err := validation.ValidateEmail(req.Email, "email"); err != nil {
		return nil, err
	}

	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if user.VerificationCode == "" {
		return &models.VerifyEmailResponse{
			Message: "Email already verified",
			Success: true,
		}, nil
	}
	// Проверка кода верификации
	if user.VerificationCode != req.Code {
		return nil, fmt.Errorf("invalid verification code")
	}

	// Проверка срока действия кода
	if time.Now().After(user.VerificationExpiresAt) {
		return nil, fmt.Errorf("verification code expired")
	}

	// Обновление статуса верификации
	user.EmailVerified = true
	user.VerificationCode = "" // Очищаем код
	user.UpdatedAt = time.Now()

	err = s.db.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &models.VerifyEmailResponse{
		Message: "Email verified successfully",
		Success: true,
	}, nil
}

// Login выполняет вход пользователя
func (s *Service) Login(ctx context.Context, req *models.LoginRequest) (*models.LoginResponse, error) {
	// Валидация обязательных полей
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Валидация длины email сначала
	if len(req.Email) > 254 {
		return nil, fmt.Errorf("email must be less than 255 characters long")
	}
	// Затем валидация формата email
	if err := validation.ValidateEmail(req.Email, "email"); err != nil {
		return nil, err
	}

	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Проверка, что пользователь активен
	if !user.IsActive {
		return nil, fmt.Errorf("user account is deactivated")
	}

	// Проверка, что email подтвержден
	if !user.EmailVerified {
		slog.Error("Email not verified", "email", req.Email, "emailVerified", user.EmailVerified)
		return nil, fmt.Errorf("email not verified")
	}

	// Получение всех членств пользователя

	memberships, err := s.db.GetMembershipsByUser(ctx, user.UserID)
	if err != nil {

		return nil, fmt.Errorf("failed to get user membership: %w", err)
	}
	if len(memberships) == 0 {

		return nil, fmt.Errorf("failed to get user membership: membership not found")
	}

	// Выбираем организацию по приоритету:
	// 1. Где пользователь - владелец организации
	// 2. Первая активная организация
	var selectedMembership *ydb.Membership

	for _, m := range memberships {
		if m.Status == "active" {
			// Проверяем, является ли пользователь владельцем
			org, err := s.db.GetOrganizationByID(ctx, m.OrgID)
			if err == nil && org.OwnerID == user.UserID {
				selectedMembership = m
				break
			}
			// Сохраняем первую активную как запасной вариант
			if selectedMembership == nil {
				selectedMembership = m
			}
		}
		log.Println("Debug in loop ", m.OrgID)
	}

	// Если нет активных, берем первое
	if selectedMembership == nil {
		selectedMembership = memberships[0]
	}

	// Собираем информацию об организациях для ответа
	// Собираем информацию об организациях для ответа
	organizations := make([]*models.OrganizationInfo, 0, len(memberships))
	for _, m := range memberships {
		// Получаем информацию об организации для всех членств
		org, err := s.db.GetOrganizationByID(ctx, m.OrgID)
		if err != nil {
			slog.Error("Failed to get organization", "error", err, "org_id", m.OrgID)
			continue
		}

		orgName := org.Name
		role := m.Role
		log.Println("Organization added ", m.OrgID, orgName)
		organizations = append(organizations, &models.OrganizationInfo{
			OrgID: m.OrgID,
			Name:  orgName,
			Role:  role,
		})
	}
	slog.Info("Organizations collected", "count", len(organizations), "user_id", user.UserID)

	// Генерация JWT токенов
	role := selectedMembership.Role
	accessToken, refreshToken, err := s.jwtManager.GenerateTokenPair(
		user.UserID,
		user.Email,
		role,
		selectedMembership.OrgID,
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
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
		IsRevoked: false,
	}

	err = s.db.CreateRefreshToken(ctx, refreshTokenRecord)
	if err != nil {
		slog.Error("Failed to save refresh token", "error", err, "user_id", user.UserID)
	}

	fullName := user.FullName
	role = selectedMembership.Role
	return &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.jwtManager.GetTokenExpiry("access")).Unix(),
		User: &models.UserInfo{
			UserID:        user.UserID,
			Email:         user.Email,
			FullName:      fullName,
			Role:          role,
			OrgID:         selectedMembership.OrgID,
			EmailVerified: user.EmailVerified,
			CreatedAt:     user.CreatedAt.Unix(),
			UpdatedAt:     user.UpdatedAt.Unix(),
		},
		Organizations: organizations,
	}, nil
}

// RefreshToken обновляет access токен
func (s *Service) RefreshToken(ctx context.Context, req *models.RefreshTokenRequest) (*models.RefreshTokenResponse, error) {
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
		TokenHash: newTokenHash,
		ExpiresAt: newExpiresAt,
		CreatedAt: newCreatedAt,
		IsRevoked: false,
	}

	err = s.db.CreateRefreshToken(ctx, newTokenRecord)
	if err != nil {
		slog.Error("Failed to save new refresh token", "error", err, "user_id", claims.UserID)
	}

	return &models.RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.jwtManager.GetTokenExpiry("access")).Unix(),
	}, nil
}

// Logout выполняет выход пользователя
func (s *Service) Logout(ctx context.Context, req *models.LogoutRequest) (*models.LogoutResponse, error) {
	// Отзыв refresh токена
	tokenHash := s.hashToken(req.RefreshToken)
	err := s.db.RevokeRefreshToken(ctx, tokenHash)
	if err != nil {
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "refresh token not found") {
			return nil, fmt.Errorf("failed to revoke refresh token: refresh token not found")
		} else if strings.Contains(errorMsg, "refresh token expired") {
			return nil, fmt.Errorf("failed to revoke refresh token: refresh token expired")
		}
		return nil, fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return &models.LogoutResponse{
		Message: "Logout successful",
	}, nil
}

// GetProfile получает профиль пользователя
func (s *Service) GetProfile(ctx context.Context, userID string) (*models.GetProfileResponse, error) {
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Получение всех членств пользователя
	memberships, err := s.db.GetMembershipsByUser(ctx, user.UserID)
	if err != nil || len(memberships) == 0 {
		return nil, fmt.Errorf("failed to get user membership: membership not found")
	}

	// Выбираем активное членство (приоритет - где пользователь владелец)
	var selectedMembership *ydb.Membership
	for _, m := range memberships {
		if m.Status == "active" {
			// Проверяем, является ли пользователь владельцем
			org, err := s.db.GetOrganizationByID(ctx, m.OrgID)
			if err == nil && org.OwnerID == user.UserID {
				selectedMembership = m
				break
			}
			// Сохраняем первую активную как запасной вариант
			if selectedMembership == nil {
				selectedMembership = m
			}
		}
	}

	// Если нет активных, берем первое
	if selectedMembership == nil {
		selectedMembership = memberships[0]
	}

	fullName := user.FullName
	role := selectedMembership.Role
	return &models.GetProfileResponse{
		User: &models.UserInfo{
			UserID:        user.UserID,
			Email:         user.Email,
			FullName:      fullName,
			Role:          role,
			OrgID:         selectedMembership.OrgID,
			EmailVerified: user.EmailVerified,
			CreatedAt:     user.CreatedAt.Unix(),
			UpdatedAt:     user.UpdatedAt.Unix(),
		},
	}, nil
}

// UpdateProfile обновляет профиль пользователя
func (s *Service) UpdateProfile(ctx context.Context, userID string, req *models.UpdateProfileRequest) (*models.GetProfileResponse, error) {
	// Валидация обязательных полей
	if req.FullName == "" {
		return nil, fmt.Errorf("full_name is required")
	}

	// Валидация длины имени
	if len(req.FullName) < 2 {
		return nil, fmt.Errorf("full_name must be at least 2 characters long")
	}
	if len(req.FullName) > 100 {
		return nil, fmt.Errorf("full_name must be less than 101 characters long")
	}

	// Валидация безопасности используя validation package
	// Для имени отключаем Unicode проверку, чтобы разрешить кириллицу
	nameOptions := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)

	// Проверка имени на инъекции (без Unicode проверки)
	if err := validation.ValidateInputWithError(req.FullName, "full_name", nameOptions); err != nil {
		return nil, err
	}

	// Получаем текущего пользователя
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Обновляем только поле full_name
	user.FullName = req.FullName
	user.UpdatedAt = time.Now()

	// Сохраняем изменения в базе
	err = s.db.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Получаем обновленный профиль пользователя
	return s.GetProfile(ctx, userID)
}

// SwitchOrganization переключает организацию пользователя
func (s *Service) SwitchOrganization(ctx context.Context, userID string, req *models.SwitchOrganizationRequest) (*models.SwitchOrganizationResponse, error) {
	// Проверяем, что пользователь состоит в этой организации
	membership, err := s.db.GetMembership(ctx, userID, req.OrgID)
	if err != nil {
		return nil, fmt.Errorf("user is not a member of this organization")
	}

	if membership.Status != "active" {
		return nil, fmt.Errorf("membership is not active")
	}

	// Получаем информацию о пользователе
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Генерируем новый токен с новой организацией
	role := membership.Role

	accessToken, _, err := s.jwtManager.GenerateTokenPair(
		user.UserID,
		user.Email,
		role,
		req.OrgID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &models.SwitchOrganizationResponse{
		AccessToken: accessToken,
		ExpiresAt:   time.Now().Add(s.jwtManager.GetTokenExpiry("access")).Unix(),
		OrgID:       req.OrgID,
	}, nil
}

// hashToken хеширует токен для хранения в базе
func (s *Service) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash)
}

// InviteUser приглашает пользователя в организацию
func (s *Service) InviteUser(ctx context.Context, inviterID, orgID string, req *models.InviteUserRequest) (*models.InviteUserResponse, error) {
	// Валидация входных данных
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if req.Role == "" {
		return nil, fmt.Errorf("role is required")
	}

	// Валидация email
	if err := validation.ValidateEmail(req.Email, "email"); err != nil {
		return nil, err
	}

	// Валидация роли
	validRoles := []rbac.Role{rbac.RoleUser, rbac.RoleManager, rbac.RoleAdmin}
	roleFound := false
	for _, validRole := range validRoles {
		if req.Role == string(validRole) {
			roleFound = true
			break
		}
	}
	if !roleFound {
		return nil, fmt.Errorf("invalid role: %s", req.Role)
	}

	// Проверяем, что приглашающий является admin или manager в организации
	inviterMembership, err := s.db.GetMembership(ctx, inviterID, orgID)
	if err != nil {
		return nil, fmt.Errorf("inviter is not a member of this organization")
	}

	if inviterMembership.Role != string(rbac.RoleAdmin) && inviterMembership.Role != string(rbac.RoleManager) {
		return nil, fmt.Errorf("only admins and managers can invite users")
	}

	// Проверяем, что приглашающий не пытается создать более высокую роль
	if inviterMembership.Role == string(rbac.RoleManager) && req.Role == string(rbac.RoleAdmin) {
		return nil, fmt.Errorf("managers cannot invite admins")
	}

	// Проверяем, что пользователь еще не приглашен в эту организацию
	existingInvitation, _ := s.db.GetInvitationByEmail(ctx, orgID, req.Email)
	if existingInvitation != nil {
		return nil, fmt.Errorf("user already invited to this organization")
	}

	// Проверяем, что пользователь не состоит уже в организации
	membership, _ := s.db.GetMembership(ctx, "", orgID)
	if membership != nil {
		return nil, fmt.Errorf("user is already a member of this organization")
	}

	// Генерируем уникальный код приглашения
	inviteCode := uuid.New().String()

	// Создаем приглашение
	invitation := &ydb.Invitation{
		InvitationID: uuid.New().String(),
		OrgID:        orgID,
		Email:        req.Email,
		Role:         req.Role,
		InviteCode:   inviteCode,
		InvitedBy:    inviterID,
		Status:       "pending",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour), // 7 дней
		CreatedAt:    time.Now(),
	}

	err = s.db.CreateInvitation(ctx, invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}

	// Отправляем email с приглашением
	// if s.email.IsConfigured() {
	// 	org, err := s.db.GetOrganizationByID(ctx, orgID)
	// 	if err != nil {
	// 		slog.Error("Failed to get organization", "error", err, "org_id", orgID)
	// 	} else {
	// 		_, err := s.email.SendInvitationEmail(ctx, req.Email, inviteCode, org.Name)
	// 		if err != nil {
	// 			slog.Error("Failed to send invitation email", "error", err, "email", req.Email)
	// 		}
	// 	}
	// }

	return &models.InviteUserResponse{
		InvitationID: invitation.InvitationID,
		InviteCode:   inviteCode,
		ExpiresAt:    invitation.ExpiresAt.Unix(),
		Email:        req.Email,
		Role:         req.Role,
	}, nil
}

// AcceptInvitation принимает приглашение в организацию
func (s *Service) AcceptInvitation(ctx context.Context, userID string, req *models.AcceptInvitationRequest) (*models.AcceptInvitationResponse, error) {
	if req.InviteCode == "" {
		return nil, fmt.Errorf("invite_code is required")
	}

	// Получаем приглашение по коду
	invitation, err := s.db.GetInvitationByCode(ctx, req.InviteCode)
	if err != nil {
		return nil, fmt.Errorf("invalid invite code")
	}

	// Проверяем статус приглашения
	if invitation.Status != "pending" {
		return nil, fmt.Errorf("invitation is not pending")
	}

	// Проверяем срок действия приглашения
	if time.Now().After(invitation.ExpiresAt) {
		s.db.UpdateInvitationStatus(ctx, invitation.InvitationID, "expired")
		return nil, fmt.Errorf("invitation has expired")
	}

	// Получаем пользователя
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Проверяем, что email пользователя совпадает с email приглашения
	if user.Email != invitation.Email {
		return nil, fmt.Errorf("invitation email does not match user email")
	}

	// Проверяем, что пользователь еще не состоит в организации
	membership, _ := s.db.GetMembership(ctx, userID, invitation.OrgID)
	if membership != nil {
		return nil, fmt.Errorf("user is already a member of this organization")
	}

	// Создаем членство в организации
	newMembership := &ydb.Membership{
		MembershipID: uuid.New().String(),
		UserID:       userID,
		OrgID:        invitation.OrgID,
		Role:         invitation.Role,
		Status:       "active",
		InvitedBy:    invitation.InvitedBy,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	err = s.db.CreateMembership(ctx, newMembership)
	if err != nil {
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}

	// Обновляем статус приглашения
	err = s.db.UpdateInvitationStatusWithAcceptTime(ctx, invitation.InvitationID, "accepted", time.Now())
	if err != nil {
		slog.Error("Failed to update invitation status", "error", err)
	}

	return &models.AcceptInvitationResponse{
		MembershipID: newMembership.MembershipID,
		OrgID:        invitation.OrgID,
		Role:         invitation.Role,
		Message:      "Invitation accepted successfully",
	}, nil
}

// ListInvitations возвращает список приглашений организации
func (s *Service) ListInvitations(ctx context.Context, orgID string) ([]*models.InvitationInfo, error) {
	invitations, err := s.db.GetInvitationsByOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get invitations: %w", err)
	}

	result := make([]*models.InvitationInfo, 0, len(invitations))
	for _, inv := range invitations {
		invInfo := &models.InvitationInfo{
			InvitationID: inv.InvitationID,
			Email:        inv.Email,
			Role:         inv.Role,
			Status:       inv.Status,
			InvitedBy:    inv.InvitedBy,
			CreatedAt:    inv.CreatedAt.Unix(),
			ExpiresAt:    inv.ExpiresAt.Unix(),
		}
		if inv.AcceptedAt != nil {
			acceptedAt := inv.AcceptedAt.Unix()
			invInfo.AcceptedAt = &acceptedAt
		}
		result = append(result, invInfo)
	}

	return result, nil
}

// CancelInvitation отменяет приглашение
func (s *Service) CancelInvitation(ctx context.Context, invitationID string) error {
	invitation, err := s.db.GetInvitationByCode(ctx, "") // Получить по ID
	if err != nil {
		// Нам нужен другой метод для получения приглашения по ID
		// На время используем эту логику
		return fmt.Errorf("invitation not found")
	}

	if invitation.Status != "pending" {
		return fmt.Errorf("only pending invitations can be cancelled")
	}

	err = s.db.UpdateInvitationStatus(ctx, invitationID, "cancelled")
	if err != nil {
		return fmt.Errorf("failed to cancel invitation: %w", err)
	}

	return nil
}

// UpdateMemberRole обновляет роль члена организации
func (s *Service) UpdateMemberRole(ctx context.Context, adminID, orgID, targetUserID, newRole string) error {
	// Проверяем, что админ является admin в организации
	adminMembership, err := s.db.GetMembership(ctx, adminID, orgID)
	if err != nil {
		return fmt.Errorf("admin is not a member of this organization")
	}

	if adminMembership.Role != string(rbac.RoleAdmin) {
		return fmt.Errorf("only admins can change roles")
	}

	// Проверяем валидность новой роли
	validRoles := []rbac.Role{rbac.RoleUser, rbac.RoleManager, rbac.RoleAdmin}
	roleFound := false
	for _, validRole := range validRoles {
		if newRole == string(validRole) {
			roleFound = true
			break
		}
	}
	if !roleFound {
		return fmt.Errorf("invalid role: %s", newRole)
	}

	// Получаем текущее членство
	targetMembership, err := s.db.GetMembership(ctx, targetUserID, orgID)
	if err != nil {
		return fmt.Errorf("target user is not a member of this organization")
	}

	// Обновляем роль
	targetMembership.Role = newRole
	targetMembership.UpdatedAt = time.Now()

	err = s.db.UpdateMembership(ctx, targetMembership)
	if err != nil {
		return fmt.Errorf("failed to update member role: %w", err)
	}

	return nil
}

// RemoveMember удаляет члена из организации
func (s *Service) RemoveMember(ctx context.Context, adminID, orgID, targetUserID string) error {
	// Проверяем, что админ является admin в организации
	adminMembership, err := s.db.GetMembership(ctx, adminID, orgID)
	if err != nil {
		return fmt.Errorf("admin is not a member of this organization")
	}

	if adminMembership.Role != string(rbac.RoleAdmin) {
		return fmt.Errorf("only admins can remove members")
	}

	// Проверяем, что целевой пользователь состоит в организации
	targetMembership, err := s.db.GetMembership(ctx, targetUserID, orgID)
	if err != nil {
		return fmt.Errorf("target user is not a member of this organization")
	}

	// Нельзя удалить владельца организации
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	if err == nil && org.OwnerID == targetUserID {
		return fmt.Errorf("cannot remove organization owner")
	}

	// Удаляем членство
	err = s.db.DeleteMembership(ctx, targetMembership.MembershipID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	return nil
}

// ListOrgMembers возвращает список членов организации
func (s *Service) ListOrgMembers(ctx context.Context, orgID string) ([]*models.MemberInfo, error) {
	memberships, err := s.db.GetMembershipsByOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get members: %w", err)
	}

	result := make([]*models.MemberInfo, 0, len(memberships))
	for _, m := range memberships {
		// Получаем информацию о пользователе
		user, err := s.db.GetUserByID(ctx, m.UserID)
		if err != nil {
			slog.Error("Failed to get user", "error", err, "user_id", m.UserID)
			continue
		}

		memberInfo := &models.MemberInfo{
			UserID:    m.UserID,
			Email:     user.Email,
			FullName:  user.FullName,
			Role:      m.Role,
			Status:    m.Status,
			JoinedAt:  m.CreatedAt.Unix(),
			InvitedBy: m.InvitedBy,
		}
		result = append(result, memberInfo)
	}

	return result, nil
}

// ValidateToken валидирует JWT токен и возвращает claims
func (s *Service) ValidateToken(tokenString string) (*jwtmanager.Claims, error) {
	return s.jwtManager.ValidateToken(tokenString)
}

// CheckPermission проверяет разрешение пользователя
func (s *Service) CheckPermission(ctx context.Context, userID, orgID string, permission rbac.Permission) (bool, error) {
	// Получение роли пользователя
	membership, err := s.db.GetMembership(ctx, userID, orgID)
	if err != nil {
		return false, fmt.Errorf("failed to get user membership: %w", err)
	}

	roleStr := membership.Role
	role := rbac.Role(roleStr)
	return s.rbac.CheckPermissionWithRole(role, permission), nil
}

// CreateOrganization создает новую организацию для администратора
func (s *Service) CreateOrganization(ctx context.Context, userID string, req *models.CreateOrganizationRequest) (*models.CreateOrganizationResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}

	orgName, err := validation.SanitizeOrganizationName(req.Name)
	if err != nil {
		return nil, err
	}

	description, err := validation.SanitizeOrganizationDescription(req.Description)
	if err != nil {
		return nil, err
	}

	memberships, err := s.db.GetMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}

	isAdmin := false
	for _, membership := range memberships {
		if membership.Status == "active" && membership.Role == string(rbac.RoleAdmin) {
			isAdmin = true
			break
		}
	}

	if !isAdmin {
		return nil, fmt.Errorf("only admins can create organizations")
	}

	// Проверка уникальности названия организации для данного пользователя
	orgs, err := s.db.GetOrganizationsByOwner(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}
	for _, org := range orgs {
		if strings.EqualFold(org.Name, orgName) {
			return nil, validation.ValidationError{Field: "name", Message: "organization name already exists"}
		}
	}

	orgID := uuid.New().String()
	now := time.Now()
	settings := map[string]string{}
	if description != "" {
		settings["description"] = description
	}

	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal organization settings: %w", err)
	}

	org := &ydb.Organization{
		OrgID:     orgID,
		Name:      orgName,
		OwnerID:   userID,
		Settings:  string(settingsJSON),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.db.CreateOrganization(ctx, org); err != nil {
		slog.Error("Failed to create organization", "error", err, "user_id", userID, "org_name", orgName)
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	membershipRecord := &ydb.Membership{
		MembershipID: uuid.New().String(),
		UserID:       userID,
		OrgID:        orgID,
		Role:         string(rbac.RoleAdmin),
		Status:       "active",
		InvitedBy:    userID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.db.CreateMembership(ctx, membershipRecord); err != nil {
		slog.Error("Failed to create membership for new organization", "error", err, "user_id", userID, "org_id", orgID)
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}

	slog.Info("Organization created", "user_id", userID, "org_id", orgID, "name", orgName)

	return &models.CreateOrganizationResponse{
		OrgID:       orgID,
		Name:        orgName,
		Description: description,
		CreatedAt:   now.Unix(),
		Message:     "Organization created successfully",
	}, nil
}
