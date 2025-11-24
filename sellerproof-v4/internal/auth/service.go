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

	"github.com/lumiforge/sellerproof-backend/internal/email"
	jwtmanager "github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/models"
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

	// Валидация длины email сначала
	if len(req.Email) > 254 {
		return nil, fmt.Errorf("email must be less than 255 characters long")
	}
	// Затем валидация формата email
	if !email.ValidateEmail(req.Email) {
		return nil, fmt.Errorf("invalid email format")
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
	if len(req.OrganizationName) > 200 {
		return nil, fmt.Errorf("organization_name must be less than 201 characters long")
	}

	// Проверка на потенциальные XSS/инъекции в имени
	if strings.Contains(req.FullName, "<script") ||
		strings.Contains(req.FullName, "</script>") ||
		strings.Contains(req.FullName, "javascript:") ||
		strings.Contains(req.FullName, "onerror=") ||
		strings.Contains(req.FullName, "onload=") ||
		strings.Contains(req.FullName, "<") ||
		strings.Contains(req.FullName, ">") {
		return nil, fmt.Errorf("full_name contains invalid characters")
	}

	// Проверка на потенциальные XSS/инъекции в организации
	if strings.Contains(req.OrganizationName, "<script") ||
		strings.Contains(req.OrganizationName, "</script>") ||
		strings.Contains(req.OrganizationName, "javascript:") ||
		strings.Contains(req.OrganizationName, "onerror=") ||
		strings.Contains(req.OrganizationName, "onload=") ||
		strings.Contains(req.OrganizationName, "<") ||
		strings.Contains(req.OrganizationName, ">") {
		return nil, fmt.Errorf("organization_name contains invalid characters")
	}

	// Улучшенная проверка на SQL инъекции во всех полях
	sqlInjectionPatterns := []string{
		"'", ";", "--", "/*", "*/", "xp_", "sp_",
		"drop ", "delete ", "insert ", "update ", "select ",
		"union ", "exec ", "execute ", "truncate ", "alter ",
		"create ", "table ", "from ", "where ", "or 1=1",
		"and 1=1", "sleep(", "benchmark(", "waitfor delay",
		"convert(", "cast(", "char(", "ascii(", "substring(",
		"concat(", "load_file(", "into outfile", "into dumpfile",
	}

	// Проверка email на SQL инъекции
	emailLower := strings.ToLower(req.Email)
	for _, pattern := range sqlInjectionPatterns {
		if strings.Contains(req.Email, pattern) || strings.Contains(emailLower, pattern) {
			return nil, fmt.Errorf("email contains invalid characters")
		}
	}

	// Проверка пароля на SQL инъекции
	passwordLower := strings.ToLower(req.Password)
	for _, pattern := range sqlInjectionPatterns {
		if strings.Contains(req.Password, pattern) || strings.Contains(passwordLower, pattern) {
			return nil, fmt.Errorf("password contains invalid characters")
		}
	}

	// Проверка имени на SQL инъекции
	nameLower := strings.ToLower(req.FullName)
	for _, pattern := range sqlInjectionPatterns {
		if strings.Contains(req.FullName, pattern) || strings.Contains(nameLower, pattern) {
			return nil, fmt.Errorf("full_name contains invalid characters")
		}
	}

	// Проверка организации на SQL инъекции
	orgLower := strings.ToLower(req.OrganizationName)
	for _, pattern := range sqlInjectionPatterns {
		if strings.Contains(req.OrganizationName, pattern) || strings.Contains(orgLower, pattern) {
			return nil, fmt.Errorf("organization_name contains invalid characters")
		}
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

	// Создание персональной организации для пользователя
	orgName := req.OrganizationName
	if orgName == "" {
		// Если имя организации не указано, используем значение по умолчанию
		orgName = req.FullName
	}
	settings := make(map[string]string)
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		slog.Error("Failed to marshal settings", "error", err)
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
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

	// Создание триальной подписки
	planID := "free"
	storageLimitMB := int64(1024) // 1GB = 1024MB
	videoCountLimit := int64(10)
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

	return &models.RegisterResponse{
		UserID:  user.UserID,
		Message: "Registration successful. Please check your email for verification.",
	}, nil
}

// VerifyEmail подтверждает email пользователя
func (s *Service) VerifyEmail(ctx context.Context, req *models.VerifyEmailRequest) (*models.VerifyEmailResponse, error) {

	if !email.ValidateEmail(req.Email) {
		return nil, fmt.Errorf("invalid email format")
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
	if !email.ValidateEmail(req.Email) {
		return nil, fmt.Errorf("invalid email format")
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

	// Проверка на потенциальные XSS/инъекции в имени
	if strings.Contains(req.FullName, "<script") ||
		strings.Contains(req.FullName, "</script>") ||
		strings.Contains(req.FullName, "javascript:") ||
		strings.Contains(req.FullName, "onerror=") ||
		strings.Contains(req.FullName, "onload=") ||
		strings.Contains(req.FullName, "<") ||
		strings.Contains(req.FullName, ">") {
		return nil, fmt.Errorf("full_name contains invalid characters")
	}

	// Улучшенная проверка на SQL инъекции в имени
	sqlInjectionPatterns := []string{
		"'", ";", "--", "/*", "*/", "xp_", "sp_",
		"drop ", "delete ", "insert ", "update ", "select ",
		"union ", "exec ", "execute ", "truncate ", "alter ",
		"create ", "table ", "from ", "where ", "or 1=1",
		"and 1=1", "sleep(", "benchmark(", "waitfor delay",
		"convert(", "cast(", "char(", "ascii(", "substring(",
		"concat(", "load_file(", "into outfile", "into dumpfile",
	}

	// Проверка имени на SQL инъекции
	nameLower := strings.ToLower(req.FullName)
	for _, pattern := range sqlInjectionPatterns {
		if strings.Contains(req.FullName, pattern) || strings.Contains(nameLower, pattern) {
			return nil, fmt.Errorf("full_name contains invalid characters")
		}
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
