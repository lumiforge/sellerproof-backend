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

	// Нормализация email (Fix: Case Sensitivity)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

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

	// Для имени и организации отключаем Unicode проверку, чтобы разрешить кириллицу
	nameOptions := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)

	// Проверка email на инъекции
	if err := validation.ValidateInputWithError(req.Email, "email", emailOptions); err != nil {
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
		// Allow unverified users to re-register to resend verification code
		if !existingUser.EmailVerified {

			// Generate new verification code
			newVerificationCode, err := email.GenerateVerificationCode()
			if err != nil {
				return nil, fmt.Errorf("failed to generate verification code: %w", err)
			}

			// Update user record

			existingUser.VerificationCode = newVerificationCode
			existingUser.VerificationExpiresAt = time.Now().Add(24 * time.Hour)
			existingUser.VerificationAttempts = 0
			existingUser.FullName = req.FullName
			existingUser.UpdatedAt = time.Now()

			if err := s.db.UpdateUser(ctx, existingUser); err != nil {
				return nil, fmt.Errorf("failed to update user: %w", err)
			}

			// Resend email
			if s.email.IsConfigured() {
				emailMessage, err := s.email.SendVerificationEmail(ctx, req.Email, newVerificationCode)
				if err != nil {
					slog.Error("Failed to resend verification email", "error", err, "email", req.Email)
				} else {
					emailLog := &ydb.EmailLog{
						EmailID:          emailMessage.ID,
						UserID:           existingUser.UserID,
						EmailType:        string(email.EmailTypeVerification),
						Recipient:        req.Email,
						Status:           string(emailMessage.Status),
						PostboxMessageID: emailMessage.MessageID,
						SentAt:           emailMessage.SentAt,
					}
					_ = s.db.CreateEmailLog(ctx, emailLog)
				}
			}

			return &models.RegisterResponse{
				UserID:  existingUser.UserID,
				Message: "Registration successful. Please check your email for verification.",
			}, nil
		}
		return nil, fmt.Errorf("email already exists")
	}

	if err := validation.ValidateInputWithError(req.Password, "password", nameOptions); err != nil {
		return nil, err
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

	// Подготовка структуры User
	passwordHashStr := string(passwordHash)
	now := time.Now()
	user := &ydb.User{
		UserID:                uuid.New().String(),
		Email:                 req.Email,
		PasswordHash:          passwordHashStr,
		FullName:              req.FullName,
		EmailVerified:         false,
		VerificationCode:      verificationCode,
		VerificationExpiresAt: now.Add(24 * time.Hour),
		VerificationAttempts:  0,
		CreatedAt:             now,
		UpdatedAt:             now,
		IsActive:              true,
	}

	// Переменные для транзакции
	var org *ydb.Organization
	var membership *ydb.Membership
	var subscription *ydb.Subscription
	var invitationID string

	if invitation != nil {
		// СЦЕНАРИЙ 1: Регистрация по приглашению
		invitationID = invitation.InvitationID
		membership = &ydb.Membership{
			MembershipID: uuid.New().String(),
			UserID:       user.UserID,
			OrgID:        invitation.OrgID,
			Role:         invitation.Role,
			Status:       "active",
			InvitedBy:    invitation.InvitedBy,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
	} else {
		// СЦЕНАРИЙ 2: Создание новой организации
		orgName := req.OrganizationName
		if orgName == "" {
			orgName = req.FullName
		}
		settings := make(map[string]string)
		settingsJSON, _ := json.Marshal(settings)
		org = &ydb.Organization{
			OrgID:     uuid.New().String(),
			Name:      orgName,
			OwnerID:   user.UserID,
			Settings:  string(settingsJSON),
			CreatedAt: now,
			UpdatedAt: now,
		}

		// Membership (Admin)
		membership = &ydb.Membership{
			MembershipID: uuid.New().String(),
			UserID:       user.UserID,
			OrgID:        org.OrgID,
			Role:         string(rbac.RoleAdmin),
			Status:       "active",
			InvitedBy:    user.UserID,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		// Subscription (trial)
		freePlan, err := s.db.GetPlanByID(ctx, "free")
		if err != nil {
			return nil, fmt.Errorf("failed to fetch free plan details: %w", err)
		}

		subscription = &ydb.Subscription{
			SubscriptionID:  uuid.New().String(),
			UserID:          user.UserID,
			OrgID:           org.OrgID,
			PlanID:          freePlan.PlanID,
			StorageLimitMB:  freePlan.StorageLimitMB,
			VideoCountLimit: freePlan.VideoCountLimit,
			IsActive:        true,
			TrialEndsAt:     now.Add(7 * 24 * time.Hour),
			StartedAt:       now,
			ExpiresAt:       now.Add(30 * 24 * time.Hour),
			BillingCycle:    "monthly",
			CreatedAt:       now,
			UpdatedAt:       now,
		}
	}

	// ВЫПОЛНЕНИЕ ТРАНЗАКЦИИ
	err = s.db.RegisterUserTx(ctx, user, org, membership, subscription, invitationID)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "duplicate") {
			return nil, fmt.Errorf("email already exists")
		}
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// ПОСТ-ТРАНЗАКЦИОННЫЕ ДЕЙСТВИЯ (Side Effects)
	if s.email.IsConfigured() {
		emailMessage, err := s.email.SendVerificationEmail(ctx, req.Email, verificationCode)
		if err != nil {
			slog.Error("Failed to send verification email", "error", err, "email", req.Email)
		} else {
			emailLog := &ydb.EmailLog{
				EmailID:          emailMessage.ID,
				UserID:           user.UserID,
				EmailType:        string(email.EmailTypeVerification),
				Recipient:        req.Email,
				Status:           string(emailMessage.Status),
				PostboxMessageID: emailMessage.MessageID,
				SentAt:           emailMessage.SentAt,
			}
			if err := s.db.CreateEmailLog(ctx, emailLog); err != nil {
				slog.Error("Failed to create email log", "error", err)
			}
		}
	}

	return &models.RegisterResponse{
		UserID:  user.UserID,
		Message: "Registration successful. Please check your email for verification.",
	}, nil
}

// VerifyEmail подтверждает email пользователя
func (s *Service) VerifyEmail(ctx context.Context, req *models.VerifyEmailRequest) (*models.VerifyEmailResponse, error) {
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if err := validation.ValidateEmail(req.Email, "email"); err != nil {
		return nil, err
	}

	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if email is already verified
	if user.EmailVerified {
		return &models.VerifyEmailResponse{
			Message: "Email already verified",
			Success: true,
		}, nil
	}

	if user.VerificationCode == "" {
		return &models.VerifyEmailResponse{
			Message: "Email already verified",
			Success: true,
		}, nil
	}

	// 1. Проверка на превышение лимита попыток
	const MaxVerificationAttempts = 5
	if user.VerificationAttempts >= MaxVerificationAttempts {
		return nil, fmt.Errorf("too many failed attempts. please request a new verification code")
	}

	// Проверка срока действия кода
	if time.Now().After(user.VerificationExpiresAt) {
		return nil, fmt.Errorf("verification code expired")
	}

	// 2. Проверка кода верификации
	if user.VerificationCode != req.Code {
		// Инкремент счетчика неудачных попыток
		user.VerificationAttempts++
		user.UpdatedAt = time.Now()

		// Сохраняем обновленный счетчик в БД
		if updateErr := s.db.UpdateUser(ctx, user); updateErr != nil {
			slog.Error("Failed to update user verification attempts", "error", updateErr)
		}

		// Если это была последняя попытка
		if user.VerificationAttempts >= MaxVerificationAttempts {
			return nil, fmt.Errorf("too many failed attempts. please request a new verification code")
		}

		return nil, fmt.Errorf("invalid verification code. attempts remaining: %d", MaxVerificationAttempts-user.VerificationAttempts)
	}

	// Обновление статуса верификации (Успех)
	user.EmailVerified = true
	user.VerificationCode = ""    // Очищаем код
	user.VerificationAttempts = 0 // Сбрасываем счетчик
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
	// Нормализация email (Fix: Case Sensitivity)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Затем валидация формата email
	if err := validation.ValidateEmail(req.Email, "email"); err != nil {
		return nil, err
	}

	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// TODO delete me
		log.Println("Error in login 1", err)

		return nil, fmt.Errorf("invalid credentials")
	}
	if len(req.Password) > 72 {
		return nil, fmt.Errorf("password must be less than 73 characters long")
	}

	// Проверка, что email подтвержден (ДО проверки пароля для правильной семантики)
	if !user.EmailVerified {
		slog.Error("Email not verified", "email", req.Email, "emailVerified", user.EmailVerified)
		return nil, fmt.Errorf("email not verified")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		// TODO delete me
		log.Println("Error in login 2", err)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Проверка, что пользователь активен
	if !user.IsActive {
		return nil, fmt.Errorf("user account is deactivated")
	}

	// Получение всех членств пользователя

	memberships, err := s.db.GetMembershipsByUser(ctx, user.UserID)
	if err != nil {

		return nil, fmt.Errorf("failed to get user membership: %w", err)
	}
	if len(memberships) == 0 {

		return nil, fmt.Errorf("failed to get user membership: membership not found")
	}
	// Оптимизация: Получаем все организации одним запросом (Batch Fetch)
	orgIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		orgIDs = append(orgIDs, m.OrgID)
	}

	orgs, err := s.db.GetOrganizationsByIDs(ctx, orgIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get organizations: %w", err)
	}

	// Создаем карту для быстрого поиска организации по ID
	orgMap := make(map[string]*ydb.Organization)
	for _, o := range orgs {
		orgMap[o.OrgID] = o
	}

	// Выбираем организацию по приоритету:
	// 1. Где пользователь - владелец организации
	// 2. Первая активная организация
	// 3. Любая существующая организация (если нет активных)
	var selectedMembership *ydb.Membership

	for _, m := range memberships {
		// Проверяем, существует ли организация физически
		org, exists := orgMap[m.OrgID]
		if !exists {
			continue
		}

		if m.Status == "active" {
			// Приоритет 1: Активный владелец
			if org.OwnerID == user.UserID {
				selectedMembership = m
				break
			}
			// Приоритет 2: Первая активная
			if selectedMembership == nil {
				selectedMembership = m
			}
		}

	}

	// // Приоритет 3: Если активных не найдено, берем первую валидную
	// if selectedMembership == nil {
	// 	for _, m := range memberships {
	// 		if _, exists := orgMap[m.OrgID]; exists {
	// 			selectedMembership = m
	// 			break
	// 		}
	// 	}
	// }

	// Если после всех проверок организация не выбрана (все удалены или рассинхрон), возвращаем ошибку
	if selectedMembership == nil {
		return nil, fmt.Errorf("no valid organizations found for user")
	}

	// Собираем информацию об организациях для ответа
	organizations := make([]*models.OrganizationInfo, 0, len(memberships))
	for _, m := range memberships {
		// Получаем информацию об организации из карты
		org, exists := orgMap[m.OrgID]
		if !exists {
			slog.Warn("Organization not found for membership", "org_id", m.OrgID)
			continue
		}

		orgName := org.Name
		role := m.Role
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

		return nil, fmt.Errorf("failed to create session: %w", err)
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
	// FIX: Проверяем актуальный статус пользователя и его права перед обновлением
	user, err := s.db.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.IsActive {
		return nil, fmt.Errorf("user account is deactivated")
	}
	// Проверяем, что пользователь всё ещё состоит в этой организации и получаем актуальную роль
	membership, err := s.db.GetMembership(ctx, claims.UserID, claims.OrgID)
	if err != nil {
		return nil, fmt.Errorf("membership not found or revoked: %w", err)
	}
	if membership.Status != "active" {
		return nil, fmt.Errorf("membership is not active")
	}
	// Генерация новой пары токенов
	accessToken, refreshToken, err := s.jwtManager.GenerateTokenPair(
		user.UserID,
		user.Email,
		membership.Role,
		membership.OrgID,
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

	// Оптимизация: Получаем все организации одним запросом (Batch Fetch)
	orgIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		orgIDs = append(orgIDs, m.OrgID)
	}

	orgs, err := s.db.GetOrganizationsByIDs(ctx, orgIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get organizations: %w", err)
	}

	// Создаем карту для быстрого поиска организации по ID
	orgMap := make(map[string]*ydb.Organization)
	for _, o := range orgs {
		orgMap[o.OrgID] = o
	}

	// Выбираем организацию по приоритету:
	// 1. Где пользователь - владелец организации
	// 2. Первая активная организация
	// 3. Любая существующая организация (если нет активных)
	var selectedMembership *ydb.Membership

	for _, m := range memberships {
		// Проверяем, существует ли организация физически
		org, exists := orgMap[m.OrgID]
		if !exists {
			continue
		}

		if m.Status == "active" {
			// Приоритет 1: Активный владелец
			if org.OwnerID == user.UserID {
				selectedMembership = m
				break
			}
			// Приоритет 2: Первая активная
			if selectedMembership == nil {
				selectedMembership = m
			}
		}

	}

	// Приоритет 3: Если активных не найдено, берем первую валидную
	if selectedMembership == nil {
		for _, m := range memberships {
			if _, exists := orgMap[m.OrgID]; exists {
				selectedMembership = m
				break
			}
		}
	}

	// Если после всех проверок организация не выбрана (все удалены или рассинхрон), возвращаем ошибку
	if selectedMembership == nil {
		return nil, fmt.Errorf("no valid organizations found for user")
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
// SwitchOrganization переключает организацию пользователя
func (s *Service) SwitchOrganization(ctx context.Context, userID string, req *models.SwitchOrganizationRequest) (*models.SwitchOrganizationResponse, error) {
	// 1. Валидация и отзыв старого Refresh токена (Ротация)
	// Валидация формата токена
	claims, err := s.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Проверка принадлежности токена пользователю
	if claims.UserID != userID {
		return nil, fmt.Errorf("refresh token does not belong to user")
	}

	// Проверка существования и статуса токена в БД
	oldTokenHash := s.hashToken(req.RefreshToken)
	tokenRecord, err := s.db.GetRefreshToken(ctx, oldTokenHash)
	if err != nil || tokenRecord == nil || tokenRecord.IsRevoked {
		return nil, fmt.Errorf("refresh token not found or revoked")
	}

	// Отзыв старого токена
	if err := s.db.RevokeRefreshToken(ctx, oldTokenHash); err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	// 2. Проверка прав доступа к новой организации
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

	// 3. Генерация новой сессии
	// Генерируем новый токен с новой организацией
	role := membership.Role

	accessToken, refreshToken, err := s.jwtManager.GenerateTokenPair(
		user.UserID,
		user.Email,
		role,
		req.OrgID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Сохранение нового refresh токена в базу
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
	if err := s.db.CreateRefreshToken(ctx, refreshTokenRecord); err != nil {
		slog.Error("Failed to save refresh token during org switch", "error", err, "user_id", user.UserID)
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &models.SwitchOrganizationResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.jwtManager.GetTokenExpiry("access")).Unix(),
		OrgID:        req.OrgID,
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
	if req.Role == string(rbac.RoleAdmin) {
		return nil, fmt.Errorf("organization can have only one admin")
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
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
	existingInvitation, err := s.db.GetInvitationByEmail(ctx, orgID, req.Email)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		slog.Error("Failed to check existing invitations", "error", err)
		return nil, fmt.Errorf("failed to check existing invitations: %w", err)
	}

	if existingInvitation != nil {
		return nil, fmt.Errorf("user already invited to this organization")
	}

	existingUser, err := s.db.GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		membership, _ := s.db.GetMembership(ctx, existingUser.UserID, orgID)
		if membership != nil {
			return nil, fmt.Errorf("user is already a member of this organization")
		}
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

	// Do not use the email service for the time being, since it is not useful for the client (who can use any other messaging service).
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

	// ✅ ИСПРАВЬТЕ НА ЭТО:
	membership, err := s.db.GetMembership(ctx, userID, invitation.OrgID)
	if err != nil {
		// Если ошибка - membership не найден, продолжаем
	} else if membership != nil && membership.Status == "active" {
		// Только если ТОТ ЖЕ пользователь уже активный член
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

		slog.Error("Failed to create membership in AcceptInvitation",
			"error", err,
			"user_id", userID,
			"org_id", invitation.OrgID,
			"membership_id", newMembership.MembershipID)
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
	// Получаем организацию для проверки владельца
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return fmt.Errorf("failed to get organization info: %w", err)
	}

	// Нельзя менять роль владельца организации
	if org.OwnerID == targetUserID {
		return fmt.Errorf("cannot change role of organization owner")
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

// UpdateMemberStatus обновляет статус члена организации (active/suspended)
func (s *Service) UpdateMemberStatus(ctx context.Context, adminID, orgID, targetUserID, newStatus string) error {
	// Валидация статуса
	if newStatus != "active" && newStatus != "suspended" {
		return fmt.Errorf("invalid status: %s", newStatus)
	}

	// Получаем членство администратора
	adminMembership, err := s.db.GetMembership(ctx, adminID, orgID)
	if err != nil {
		return fmt.Errorf("admin is not a member of this organization")
	}

	// Проверяем права: только Admin и Manager могут менять статусы
	if adminMembership.Role != string(rbac.RoleAdmin) && adminMembership.Role != string(rbac.RoleManager) {
		return fmt.Errorf("insufficient permissions")
	}

	// Получаем целевое членство
	targetMembership, err := s.db.GetMembership(ctx, targetUserID, orgID)
	if err != nil {
		return fmt.Errorf("target user is not a member of this organization")
	}

	// Проверка иерархии: Manager не может блокировать Admin или другого Manager
	if adminMembership.Role == string(rbac.RoleManager) {
		if targetMembership.Role == string(rbac.RoleAdmin) || targetMembership.Role == string(rbac.RoleManager) {
			return fmt.Errorf("managers cannot manage admins or other managers")
		}
	}

	// Нельзя заблокировать владельца организации
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	if err == nil && org.OwnerID == targetUserID {
		return fmt.Errorf("cannot change status of organization owner")
	}

	targetMembership.Status = newStatus
	targetMembership.UpdatedAt = time.Now()

	// Обновляем запись в БД
	return s.db.UpdateMembership(ctx, targetMembership)
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

// ValidateActiveSession проверяет, что пользователь активен и имеет доступ к организации
func (s *Service) ValidateActiveSession(ctx context.Context, userID, orgID string) error {

	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !user.IsActive {
		return fmt.Errorf("user account is deactivated")
	}

	if orgID != "" {
		membership, err := s.db.GetMembership(ctx, userID, orgID)
		if err != nil || membership.Status != "active" {
			return fmt.Errorf("membership is not active or revoked")
		}
	}
	return nil
}
