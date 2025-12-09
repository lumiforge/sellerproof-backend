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
	app_errors "github.com/lumiforge/sellerproof-backend/internal/errors"
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
	jwtManager jwtmanager.TokenManager
	rbac       *rbac.RBAC
	email      *email.Client
	config     *config.Config
}

// NewService создает новый auth сервис
func NewService(db ydb.Database, jwtManager jwtmanager.TokenManager, rbac *rbac.RBAC, emailClient *email.Client, cfg *config.Config) *Service {
	return &Service{
		db:         db,
		jwtManager: jwtManager,
		rbac:       rbac,
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
			return nil, app_errors.ErrInvalidInviteCode
		}
		if inv.Status != "pending" {
			return nil, app_errors.ErrInvitationNotPending
		}
		if time.Now().After(inv.ExpiresAt) {
			return nil, app_errors.ErrInvitationExpired
		}
		// Проверяем, что email регистрации совпадает с приглашением
		if !strings.EqualFold(inv.Email, req.Email) {
			return nil, app_errors.ErrRegistrationEmailMismatch
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
				return nil, app_errors.ErrFailedToGenerateVerificationCode
			}

			// Update user record

			existingUser.VerificationCode = newVerificationCode
			existingUser.VerificationExpiresAt = time.Now().Add(24 * time.Hour)
			existingUser.VerificationAttempts = 0
			existingUser.FullName = req.FullName
			existingUser.UpdatedAt = time.Now()

			if err := s.db.UpdateUser(ctx, existingUser); err != nil {
				return nil, app_errors.ErrFailedToUpdateUser
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
		return nil, app_errors.ErrEmailAlreadyExists
	}

	if err := validation.ValidateInputWithError(req.Password, "password", nameOptions); err != nil {
		return nil, err
	}

	// Хеширование пароля
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, app_errors.ErrFailedToHashPassword
	}

	// Генерация кода верификации
	verificationCode, err := email.GenerateVerificationCode()
	if err != nil {
		return nil, app_errors.ErrFailedToGenerateVerificationCode
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
		user.LastOrgID = &invitation.OrgID
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
		user.LastOrgID = &org.OrgID
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
			return nil, app_errors.ErrFailedToFetchFreePlan
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
			return nil, app_errors.ErrEmailAlreadyExists
		}
		return nil, app_errors.ErrRegistrationFailed
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
		return nil, app_errors.ErrUserNotFound
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
		return nil, app_errors.ErrTooManyFailedAttempts
	}

	// Проверка срока действия кода
	if time.Now().After(user.VerificationExpiresAt) {
		return nil, app_errors.ErrVerificationCodeExpired
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
			return nil, app_errors.ErrTooManyFailedAttempts
		}

		return nil, app_errors.ErrInvalidVerificationCode
	}

	// Обновление статуса верификации (Успех)
	user.EmailVerified = true
	user.VerificationCode = ""    // Очищаем код
	user.VerificationAttempts = 0 // Сбрасываем счетчик
	user.UpdatedAt = time.Now()

	err = s.db.UpdateUser(ctx, user)
	if err != nil {
		return nil, app_errors.ErrFailedToUpdateUser
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
		return nil, app_errors.ErrEmailRequired
	}
	if req.Password == "" {
		return nil, app_errors.ErrPasswordRequired
	}

	// Валидация длины email сначала
	if len(req.Email) > 254 {
		return nil, app_errors.ErrEmailTooLong
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

		return nil, app_errors.ErrInvalidCredentials
	}
	if len(req.Password) > 72 {
		return nil, app_errors.ErrPasswordTooLong
	}

	// Проверка, что email подтвержден (ДО проверки пароля для правильной семантики)
	if !user.EmailVerified {
		slog.Error("Email not verified", "email", req.Email, "emailVerified", user.EmailVerified)
		return nil, app_errors.ErrEmailNotVerified
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		// TODO delete me
		log.Println("Error in login 2", err)
		return nil, app_errors.ErrInvalidCredentials
	}

	// Проверка, что пользователь активен
	if !user.IsActive {
		return nil, app_errors.ErrUserAccountDeactivated
	}

	// Получение всех членств пользователя

	memberships, err := s.db.GetMembershipsByUser(ctx, user.UserID)
	if err != nil {

		return nil, app_errors.ErrFailedToGetUserMembership
	}
	if len(memberships) == 0 {

		return nil, app_errors.ErrMembershipNotFound
	}
	// Оптимизация: Получаем все организации одним запросом (Batch Fetch)
	orgIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		orgIDs = append(orgIDs, m.OrgID)
	}

	orgs, err := s.db.GetOrganizationsByIDs(ctx, orgIDs)
	if err != nil {
		return nil, app_errors.ErrFailedToGetOrganizations
	}

	// Создаем карту для быстрого поиска организации по ID
	orgMap := make(map[string]*ydb.Organization)
	for _, o := range orgs {
		orgMap[o.OrgID] = o
	}

	// Выбираем организацию
	var selectedMembership *ydb.Membership

	// ЛОГИКА ВЫБОРА ОРГАНИЗАЦИИ:

	// 1. Проверяем LastOrgID
	if user.LastOrgID != nil {
		for _, m := range memberships {
			if m.OrgID == *user.LastOrgID && m.Status == "active" {
				// Проверяем, существует ли организация физически
				if _, exists := orgMap[m.OrgID]; exists {
					selectedMembership = m
					break
				}
			}
		}
	}

	// 2. Если LastOrgID не сработал (пуст, или юзер удален из той орг), используем Fallback
	if selectedMembership == nil {
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
				// Приоритет 2: Первая активная (благодаря ORDER BY в SQL это будет самая старая)
				if selectedMembership == nil {
					selectedMembership = m
				}
			}
		}
	}

	// Если после всех проверок организация не выбрана (все удалены или рассинхрон), возвращаем ошибку
	if selectedMembership == nil {
		return nil, fmt.Errorf("no valid organizations found for user")
	}

	// Если LastOrgID был пуст или отличался от выбранного (fallback), обновляем его
	if user.LastOrgID == nil || *user.LastOrgID != selectedMembership.OrgID {
		user.LastOrgID = &selectedMembership.OrgID
		// Обновляем в фоне, чтобы не тормозить логин, или синхронно
		// Для надежности лучше синхронно, но можно игнорировать ошибку
		_ = s.db.UpdateUser(ctx, user)
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
			OrgID:       m.OrgID,
			Name:        orgName,
			Role:        role,
			CreatedAt:   org.CreatedAt.Unix(),
			MemberCount: 0, // Optimization: don't count members on login
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
		return nil, app_errors.ErrFailedToGenerateTokens
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

		return nil, app_errors.ErrFailedToCreateSession
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
	claims, err := s.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, app_errors.ErrInvalidRefreshToken
	}

	// Проверка токена в базе
	tokenHash := s.hashToken(req.RefreshToken)
	tokenRecord, err := s.db.GetRefreshToken(ctx, tokenHash)
	if err != nil || tokenRecord == nil || tokenRecord.IsRevoked {
		return nil, app_errors.ErrRefreshTokenNotFoundOrRevoked
	}
	// FIX: Проверяем актуальный статус пользователя и его права перед обновлением
	user, err := s.db.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, app_errors.ErrUserNotFound
	}
	if !user.IsActive {
		return nil, app_errors.ErrUserAccountDeactivated
	}
	// Проверяем, что пользователь всё ещё состоит в этой организации и получаем актуальную роль
	membership, err := s.db.GetMembership(ctx, claims.UserID, claims.OrgID)
	if err != nil {
		return nil, app_errors.ErrMembershipNotFoundOrRevoked
	}
	if membership.Status != "active" {
		return nil, app_errors.ErrMembershipNotActive
	}
	// Генерация новой пары токенов
	accessToken, refreshToken, err := s.jwtManager.GenerateTokenPair(
		user.UserID,
		user.Email,
		membership.Role,
		membership.OrgID,
	)
	if err != nil {
		return nil, app_errors.ErrFailedToGenerateNewTokens
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
			return nil, app_errors.ErrRefreshTokenNotFoundOrRevoked
		} else if strings.Contains(errorMsg, "refresh token expired") {
			return nil, app_errors.ErrRefreshTokenExpired
		}
		return nil, app_errors.ErrFailedToRevokeRefreshToken
	}

	return &models.LogoutResponse{
		Message: "Logout successful",
	}, nil
}

// GetProfile получает профиль пользователя
func (s *Service) GetProfile(ctx context.Context, userID, orgID string) (*models.GetProfileResponse, error) {
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, app_errors.ErrUserNotFound
	}

	// Получение всех членств пользователя
	memberships, err := s.db.GetMembershipsByUser(ctx, user.UserID)
	if err != nil || len(memberships) == 0 {
		return nil, app_errors.ErrMembershipNotFound
	}

	// Оптимизация: Получаем все организации одним запросом (Batch Fetch)
	orgIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		orgIDs = append(orgIDs, m.OrgID)
	}

	orgs, err := s.db.GetOrganizationsByIDs(ctx, orgIDs)
	if err != nil {
		return nil, app_errors.ErrFailedToGetOrganizations
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
	// Приоритет 0: Организация из текущего токена (Session Context)
	if orgID != "" {
		for _, m := range memberships {
			if m.OrgID == orgID && m.Status == "active" {
				if _, exists := orgMap[m.OrgID]; exists {
					selectedMembership = m
					break
				}
			}
		}
	}
	// Fallback логика, если токен не содержит валидной организации или orgID пуст
	if selectedMembership == nil {
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
		return nil, app_errors.ErrNoValidOrganizations
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
func (s *Service) UpdateProfile(ctx context.Context, userID, orgID string, req *models.UpdateProfileRequest) (*models.GetProfileResponse, error) {
	// Валидация обязательных полей
	if req.FullName == "" {
		return nil, app_errors.ErrFullNameRequired
	}

	// Валидация длины имени
	if len(req.FullName) < 2 {
		return nil, app_errors.ErrFullNameTooShort
	}
	if len(req.FullName) > 100 {
		return nil, app_errors.ErrFullNameTooLong
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
		return nil, app_errors.ErrUserNotFound
	}

	// Обновляем только поле full_name
	user.FullName = req.FullName
	user.UpdatedAt = time.Now()

	// Сохраняем изменения в базе
	err = s.db.UpdateUser(ctx, user)
	if err != nil {
		return nil, app_errors.ErrFailedToUpdateUser
	}

	// Получаем обновленный профиль пользователя
	return s.GetProfile(ctx, userID, orgID)
}

// SwitchOrganization переключает организацию пользователя

func (s *Service) SwitchOrganization(ctx context.Context, userID string, req *models.SwitchOrganizationRequest) (*models.SwitchOrganizationResponse, error) {
	// 1. Валидация и отзыв старого Refresh токена (Ротация)
	// Валидация формата токена
	claims, err := s.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, app_errors.ErrInvalidRefreshToken
	}

	// Проверка принадлежности токена пользователю
	if claims.UserID != userID {
		return nil, app_errors.ErrRefreshTokenDoesNotBelongToUser
	}

	// Проверка существования и статуса токена в БД
	oldTokenHash := s.hashToken(req.RefreshToken)
	tokenRecord, err := s.db.GetRefreshToken(ctx, oldTokenHash)
	if err != nil || tokenRecord == nil || tokenRecord.IsRevoked {
		return nil, app_errors.ErrRefreshTokenNotFoundOrRevoked
	}

	// 2. Проверка прав доступа к новой организации
	// Проверяем, что пользователь состоит в этой организации
	membership, err := s.db.GetMembership(ctx, userID, req.OrgID)
	// TODO DELETE ME
	log.Printf("Error in switch-organization: %v, userID: %v, orgID: %v", err, userID, req.OrgID)
	if err != nil {
		return nil, app_errors.ErrMembershipNotFound
	}

	if membership.Status != "active" {
		return nil, app_errors.ErrMembershipNotActive
	}

	// Получаем информацию о пользователе
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, app_errors.ErrUserNotFound
	}

	// все проверки пройдены, можно сжигать старый токен
	if err := s.db.RevokeRefreshToken(ctx, oldTokenHash); err != nil {
		return nil, app_errors.ErrFailedToRevokeOldToken
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
		return nil, app_errors.ErrFailedToGenerateTokens
	}

	// ОБНОВЛЕНИЕ LastOrgID
	if user.LastOrgID == nil || *user.LastOrgID != req.OrgID {
		user.LastOrgID = &req.OrgID
		if err := s.db.UpdateUser(ctx, user); err != nil {
			slog.Error("Failed to update user last_org_id", "error", err, "user_id", userID)
			// Не возвращаем ошибку, так как переключение фактически произошло
		}
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
		return nil, app_errors.ErrFailedToCreateSession
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
	// TODO: remove this after testing
	log.Println("InviteUser input", "inviter_id", inviterID, "org_id", orgID, "email", req.Email, "role", req.Role)
	// Валидация входных данных
	if req.Email == "" {
		return nil, app_errors.ErrEmailRequired
	}
	if req.Role == "" {
		return nil, app_errors.ErrRoleRequired
	}
	if req.Role == string(rbac.RoleAdmin) {
		return nil, app_errors.ErrOrgCanHaveOnlyOneAdmin
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
		return nil, app_errors.ErrInvalidRole
	}

	// Проверяем, что приглашающий является admin или manager в организации
	inviterMembership, err := s.db.GetMembership(ctx, inviterID, orgID)
	// TODO: remove this after testing
	log.Println("InviteUser GetMembership(inviter) result", "membership", inviterMembership, "error", err)
	if err != nil {
		return nil, app_errors.ErrInviterNotMember
	}

	if inviterMembership.Role != string(rbac.RoleAdmin) && inviterMembership.Role != string(rbac.RoleManager) {
		return nil, app_errors.ErrOnlyAdminsAndManagersCanInvite
	}

	// Проверяем, что приглашающий не пытается создать более высокую роль
	if inviterMembership.Role == string(rbac.RoleManager) && req.Role == string(rbac.RoleAdmin) {
		return nil, app_errors.ErrManagersCannotInviteAdmins
	}

	// Проверяем, что пользователь еще не приглашен в эту организацию
	existingInvitation, err := s.db.GetInvitationByEmail(ctx, orgID, req.Email)
	// TODO: remove this after testing
	log.Println("InviteUser GetInvitationByEmail result", "invitation", existingInvitation, "error", err)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		slog.Error("Failed to check existing invitations", "error", err)
		return nil, app_errors.ErrFailedToCheckExistingInvitations
	}

	if existingInvitation != nil {
		return nil, app_errors.ErrUserAlreadyInvited
	}

	existingUser, err := s.db.GetUserByEmail(ctx, req.Email)
	// TODO: remove this after testing
	log.Println("InviteUser GetUserByEmail result", "user", existingUser, "error", err)
	if err == nil && existingUser != nil {
		membership, _ := s.db.GetMembership(ctx, existingUser.UserID, orgID)
		// TODO: remove this after testing
		log.Println("InviteUser GetMembership(existingUser) result", "membership", membership)
		if membership != nil {
			return nil, app_errors.ErrUserIsAlreadyMember
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

	// TODO: remove this after testing
	log.Println("InviteUser before CreateInvitation", "invitation", invitation)
	err = s.db.CreateInvitation(ctx, invitation)
	// TODO: remove this after testing
	log.Println("InviteUser CreateInvitation result", "error", err)
	if err != nil {
		return nil, app_errors.ErrFailedToCreateInvitation
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

	// TODO: remove this after testing
	log.Println("InviteUser response", "invitation_id", invitation.InvitationID, "invite_code", inviteCode, "expires_at", invitation.ExpiresAt.Unix(), "email", req.Email, "role", req.Role)
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
	// TODO: remove this after testing
	log.Println("AcceptInvitation input", "user_id", userID, "invite_code", req.InviteCode)
	if req.InviteCode == "" {
		return nil, app_errors.ErrInviteCodeRequired
	}

	// Получаем приглашение по коду
	invitation, err := s.db.GetInvitationByCode(ctx, req.InviteCode)
	// TODO: remove this after testing
	log.Println("AcceptInvitation GetInvitationByCode result", "invitation", invitation, "error", err)
	if err != nil {
		return nil, app_errors.ErrInvalidInviteCode
	}

	// Проверяем статус приглашения
	if invitation.Status != "pending" {
		return nil, app_errors.ErrInvitationNotPending
	}

	// Проверяем срок действия приглашения
	if time.Now().After(invitation.ExpiresAt) {
		err = s.db.UpdateInvitationStatus(ctx, invitation.InvitationID, "expired")
		// TODO: remove this after testing
		log.Println("AcceptInvitation UpdateInvitationStatus(expired) result", "error", err)
		return nil, app_errors.ErrInvitationExpired
	}

	// Получаем пользователя
	user, err := s.db.GetUserByID(ctx, userID)
	// TODO: remove this after testing
	log.Println("AcceptInvitation GetUserByID result", "user", user, "error", err)
	if err != nil {
		return nil, app_errors.ErrUserNotFound
	}
	// Проверяем, что пользователь активен
	if !user.IsActive {
		return nil, app_errors.ErrUserAccountDeactivated
	}

	// Проверяем, что email пользователя совпадает с email приглашения
	if user.Email != invitation.Email {
		return nil, app_errors.ErrRegistrationEmailMismatch
	}

	membership, err := s.db.GetMembership(ctx, userID, invitation.OrgID)
	// TODO: remove this after testing
	log.Println("AcceptInvitation GetMembership result", "membership", membership, "error", err)
	if err != nil {
		// Если ошибка - membership не найден, продолжаем
	} else if membership != nil && membership.Status == "active" {
		// Только если ТОТ ЖЕ пользователь уже активный член
		return nil, app_errors.ErrUserIsAlreadyMember
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
	// TODO: remove this after testing
	log.Println("AcceptInvitation CreateMembership result", "membership_id", newMembership.MembershipID, "error", err)
	if err != nil {

		slog.Error("Failed to create membership in AcceptInvitation",
			"error", err,
			"user_id", userID,
			"org_id", invitation.OrgID,
			"membership_id", newMembership.MembershipID)
		return nil, app_errors.ErrFailedToCreateMembership

	}

	// Обновляем статус приглашения
	err = s.db.UpdateInvitationStatusWithAcceptTime(ctx, invitation.InvitationID, "accepted", time.Now())
	// TODO: remove this after testing
	log.Println("AcceptInvitation UpdateInvitationStatusWithAcceptTime result", "error", err)
	if err != nil {
		slog.Error("Failed to update invitation status", "error", err)
	}

	// Генерация новой сессии для принятой организации
	role := invitation.Role
	accessToken, refreshToken, err := s.jwtManager.GenerateTokenPair(
		user.UserID,
		user.Email,
		role,
		invitation.OrgID,
	)
	// TODO: remove this after testing
	log.Println("AcceptInvitation GenerateTokenPair result", "access_token", accessToken, "refresh_token", refreshToken, "role", role, "org_id", invitation.OrgID)
	if err != nil {
		return nil, app_errors.ErrFailedToGenerateTokens
	}

	// Сохранение refresh токена
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
	// TODO: remove this after testing
	log.Println("AcceptInvitation before CreateRefreshToken", "refresh_token_record", refreshTokenRecord)
	if err := s.db.CreateRefreshToken(ctx, refreshTokenRecord); err != nil {
		slog.Error("Failed to save refresh token during invitation accept", "error", err, "user_id", user.UserID)
		return nil, app_errors.ErrFailedToCreateSession
	}

	// TODO: remove this after testing
	log.Println("AcceptInvitation response", "membership_id", newMembership.MembershipID, "org_id", invitation.OrgID, "role", invitation.Role)
	return &models.AcceptInvitationResponse{
		MembershipID: newMembership.MembershipID,
		OrgID:        invitation.OrgID,
		Role:         invitation.Role,
		Message:      "Invitation accepted successfully",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.jwtManager.GetTokenExpiry("access")).Unix(),
	}, nil
}

// ListInvitations возвращает список приглашений организации
func (s *Service) ListInvitations(ctx context.Context, orgID string) ([]*models.InvitationInfo, error) {
	// TODO: remove this after testing
	log.Println("ListInvitations input", "org_id", orgID)
	invitations, err := s.db.GetInvitationsByOrg(ctx, orgID)
	// TODO: remove this after testing
	log.Println("ListInvitations GetInvitationsByOrg result", "count", len(invitations), "error", err)
	if err != nil {
		return nil, app_errors.ErrFailedToGetInvitations
	}

	result := make([]*models.InvitationInfo, 0, len(invitations))
	for _, inv := range invitations {
		invInfo := &models.InvitationInfo{
			InvitationID: inv.InvitationID,
			InviteCode:   inv.InviteCode,
			OrgID:        inv.OrgID,
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

	// TODO: remove this after testing
	log.Println("ListInvitations response", "count", len(result))
	return result, nil
}

// CancelInvitation отменяет приглашение
func (s *Service) CancelInvitation(ctx context.Context, invitationID string) error {
	// TODO: remove this after testing
	log.Println("CancelInvitation input", "invitation_id", invitationID)
	invitation, err := s.db.GetInvitationByID(ctx, invitationID)

	// TODO: remove this after testing
	log.Println("CancelInvitation GetInvitationByCode result", "invitation", invitation, "error", err)
	if err != nil {
		// Нам нужен другой метод для получения приглашения по ID
		// На время используем эту логику
		return app_errors.ErrInvitationNotFound
	}

	if invitation.Status != "pending" {
		return app_errors.ErrOnlyPendingInvitationsCanBeCancelled
	}

	err = s.db.UpdateInvitationStatus(ctx, invitationID, "cancelled")
	// TODO: remove this after testing
	log.Println("CancelInvitation UpdateInvitationStatus result", "error", err)
	if err != nil {
		return app_errors.ErrFailedToCancelInvitation
	}

	// TODO: remove this after testing
	log.Println("CancelInvitation response", "status", "cancelled", "invitation_id", invitationID)
	return nil
}

// GetOrganizationSubscription retrieves subscription and usage details for an organization
func (s *Service) GetOrganizationSubscription(ctx context.Context, orgID string) (*models.GetSubscriptionResponse, error) {
	// 1. Get Organization to find the owner
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetOrganizationInfo
	}

	// 2. Get Subscription by OwnerID
	sub, err := s.db.GetSubscriptionByUser(ctx, org.OwnerID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetSubscription
	}

	// 3. Get Storage Usage by OwnerID
	usedBytes, videoCount, err := s.db.GetStorageUsage(ctx, org.OwnerID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetStorageUsage
	}

	// 4. Calculate Usage Stats
	usedMB := usedBytes / (1024 * 1024)

	var storageAvailableMB int64
	var storagePercent float64
	if sub.StorageLimitMB > 0 {
		storageAvailableMB = sub.StorageLimitMB - usedMB
		if storageAvailableMB < 0 {
			storageAvailableMB = 0
		}
		storagePercent = (float64(usedMB) / float64(sub.StorageLimitMB)) * 100
		if storagePercent > 100 {
			storagePercent = 100
		}
	}

	var videosAvailable int64
	var videosPercent float64
	if sub.VideoCountLimit > 0 {
		videosAvailable = sub.VideoCountLimit - videoCount
		if videosAvailable < 0 {
			videosAvailable = 0
		}
		videosPercent = (float64(videoCount) / float64(sub.VideoCountLimit)) * 100
		if videosPercent > 100 {
			videosPercent = 100
		}
	}

	return &models.GetSubscriptionResponse{
		Subscription: &models.SubscriptionDetails{
			SubscriptionID:  sub.SubscriptionID,
			PlanID:          sub.PlanID,
			StorageLimitMB:  sub.StorageLimitMB,
			VideoCountLimit: sub.VideoCountLimit,
			IsActive:        sub.IsActive,
			TrialEndsAt:     sub.TrialEndsAt.Unix(),
			StartedAt:       sub.StartedAt.Unix(),
			ExpiresAt:       sub.ExpiresAt.Unix(),
			BillingCycle:    sub.BillingCycle,
		},
		Usage: &models.StorageUsage{
			StorageUsedMB:      usedMB,
			StorageAvailableMB: storageAvailableMB,
			StoragePercentUsed: storagePercent,
			VideosCount:        videoCount,
			VideosAvailable:    videosAvailable,
			VideosPercentUsed:  videosPercent,
		},
	}, nil
}

// UpdateMemberRole обновляет роль члена организации
func (s *Service) UpdateMemberRole(ctx context.Context, adminID, orgID, targetUserID, newRole string) error {
	// TODO: remove this after testing
	log.Println("UpdateMemberRole input", "admin_id", adminID, "org_id", orgID, "target_user_id", targetUserID, "new_role", newRole)
	// Проверяем, что админ является admin в организации
	adminMembership, err := s.db.GetMembership(ctx, adminID, orgID)
	// TODO: remove this after testing
	log.Println("UpdateMemberRole GetMembership(admin) result", "membership", adminMembership, "error", err)
	if err != nil {
		return app_errors.ErrInviterNotMember
	}

	if adminMembership.Role != string(rbac.RoleAdmin) {
		return app_errors.ErrOnlyAdminsCanChangeRoles
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
		return app_errors.ErrInvalidRole
	}

	// Получаем текущее членство
	targetMembership, err := s.db.GetMembership(ctx, targetUserID, orgID)
	// TODO: remove this after testing
	log.Println("UpdateMemberRole GetMembership(target) result", "membership", targetMembership, "error", err)
	if err != nil {
		return app_errors.ErrTargetUserNotMember
	}
	// Получаем организацию для проверки владельца
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	// TODO: remove this after testing
	log.Println("UpdateMemberRole GetOrganizationByID result", "org", org, "error", err)
	if err != nil {
		return app_errors.ErrFailedToGetOrganizationInfo
	}

	// Нельзя менять роль владельца организации
	if org.OwnerID == targetUserID {
		return app_errors.ErrCannotChangeRoleOfOrgOwner
	}
	// Обновляем роль
	targetMembership.Role = newRole
	targetMembership.UpdatedAt = time.Now()

	err = s.db.UpdateMembership(ctx, targetMembership)
	// TODO: remove this after testing
	log.Println("UpdateMemberRole UpdateMembership result", "membership_id", targetMembership.MembershipID, "error", err)
	if err != nil {
		return app_errors.ErrFailedToUpdateMemberRole
	}

	// TODO: remove this after testing
	log.Println("UpdateMemberRole response", "target_user_id", targetUserID, "new_role", newRole)
	return nil
}

// RemoveMember удаляет члена из организации
func (s *Service) RemoveMember(ctx context.Context, adminID, orgID, targetUserID string) error {
	// TODO: remove this after testing
	log.Println("RemoveMember input", "admin_id", adminID, "org_id", orgID, "target_user_id", targetUserID)
	// Проверяем, что админ является admin в организации
	adminMembership, err := s.db.GetMembership(ctx, adminID, orgID)
	// TODO: remove this after testing
	log.Println("RemoveMember GetMembership(admin) result", "membership", adminMembership, "error", err)
	if err != nil {
		return app_errors.ErrInviterNotMember
	}

	if adminMembership.Role != string(rbac.RoleAdmin) {
		return app_errors.ErrOnlyAdminsCanRemoveMembers
	}

	// Проверяем, что целевой пользователь состоит в организации
	targetMembership, err := s.db.GetMembership(ctx, targetUserID, orgID)
	// TODO: remove this after testing
	log.Println("RemoveMember GetMembership(target) result", "membership", targetMembership, "error", err)
	if err != nil {
		return app_errors.ErrTargetUserNotMember
	}

	// Нельзя удалить владельца организации
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	// TODO: remove this after testing
	log.Println("RemoveMember GetOrganizationByID result", "org", org, "error", err)
	if err == nil && org.OwnerID == targetUserID {
		return app_errors.ErrCannotRemoveOrgOwner
	}

	// Удаляем членство
	err = s.db.DeleteMembership(ctx, targetMembership.MembershipID)
	// TODO: remove this after testing
	log.Println("RemoveMember DeleteMembership result", "membership_id", targetMembership.MembershipID, "error", err)
	if err != nil {
		return app_errors.ErrFailedToRemoveMember
	}

	// TODO: remove this after testing
	log.Println("RemoveMember response", "removed_user_id", targetUserID)
	return nil
}

// UpdateMemberStatus обновляет статус члена организации (active/suspended)
func (s *Service) UpdateMemberStatus(ctx context.Context, adminID, orgID, targetUserID, newStatus string) error {
	// TODO: remove this after testing
	log.Println("UpdateMemberStatus input", "admin_id", adminID, "org_id", orgID, "target_user_id", targetUserID, "new_status", newStatus)
	// Валидация статуса
	if newStatus != "active" && newStatus != "suspended" {
		return app_errors.ErrInvalidStatus
	}

	// Получаем членство администратора
	adminMembership, err := s.db.GetMembership(ctx, adminID, orgID)
	// TODO: remove this after testing
	log.Println("UpdateMemberStatus GetMembership(admin) result", "membership", adminMembership, "error", err)
	if err != nil {
		return app_errors.ErrInviterNotMember
	}

	// Проверяем права: только Admin и Manager могут менять статусы
	if adminMembership.Role != string(rbac.RoleAdmin) && adminMembership.Role != string(rbac.RoleManager) {
		return app_errors.ErrInsufficientPermissions
	}

	// Получаем целевое членство
	targetMembership, err := s.db.GetMembership(ctx, targetUserID, orgID)
	// TODO: remove this after testing
	log.Println("UpdateMemberStatus GetMembership(target) result", "membership", targetMembership, "error", err)
	if err != nil {
		return app_errors.ErrTargetUserNotMember
	}

	// Проверка иерархии: Manager не может блокировать Admin или другого Manager
	if adminMembership.Role == string(rbac.RoleManager) {
		if targetMembership.Role == string(rbac.RoleAdmin) || targetMembership.Role == string(rbac.RoleManager) {
			return app_errors.ErrManagersCannotManageAdmins
		}
	}

	// Нельзя заблокировать владельца организации
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	// TODO: remove this after testing
	log.Println("UpdateMemberStatus GetOrganizationByID result", "org", org, "error", err)
	if err == nil && org.OwnerID == targetUserID {
		return app_errors.ErrCannotChangeStatusOfOrgOwner
	}

	targetMembership.Status = newStatus
	targetMembership.UpdatedAt = time.Now()

	// Обновляем запись в БД
	// TODO: remove this after testing
	log.Println("UpdateMemberStatus before UpdateMembership", "membership_id", targetMembership.MembershipID, "new_status", newStatus)
	return s.db.UpdateMembership(ctx, targetMembership)
}

// ListOrgMembers возвращает список членов организации
func (s *Service) ListOrgMembers(ctx context.Context, orgID string) ([]*models.MemberInfo, error) {
	// TODO: remove this after testing
	log.Println("ListOrgMembers input", "org_id", orgID)
	memberships, err := s.db.GetMembershipsByOrg(ctx, orgID)
	// TODO: remove this after testing
	log.Println("ListOrgMembers GetMembershipsByOrg result", "count", len(memberships), "error", err)
	if err != nil {
		return nil, app_errors.ErrFailedToGetMembers
	}

	result := make([]*models.MemberInfo, 0, len(memberships))
	for _, m := range memberships {
		// Получаем информацию о пользователе
		user, err := s.db.GetUserByID(ctx, m.UserID)
		// TODO: remove this after testing
		log.Println("ListOrgMembers GetUserByID result", "user", user, "error", err)
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

	// TODO: remove this after testing
	log.Println("ListOrgMembers response", "count", len(result))
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
		return false, app_errors.ErrFailedToGetUserMembership
	}

	roleStr := membership.Role
	role := rbac.Role(roleStr)
	return s.rbac.CheckPermissionWithRole(role, permission), nil
}

// CreateOrganization создает новую организацию для администратора
func (s *Service) CreateOrganization(ctx context.Context, userID string, req *models.CreateOrganizationRequest) (*models.CreateOrganizationResponse, error) {
	if req == nil {
		return nil, app_errors.ErrRequestIsRequired
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
		return nil, app_errors.ErrFailedToGetUserMemberships
	}

	isAdmin := false
	for _, membership := range memberships {
		if membership.Status == "active" && membership.Role == string(rbac.RoleAdmin) {
			isAdmin = true
			break
		}
	}

	if !isAdmin {
		return nil, app_errors.ErrOnlyAdminsCanCreateOrgs
	}

	// Проверка уникальности названия организации для данного пользователя
	orgs, err := s.db.GetOrganizationsByOwner(ctx, userID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetUserOrgs
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
		return nil, app_errors.ErrFailedToMarshalOrgSettings
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
		return nil, app_errors.ErrFailedToCreateOrg
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
		return nil, app_errors.ErrFailedToCreateMembership
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
		return app_errors.ErrUserNotFound
	}
	if !user.IsActive {
		return app_errors.ErrUserAccountDeactivated
	}

	if orgID != "" {
		membership, err := s.db.GetMembership(ctx, userID, orgID)
		if err != nil || membership.Status != "active" {
			return app_errors.ErrMembershipNotActiveOrRevoked
		}
	}
	return nil
}

// RequestPasswordReset инициирует процесс сброса пароля
func (s *Service) RequestPasswordReset(ctx context.Context, req *models.ForgotPasswordRequest) (*models.ForgotPasswordResponse, error) {
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if err := validation.ValidateEmail(req.Email, "email"); err != nil {
		return nil, err
	}

	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Возвращаем успех, даже если email не найден (security best practice)
		return &models.ForgotPasswordResponse{
			Message: "If an account exists with this email, a password reset code has been sent.",
		}, nil
	}

	if !user.IsActive {
		return nil, app_errors.ErrUserAccountDeactivated
	}

	// Rate Limiting: Проверяем, когда был создан предыдущий код
	// Мы устанавливаем срок жизни +1 час. Если до истечения осталось больше 59 минут,
	// значит код был создан менее 1 минуты назад.
	if user.PasswordResetExpiresAt != nil {
		if time.Until(*user.PasswordResetExpiresAt) > 59*time.Minute {
			// Возвращаем успех, но ничего не делаем (Silent fail для защиты от спама)
			slog.Info("Password reset rate limit hit", "email", req.Email)
			return &models.ForgotPasswordResponse{
				Message: "If an account exists with this email, a password reset code has been sent.",
			}, nil
		}
	}

	resetCode, err := email.GenerateVerificationCode()
	if err != nil {
		return nil, app_errors.ErrFailedToGenerateResetCode
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	if err := s.db.UpdateUserPasswordResetInfo(ctx, user.UserID, resetCode, expiresAt); err != nil {
		return nil, app_errors.ErrFailedToSaveResetCode
	}

	if s.email.IsConfigured() {
		_, err := s.email.SendPasswordResetEmail(ctx, req.Email, resetCode, s.config.AppLoginURL)
		if err != nil {
			slog.Error("Failed to send password reset email", "error", err, "email", req.Email)
		} else {
			emailLog := &ydb.EmailLog{
				EmailID:   uuid.New().String(),
				UserID:    user.UserID,
				EmailType: string(email.EmailTypePasswordReset),
				Recipient: req.Email,
				Status:    "sent",
				SentAt:    time.Now(),
			}
			_ = s.db.CreateEmailLog(ctx, emailLog)
		}
	}

	return &models.ForgotPasswordResponse{
		Message: "If an account exists with this email, a password reset code has been sent.",
	}, nil
}

// ResetPassword сбрасывает пароль с использованием кода
func (s *Service) ResetPassword(ctx context.Context, req *models.ResetPasswordRequest) (*models.ResetPasswordResponse, error) {
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Code = strings.TrimSpace(req.Code)
	// TODO: remove this after testing
	log.Println("ResetPassword input", "email:", req.Email, ", code:", req.Code)
	if err := validation.ValidateEmail(req.Email, "email"); err != nil {
		return nil, err
	}
	if req.Code == "" {
		return nil, app_errors.ErrInviteCodeRequired
	}
	if len(req.NewPassword) < 8 || len(req.NewPassword) > 72 {
		return nil, app_errors.ErrPasswordWrongLength
	}

	user, err := s.db.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, app_errors.ErrInvalidRequest
	}

	// TODO: remove this after testing
	log.Println("ResetPassword GetUserByEmail result", "password_reset_code:", user.PasswordResetCode)
	if user.PasswordResetCode == nil || *user.PasswordResetCode != req.Code {
		return nil, app_errors.ErrInvalidResetCode
	}
	if user.PasswordResetExpiresAt == nil || time.Now().After(*user.PasswordResetExpiresAt) {
		return nil, app_errors.ErrResetCodeExpired
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, app_errors.ErrFailedToHashPassword
	}

	if err := s.db.UpdateUserPassword(ctx, user.UserID, string(passwordHash)); err != nil {
		return nil, app_errors.ErrFailedToUpdatePassword
	}

	_ = s.db.RevokeAllUserRefreshTokens(ctx, user.UserID)

	return &models.ResetPasswordResponse{
		Message: "Password has been reset successfully",
	}, nil
}

// GetUserOrganizations retrieves all organizations for a user
func (s *Service) GetUserOrganizations(ctx context.Context, userID string) (*models.GetUserOrganizationsResponse, error) {
	memberships, err := s.db.GetMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetUserMembership
	}

	if len(memberships) == 0 {
		return &models.GetUserOrganizationsResponse{
			Organizations: []*models.OrganizationInfo{},
		}, nil
	}

	orgIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		orgIDs = append(orgIDs, m.OrgID)
	}

	orgs, err := s.db.GetOrganizationsByIDs(ctx, orgIDs)
	if err != nil {
		return nil, app_errors.ErrFailedToGetOrganizations
	}

	orgMap := make(map[string]*ydb.Organization)
	for _, o := range orgs {
		orgMap[o.OrgID] = o
	}

	result := make([]*models.OrganizationInfo, 0, len(memberships))
	for _, m := range memberships {
		if org, exists := orgMap[m.OrgID]; exists {
			// Получаем количество участников
			// TODO: В будущем оптимизировать через отдельный метод GetMemberCount или поле в Organization
			members, err := s.db.GetMembershipsByOrg(ctx, m.OrgID)
			memberCount := 0
			if err == nil {
				memberCount = len(members)
			}

			result = append(result, &models.OrganizationInfo{
				OrgID:       m.OrgID,
				Name:        org.Name,
				Role:        m.Role,
				MemberCount: memberCount,
				CreatedAt:   org.CreatedAt.Unix(),
			})
		}
	}

	return &models.GetUserOrganizationsResponse{
		Organizations: result,
	}, nil
}

// DeleteOrganization удаляет организацию пользователя
func (s *Service) DeleteOrganization(ctx context.Context, userID, orgID string) error {
	// 1. Получаем информацию об организации
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return app_errors.ErrFailedToGetOrganizationInfo
	}

	// 2. Проверяем, является ли пользователь владельцем
	if org.OwnerID != userID {
		return app_errors.ErrOnlyOwnerCanDeleteOrg
	}

	// 3. Удаляем организацию и связанные данные
	return s.db.DeleteOrganizationTx(ctx, orgID)
}

// UpdateOrganizationName updates the name of an organization
func (s *Service) UpdateOrganizationName(ctx context.Context, userID, orgID string, req *models.UpdateOrganizationNameRequest) (*models.UpdateOrganizationNameResponse, error) {
	if req.Name == "" {
		return nil, validation.ValidationError{Field: "name", Message: "is required"}
	}

	orgName, err := validation.SanitizeOrganizationName(req.Name)
	if err != nil {
		return nil, err
	}

	// Check if user is a member of the organization
	membership, err := s.db.GetMembership(ctx, userID, orgID)
	if err != nil {
		return nil, app_errors.ErrMembershipNotFound
	}

	// Check permissions: Only Admin can update organization name
	if membership.Role != string(rbac.RoleAdmin) {
		return nil, app_errors.ErrInsufficientPermissions
	}

	// Get Organization
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetOrganizationInfo
	}

	// Update name
	org.Name = orgName
	org.UpdatedAt = time.Now()

	if err := s.db.UpdateOrganization(ctx, org); err != nil {
		slog.Error("Failed to update organization name", "error", err, "org_id", orgID)
		return nil, app_errors.ErrInternalServer
	}

	return &models.UpdateOrganizationNameResponse{
		OrgID:   org.OrgID,
		Name:    org.Name,
		Message: "Organization name updated successfully",
	}, nil
}
