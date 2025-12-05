package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lumiforge/sellerproof-backend/internal/config"
	"github.com/lumiforge/sellerproof-backend/internal/email"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	jwtmocks "github.com/lumiforge/sellerproof-backend/internal/jwt/mocks"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
	ydbmocks "github.com/lumiforge/sellerproof-backend/internal/ydb/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// setupAuthService создает сервис с моками
// setupAuthService создает сервис с моками
func setupAuthService() (*Service, *ydbmocks.Database, *jwtmocks.TokenManager) {
	mockDB := new(ydbmocks.Database)
	mockJWT := new(jwtmocks.TokenManager)

	// Используем реальный RBAC, так как это чистая логика
	realRBAC := rbac.NewRBAC()

	// Создаем "пустой" email клиент, чтобы IsConfigured() возвращал false и не пытался слать письма
	// Важно: передаем пустой конфиг
	emailClient := email.NewClient(&config.Config{})

	cfg := &config.Config{}

	service := NewService(mockDB, mockJWT, realRBAC, emailClient, cfg)
	return service, mockDB, mockJWT
}
func TestService_Register_Success(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	req := &models.RegisterRequest{
		Email:            "test@example.com",
		Password:         "password123",
		FullName:         "Test User",
		OrganizationName: "Test Org",
	}

	// 1. Mock: Проверка существования пользователя (должен вернуть ошибку, т.к. юзера нет)
	mockDB.On("GetUserByEmail", ctx, "test@example.com").Return(nil, errors.New("not found"))

	// 2. Mock: Получение тарифного плана (для создания подписки)
	mockDB.On("GetPlanByID", ctx, "free").Return(&ydb.Plan{
		PlanID:          "free",
		StorageLimitMB:  1024,
		VideoCountLimit: 10,
	}, nil)

	// 3. Mock: Транзакция регистрации
	// Используем mock.MatchedBy для проверки типов, но не содержимого (т.к. ID генерируются внутри)
	mockDB.On("RegisterUserTx",
		ctx,
		mock.MatchedBy(func(u *ydb.User) bool { return u.Email == "test@example.com" }), // User
		mock.MatchedBy(func(o *ydb.Organization) bool { return o.Name == "Test Org" }),  // Org
		mock.AnythingOfType("*ydb.Membership"),                                          // Membership
		mock.AnythingOfType("*ydb.Subscription"),                                        // Subscription
		"",                                                                              // InvitationID (empty)
	).Return(nil)

	// Act
	resp, err := service.Register(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Registration successful. Please check your email for verification.", resp.Message)

	mockDB.AssertExpectations(t)
}

func TestService_Register_UserAlreadyExists(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	req := &models.RegisterRequest{
		Email:            "existing@example.com",
		Password:         "password123",
		FullName:         "Test User",
		OrganizationName: "Test Org", // Добавлено обязательное поле
	}

	// Mock: Пользователь найден и верифицирован
	existingUser := &ydb.User{
		UserID:        "user-123",
		Email:         "existing@example.com",
		EmailVerified: true,
	}
	mockDB.On("GetUserByEmail", ctx, "existing@example.com").Return(existingUser, nil)

	// Act
	resp, err := service.Register(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "email already exists", err.Error())

	mockDB.AssertExpectations(t)
}

func TestService_SwitchOrganization_Success(t *testing.T) {
	service, mockDB, mockJWT := setupAuthService()
	ctx := context.Background()

	userID := "user-1"
	targetOrgID := "org-2"
	refreshToken := "valid-refresh-token"

	req := &models.SwitchOrganizationRequest{
		OrgID:        targetOrgID,
		RefreshToken: refreshToken,
	}

	// --- MOCK SETUP START ---

	// 1. Валидация токена (JWT Mock)
	// Теперь мы можем использовать реальную структуру jwt.Claims благодаря импорту
	mockJWT.On("ValidateToken", refreshToken).Return(&jwt.Claims{
		UserID: userID,
		OrgID:  "old-org-id", // Старая организация в токене
	}, nil)

	// 2. Проверка токена в БД
	mockDB.On("GetRefreshToken", ctx, mock.AnythingOfType("string")).Return(&ydb.RefreshToken{
		TokenID:   "token-id",
		UserID:    userID,
		IsRevoked: false,
	}, nil)

	// 3. Проверка членства в целевой организации
	mockDB.On("GetMembership", ctx, userID, targetOrgID).Return(&ydb.Membership{
		UserID: userID,
		OrgID:  targetOrgID,
		Status: "active",
		Role:   "user",
	}, nil)

	// 4. Получение пользователя
	mockDB.On("GetUserByID", ctx, userID).Return(&ydb.User{
		UserID: userID,
		Email:  "test@example.com",
	}, nil)

	// 5. Отзыв старого токена
	mockDB.On("RevokeRefreshToken", ctx, mock.AnythingOfType("string")).Return(nil)

	// 6. Генерация новых токенов (JWT Mock)
	mockJWT.On("GenerateTokenPair", userID, "test@example.com", "user", targetOrgID).Return("new-access", "new-refresh", nil)
	mockJWT.On("GetTokenExpiry", "access").Return(time.Hour)
	mockJWT.On("GetTokenExpiry", "refresh").Return(time.Hour * 24)

	// 7. Обновление LastOrgID пользователя
	mockDB.On("UpdateUser", ctx, mock.MatchedBy(func(u *ydb.User) bool {
		return *u.LastOrgID == targetOrgID
	})).Return(nil)

	// 8. Сохранение нового refresh токена
	mockDB.On("CreateRefreshToken", ctx, mock.Anything).Return(nil)

	// --- MOCK SETUP END ---

	// Act (Раскомментировано и используется service и req)
	resp, err := service.SwitchOrganization(ctx, userID, req)

	// Assert (Раскомментировано)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, targetOrgID, resp.OrgID)
	assert.Equal(t, "new-access", resp.AccessToken)

	mockDB.AssertExpectations(t)
	mockJWT.AssertExpectations(t)
}
func TestService_RemoveMember_RBAC_ManagerCannotRemoveAdmin(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	adminID := "manager-id" // Тот, кто пытается удалить (Manager)
	orgID := "org-1"
	targetUserID := "admin-id" // Тот, кого пытаются удалить (Admin)

	// 1. Получаем членство вызывающего (Manager)
	mockDB.On("GetMembership", ctx, adminID, orgID).Return(&ydb.Membership{
		UserID: adminID,
		OrgID:  orgID,
		Role:   "manager", // Он менеджер
	}, nil)

	// Act
	err := service.RemoveMember(ctx, adminID, orgID, targetUserID)

	// Assert
	assert.Error(t, err)
	// Ожидаем ошибку, так как в коде service.go:
	// if adminMembership.Role != string(rbac.RoleAdmin) { return fmt.Errorf("only admins can remove members") }
	assert.Contains(t, err.Error(), "only admins can remove members")

	mockDB.AssertExpectations(t)
}

func TestService_Login_Success(t *testing.T) {
	service, mockDB, mockJWT := setupAuthService()
	ctx := context.Background()

	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := &ydb.User{
		UserID:        "user-1",
		Email:         "test@example.com",
		PasswordHash:  string(hashedPassword),
		EmailVerified: true,
		IsActive:      true,
		FullName:      "Test User",
	}

	req := &models.LoginRequest{
		Email:    "test@example.com",
		Password: password,
	}

	// Mocks
	mockDB.On("GetUserByEmail", ctx, req.Email).Return(user, nil)
	mockDB.On("GetMembershipsByUser", ctx, user.UserID).Return([]*ydb.Membership{
		{OrgID: "org-1", Role: "admin", Status: "active"},
	}, nil)
	mockDB.On("GetOrganizationsByIDs", ctx, []string{"org-1"}).Return([]*ydb.Organization{
		{OrgID: "org-1", Name: "Test Org", OwnerID: user.UserID},
	}, nil)
	mockDB.On("UpdateUser", ctx, mock.Anything).Return(nil) // Update LastOrgID

	mockJWT.On("GenerateTokenPair", user.UserID, user.Email, "admin", "org-1").Return("access-token", "refresh-token", nil)
	mockJWT.On("GetTokenExpiry", "access").Return(time.Hour)
	mockJWT.On("GetTokenExpiry", "refresh").Return(time.Hour * 24)

	mockDB.On("CreateRefreshToken", ctx, mock.Anything).Return(nil)

	// Act
	resp, err := service.Login(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "access-token", resp.AccessToken)
	assert.Equal(t, user.UserID, resp.User.UserID)
}

func TestService_Login_InvalidPassword(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	user := &ydb.User{
		UserID:        "user-1",
		Email:         "test@example.com",
		PasswordHash:  string(hashedPassword),
		EmailVerified: true,
		IsActive:      true,
	}

	req := &models.LoginRequest{
		Email:    "test@example.com",
		Password: "wrong-password",
	}

	mockDB.On("GetUserByEmail", ctx, req.Email).Return(user, nil)

	// Act
	resp, err := service.Login(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "invalid credentials", err.Error())
}

func TestService_Login_EmailNotVerified(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	user := &ydb.User{
		UserID:        "user-1",
		Email:         "test@example.com",
		EmailVerified: false, // Not verified
	}

	req := &models.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockDB.On("GetUserByEmail", ctx, req.Email).Return(user, nil)

	// Act
	resp, err := service.Login(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "email not verified", err.Error())
}

func TestService_Login_UserDeactivated(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user := &ydb.User{
		UserID:        "user-1",
		Email:         "test@example.com",
		PasswordHash:  string(hashedPassword),
		EmailVerified: true,
		IsActive:      false, // Deactivated
	}

	req := &models.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockDB.On("GetUserByEmail", ctx, req.Email).Return(user, nil)

	// Act
	resp, err := service.Login(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "user account is deactivated", err.Error())
}

func TestService_VerifyEmail_Success(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	req := &models.VerifyEmailRequest{
		Email: "test@example.com",
		Code:  "123456",
	}

	user := &ydb.User{
		UserID:                "user-1",
		Email:                 "test@example.com",
		VerificationCode:      "123456",
		VerificationExpiresAt: time.Now().Add(time.Hour),
		EmailVerified:         false,
	}

	mockDB.On("GetUserByEmail", ctx, req.Email).Return(user, nil)
	mockDB.On("UpdateUser", ctx, mock.MatchedBy(func(u *ydb.User) bool {
		return u.EmailVerified == true && u.VerificationCode == ""
	})).Return(nil)

	// Act
	resp, err := service.VerifyEmail(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestService_VerifyEmail_InvalidCode(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	req := &models.VerifyEmailRequest{
		Email: "test@example.com",
		Code:  "wrong-code",
	}

	user := &ydb.User{
		UserID:                "user-1",
		Email:                 "test@example.com",
		VerificationCode:      "123456",
		VerificationExpiresAt: time.Now().Add(time.Hour),
		VerificationAttempts:  0,
	}

	mockDB.On("GetUserByEmail", ctx, req.Email).Return(user, nil)
	mockDB.On("UpdateUser", ctx, mock.MatchedBy(func(u *ydb.User) bool {
		return u.VerificationAttempts == 1
	})).Return(nil)

	// Act
	resp, err := service.VerifyEmail(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid verification code")
}

func TestService_VerifyEmail_ExpiredCode(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	req := &models.VerifyEmailRequest{
		Email: "test@example.com",
		Code:  "123456",
	}

	user := &ydb.User{
		UserID:                "user-1",
		Email:                 "test@example.com",
		VerificationCode:      "123456",
		VerificationExpiresAt: time.Now().Add(-time.Hour), // Expired
	}

	mockDB.On("GetUserByEmail", ctx, req.Email).Return(user, nil)

	// Act
	resp, err := service.VerifyEmail(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "verification code expired", err.Error())
}

func TestService_InviteUser_UserAlreadyMember(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	inviterID := "admin-1"
	orgID := "org-1"
	req := &models.InviteUserRequest{Email: "existing@example.com", Role: "user"}

	// Mock inviter permissions
	mockDB.On("GetMembership", ctx, inviterID, orgID).Return(&ydb.Membership{Role: "admin"}, nil)
	// Mock no pending invitation
	mockDB.On("GetInvitationByEmail", ctx, orgID, req.Email).Return(nil, errors.New("not found"))
	// Mock user exists
	existingUser := &ydb.User{UserID: "user-2", Email: "existing@example.com"}
	mockDB.On("GetUserByEmail", ctx, req.Email).Return(existingUser, nil)
	// Mock user is already member
	mockDB.On("GetMembership", ctx, existingUser.UserID, orgID).Return(&ydb.Membership{Status: "active"}, nil)

	_, err := service.InviteUser(ctx, inviterID, orgID, req) // Возвращает (*InviteUserResponse, error)
	_, errResult := err, err                                 // Go trick to handle return values if needed, but here we check err

	assert.Error(t, errResult) // Исправлено: проверяем ошибку
	assert.Equal(t, "user is already a member of this organization", errResult.Error())
}

func TestService_InviteUser_ManagerCannotInviteAdmin(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	inviterID := "manager-1"
	orgID := "org-1"
	req := &models.InviteUserRequest{Email: "new@example.com", Role: "admin"}

	// Mock inviter is Manager
	mockDB.On("GetMembership", ctx, inviterID, orgID).Return(&ydb.Membership{Role: "manager"}, nil)

	_, err := service.InviteUser(ctx, inviterID, orgID, req)

	assert.Error(t, err)
	assert.Equal(t, "organization can have only one admin", err.Error())
}

func TestService_AcceptInvitation_Expired(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	req := &models.AcceptInvitationRequest{InviteCode: "expired-code"}
	invitation := &ydb.Invitation{
		InvitationID: "inv-1",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(-time.Hour), // Expired
	}

	mockDB.On("GetInvitationByCode", ctx, req.InviteCode).Return(invitation, nil)
	mockDB.On("UpdateInvitationStatus", ctx, invitation.InvitationID, "expired").Return(nil)

	_, err := service.AcceptInvitation(ctx, "user-1", req)

	assert.Error(t, err)
	assert.Equal(t, "invitation has expired", err.Error())
}

func TestService_RefreshToken_Revoked(t *testing.T) {
	service, mockDB, mockJWT := setupAuthService()
	ctx := context.Background()

	req := &models.RefreshTokenRequest{RefreshToken: "revoked-token"}

	mockJWT.On("ValidateToken", req.RefreshToken).Return(&jwt.Claims{UserID: "user-1"}, nil)
	mockDB.On("GetRefreshToken", ctx, mock.Anything).Return(&ydb.RefreshToken{IsRevoked: true}, nil)

	_, err := service.RefreshToken(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, "refresh token not found or revoked", err.Error())
}

func TestService_RequestPasswordReset_Success(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	req := &models.ForgotPasswordRequest{Email: "test@example.com"}
	user := &ydb.User{UserID: "u1", Email: "test@example.com", IsActive: true}

	// Mock: User found
	mockDB.On("GetUserByEmail", ctx, "test@example.com").Return(user, nil)
	// Mock: Save reset code
	mockDB.On("UpdateUserPasswordResetInfo", ctx, "u1", mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)
	// Mock: Log email (since email client is mocked but logic tries to log)
	// Note: In setupAuthService email client is not configured, so it might skip sending.
	// However, if we want to test full flow we might need to adjust IsConfigured logic or just check DB calls.
	// In current implementation if !IsConfigured, it just returns success.

	resp, err := service.RequestPasswordReset(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Message, "password reset code has been sent")
	mockDB.AssertExpectations(t)
}

func TestService_ResetPassword_Success(t *testing.T) {
	service, mockDB, _ := setupAuthService()
	ctx := context.Background()

	code := "123456"
	expires := time.Now().Add(time.Hour)
	req := &models.ResetPasswordRequest{
		Email:       "test@example.com",
		Code:        code,
		NewPassword: "newPassword123",
	}

	user := &ydb.User{
		UserID:                 "u1",
		Email:                  "test@example.com",
		PasswordResetCode:      &code,
		PasswordResetExpiresAt: &expires,
	}

	// Mock: Get user
	mockDB.On("GetUserByEmail", ctx, "test@example.com").Return(user, nil)
	// Mock: Update password
	mockDB.On("UpdateUserPassword", ctx, "u1", mock.MatchedBy(func(hash string) bool {
		// Verify it's hashed (bcrypt hash is usually ~60 chars)
		return len(hash) > 50 && hash != "newPassword123"
	})).Return(nil)
	// Mock: Revoke tokens
	mockDB.On("RevokeAllUserRefreshTokens", ctx, "u1").Return(nil)

	resp, err := service.ResetPassword(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Password has been reset successfully", resp.Message)
	mockDB.AssertExpectations(t)
}
