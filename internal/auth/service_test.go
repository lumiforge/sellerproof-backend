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
