package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lumiforge/sellerproof-backend/internal/audit"
	"github.com/lumiforge/sellerproof-backend/internal/auth"
	"github.com/lumiforge/sellerproof-backend/internal/config"
	"github.com/lumiforge/sellerproof-backend/internal/email"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	jwtmocks "github.com/lumiforge/sellerproof-backend/internal/jwt/mocks"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	storagemocks "github.com/lumiforge/sellerproof-backend/internal/storage/mocks"
	"github.com/lumiforge/sellerproof-backend/internal/video"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
	ydbmocks "github.com/lumiforge/sellerproof-backend/internal/ydb/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupTestRouter() (http.Handler, *ydbmocks.Database, *jwtmocks.TokenManager) {
	mockDB := new(ydbmocks.Database)
	mockStorage := new(storagemocks.StorageProvider)
	mockJWT := new(jwtmocks.TokenManager)

	realRBAC := rbac.NewRBAC()
	emailClient := email.NewClient(&config.Config{})
	cfg := &config.Config{APIBaseURL: "http://test.local"}

	authService := auth.NewService(mockDB, mockJWT, realRBAC, emailClient, cfg)
	videoService := video.NewService(mockDB, mockStorage, realRBAC, cfg.APIBaseURL)

	// Настраиваем мок для InsertAuditLog глобально для всех тестов, использующих этот роутер
	// Используем .Maybe(), чтобы тест не падал, если метод не вызван
	mockDB.On("InsertAuditLog", mock.Anything, mock.Anything).Return(nil).Maybe()

	auditService := audit.NewService(mockDB)

	realJWTForStruct := jwt.NewJWTManager(&config.Config{JWTSecretKey: "secret"})

	server := NewServer(authService, videoService, realJWTForStruct, auditService)
	router := SetupRouter(server, realJWTForStruct)

	return router, mockDB, mockJWT
}

func TestHandler_Register_InvalidJSON(t *testing.T) {
	router, _, _ := setupTestRouter()

	jsonBody := `{"email": "test@example.com", "password": "123"`
	req := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid request format")
}

func TestHandler_Register_InvalidContentType(t *testing.T) {
	router, _, _ := setupTestRouter()

	jsonBody := `{"email": "test@example.com", "password": "123"}`
	req := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	router, _, _ := setupTestRouter()

	req := httptest.NewRequest("GET", "/api/v1/auth/register", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandler_Register_UserExists_Mapping(t *testing.T) {
	router, mockDB, _ := setupTestRouter()

	reqBody := &models.RegisterRequest{
		Email:            "existing@example.com",
		Password:         "password123",
		FullName:         "Test User",
		OrganizationName: "Test Org",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	existingUser := &ydb.User{
		UserID:        "existing-id",
		Email:         "existing@example.com",
		EmailVerified: true,
	}

	// Настраиваем мок: пользователь найден
	mockDB.On("GetUserByEmail", mock.Anything, "existing@example.com").Return(existingUser, nil)

	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp models.RegisterResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "", resp.UserID)
	assert.Contains(t, resp.Message, "Registration successful. Please check your email for verification.")
}

func TestHandler_Register_UserExists_Unverified_Mapping(t *testing.T) {
	router, mockDB, _ := setupTestRouter()

	reqBody := &models.RegisterRequest{
		Email:            "unverified@example.com",
		Password:         "password123",
		FullName:         "Test User",
		OrganizationName: "Test Org",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	existingUser := &ydb.User{
		UserID:        "unverified-id",
		Email:         "unverified@example.com",
		EmailVerified: false,
	}

	// Настраиваем мок: пользователь найден но email не подтвержден
	mockDB.On("GetUserByEmail", mock.Anything, "unverified@example.com").Return(existingUser, nil)
	// Настраиваем мок для обновления пользователя
	mockDB.On("UpdateUser", mock.Anything, mock.AnythingOfType("*ydb.User")).Return(nil)

	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Проверяем, что хендлер возвращает 201 для существующего пользователя с неподтвержденным email
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp models.RegisterResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "unverified-id", resp.UserID)
	assert.Contains(t, resp.Message, "Registration successful. Please check your email for verification.")
}

func TestHandler_Register_ValidationError_Mapping(t *testing.T) {
	router, _, _ := setupTestRouter()

	reqBody := &models.RegisterRequest{
		Email:            "", // Empty email -> Validation Error
		Password:         "password123",
		FullName:         "Test User",
		OrganizationName: "Test Org",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "email is required")
}

func TestHandler_Register_InternalError_Mapping(t *testing.T) {
	router, mockDB, _ := setupTestRouter()

	reqBody := &models.RegisterRequest{
		Email:            "test@example.com",
		Password:         "password123",
		FullName:         "Test User",
		OrganizationName: "Test Org",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	// Имитируем падение БД
	mockDB.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, errors.New("db connection failed"))
	// Добавляем мок для GetPlanByID, который вызывается в сервисе
	mockDB.On("GetPlanByID", mock.Anything, "free").Return(&ydb.Plan{
		PlanID:          "free",
		Name:            "Free",
		StorageLimitMB:  1024, // 1GB
		VideoCountLimit: 10,
		PriceRub:        0,
		BillingCycle:    "monthly",
		Features:        "{}",
	}, nil)
	// Добавляем мок для RegisterUserTx, который вызывается в сервисе
	mockDB.On("RegisterUserTx", mock.Anything, mock.AnythingOfType("*ydb.User"), mock.AnythingOfType("*ydb.Organization"), mock.AnythingOfType("*ydb.Membership"), mock.AnythingOfType("*ydb.Subscription"), mock.AnythingOfType("string")).Return(errors.New("db connection failed"))

	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "registration failed")
}

func TestHandler_Login_ValidationError(t *testing.T) {
	router, _, _ := setupTestRouter()

	// Empty email and password
	reqBody := &models.LoginRequest{
		Email:    "",
		Password: "",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "email is required")
}

func TestMiddleware_MissingAuthHeader(t *testing.T) {
	router, _, _ := setupTestRouter()

	// Access protected route without header
	req := httptest.NewRequest("GET", "/api/v1/auth/profile", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header is required")
}

func TestMiddleware_InvalidToken(t *testing.T) {
	router, _, _ := setupTestRouter()

	// Access protected route with invalid token
	req := httptest.NewRequest("GET", "/api/v1/auth/profile", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.signature")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_InitiateMultipartUpload_Validation(t *testing.T) {
	router, mockDB, _ := setupTestRouter()

	// 1. Generate a valid token to bypass middleware
	// Note: setupTestRouter uses "secret" as the key for the real JWT manager used in middleware
	tokenMgr := jwt.NewJWTManager(&config.Config{JWTSecretKey: "secret"})
	token, _, _ := tokenMgr.GenerateTokenPair("user-1", "test@example.com", "user", "org-1")
	mockDB.On("GetUserByID", mock.Anything, "user-1").Return(&ydb.User{
		UserID:   "user-1",
		IsActive: true,
	}, nil)
	mockDB.On("GetMembership", mock.Anything, "user-1", "org-1").Return(&ydb.Membership{
		Status: "active",
	}, nil)
	// 2. Create request with invalid data (empty filename, negative size)
	reqBody := &models.InitiateMultipartUploadRequest{
		FileName:        "",
		FileSizeBytes:   -100,
		DurationSeconds: 0,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/video/upload/initiate", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// 3. Assert validation error
	assert.Equal(t, http.StatusBadRequest, w.Code)
	respBody := w.Body.String()
	assert.Contains(t, respBody, "file_name is required")
	assert.Contains(t, respBody, "file_size_bytes must be greater than 0")
}

func TestHandler_ForgotPassword_Success(t *testing.T) {
	router, mockDB, _ := setupTestRouter()

	reqBody := &models.ForgotPasswordRequest{Email: "test@example.com"}
	bodyBytes, _ := json.Marshal(reqBody)

	user := &ydb.User{UserID: "u1", Email: "test@example.com", IsActive: true}

	mockDB.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
	mockDB.On("UpdateUserPasswordResetInfo", mock.Anything, "u1", mock.Anything, mock.Anything).Return(nil)
	// InsertAuditLog is already mocked in setupTestRouter with .Maybe()

	req := httptest.NewRequest("POST", "/api/v1/auth/forgot-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "password reset code has been sent")
}

func TestHandler_ResetPassword_Success(t *testing.T) {
	router, mockDB, _ := setupTestRouter()

	code := "123456"
	expires := time.Now().Add(time.Hour)
	reqBody := &models.ResetPasswordRequest{
		Email:       "test@example.com",
		Code:        code,
		NewPassword: "newPass123",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	user := &ydb.User{UserID: "u1", Email: "test@example.com", PasswordResetCode: &code, PasswordResetExpiresAt: &expires}

	mockDB.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)
	mockDB.On("UpdateUserPassword", mock.Anything, "u1", mock.Anything).Return(nil)
	mockDB.On("RevokeAllUserRefreshTokens", mock.Anything, "u1").Return(nil)

	req := httptest.NewRequest("POST", "/api/v1/auth/reset-password", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Password has been reset successfully")
}

func TestHandler_GetUserOrganizations_Success(t *testing.T) {
	router, mockDB, _ := setupTestRouter()

	// 1. Generate a valid token to bypass middleware
	tokenMgr := jwt.NewJWTManager(&config.Config{JWTSecretKey: "secret"})
	token, _, _ := tokenMgr.GenerateTokenPair("user-1", "test@example.com", "user", "org-1")

	// Mock for AuthMiddleware session check
	mockDB.On("GetUserByID", mock.Anything, "user-1").Return(&ydb.User{
		UserID:   "user-1",
		IsActive: true,
	}, nil)
	mockDB.On("GetMembership", mock.Anything, "user-1", "org-1").Return(&ydb.Membership{
		Status: "active",
	}, nil)

	// Mock for GetUserOrganizations
	mockDB.On("GetMembershipsByUser", mock.Anything, "user-1").Return([]*ydb.Membership{}, nil)
	// GetOrganizationsByIDs won't be called if memberships is empty

	req := httptest.NewRequest("GET", "/api/v1/auth/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp models.GetUserOrganizationsResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Empty(t, resp.Organizations)
}

func TestHandler_DeleteOrganization_Success(t *testing.T) {
	router, mockDB, _ := setupTestRouter()

	// Generate token
	tokenMgr := jwt.NewJWTManager(&config.Config{JWTSecretKey: "secret"})
	token, _, _ := tokenMgr.GenerateTokenPair("user-1", "test@example.com", "admin", "org-1")

	// Mock AuthMiddleware session check
	mockDB.On("GetUserByID", mock.Anything, "user-1").Return(&ydb.User{UserID: "user-1", IsActive: true}, nil)
	mockDB.On("GetMembership", mock.Anything, "user-1", "org-1").Return(&ydb.Membership{Status: "active"}, nil)

	// Mock Service calls
	mockDB.On("GetOrganizationByID", mock.Anything, "org-1").Return(&ydb.Organization{OrgID: "org-1", OwnerID: "user-1"}, nil)
	mockDB.On("DeleteOrganizationTx", mock.Anything, "org-1").Return(nil)

	req := httptest.NewRequest("DELETE", "/api/v1/organization?org_id=org-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Organization deleted successfully")
}

func TestHandler_DeleteOrganization_Forbidden(t *testing.T) {
	router, mockDB, _ := setupTestRouter()

	tokenMgr := jwt.NewJWTManager(&config.Config{JWTSecretKey: "secret"})
	token, _, _ := tokenMgr.GenerateTokenPair("user-1", "test@example.com", "admin", "org-1")

	// Mock AuthMiddleware
	mockDB.On("GetUserByID", mock.Anything, "user-1").Return(&ydb.User{UserID: "user-1", IsActive: true}, nil)
	mockDB.On("GetMembership", mock.Anything, "user-1", "org-1").Return(&ydb.Membership{Status: "active"}, nil)

	// Mock Service calls
	mockDB.On("GetOrganizationByID", mock.Anything, "org-1").Return(&ydb.Organization{OrgID: "org-1", OwnerID: "other-owner"}, nil)

	req := httptest.NewRequest("DELETE", "/api/v1/organization?org_id=org-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "only organization owner can delete it")
}
