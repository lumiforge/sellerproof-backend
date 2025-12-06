package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/audit"
	"github.com/lumiforge/sellerproof-backend/internal/auth"
	app_errors "github.com/lumiforge/sellerproof-backend/internal/errors"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/validation"
	"github.com/lumiforge/sellerproof-backend/internal/video"
)

// Server represents HTTP server
type Server struct {
	authService  *auth.Service
	videoService *video.Service
	jwtManager   *jwt.JWTManager
	auditService *audit.Service
}

// NewServer creates a new HTTP server
func NewServer(authService *auth.Service, videoService *video.Service, jwtManager *jwt.JWTManager, auditService *audit.Service) *Server {
	return &Server{
		authService:  authService,
		videoService: videoService,
		jwtManager:   jwtManager,
		auditService: auditService,
	}
}

// writeJSON writes a JSON response
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response
func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, models.ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
		Code:    status,
	})
}

// validateRequest validates and decodes a request struct
func (s *Server) validateRequest(r *http.Request, req interface{}) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1048576) // 1MB limit
	return json.NewDecoder(r.Body).Decode(req)
}

// Auth Handlers

// Register handles user registration
// @Summary		Register a new user
// @Description	Register a new user with email, password, full name and optional organization name
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		models.RegisterRequest	true	"Registration request"
// @Success	201	{object}	models.RegisterResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	409	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/auth/register [post]
func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
	// Extract client info for audit logging
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("Register: Invalid Content-Type header", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.RegisterRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("Register: Invalid request format", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &models.RegisterRequest{
		Email:            req.Email,
		Password:         req.Password,
		FullName:         req.FullName,
		OrganizationName: req.OrganizationName,
	}

	resp, err := s.authService.Register(r.Context(), authReq)
	if err != nil {
		slog.Error("Register: Failed to register user", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		// Log failed registration attempt
		s.auditService.LogAction(r.Context(), "unknown", "", models.AuditRegisterSuccess, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"email":  req.Email,
			"reason": err.Error(),
		})

		// Проверяем тип ошибки и возвращаем соответствующий код
		errorMsg := err.Error()
		if errorMsg == "email already exists" {
			s.writeJSON(w, http.StatusCreated, models.RegisterResponse{
				UserID:  "",
				Message: "Registration successful. Please check your email for verification.",
			})
			return

		} else if strings.Contains(errorMsg, "invalid email format") ||
			strings.Contains(errorMsg, "must be at least") ||
			strings.Contains(errorMsg, "must be less than") ||
			strings.Contains(errorMsg, "is required") ||
			strings.Contains(errorMsg, "contains invalid characters") ||
			strings.Contains(errorMsg, "contains potentially dangerous") ||
			strings.Contains(errorMsg, "contains XSS") ||
			strings.Contains(errorMsg, "contains SQL injection") ||
			strings.Contains(errorMsg, "contains Unicode security") ||
			strings.Contains(errorMsg, "validation error in") ||
			strings.Contains(errorMsg, "failed to create user") ||
			strings.Contains(errorMsg, "failed to create organization") ||
			strings.Contains(errorMsg, "failed to marshal settings") {
			slog.Error("Register: Failed to register user", "error", errorMsg, "user_agent", userAgent, "ip_address", ipAddress)
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			slog.Error("Register: Failed to register user", "error", errorMsg, "user_agent", userAgent, "ip_address", ipAddress)
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	// Log successful registration
	s.auditService.LogAction(r.Context(), resp.UserID, "", models.AuditRegisterSuccess, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"email": req.Email,
	})

	s.writeJSON(w, http.StatusCreated, models.RegisterResponse{
		UserID:  resp.UserID,
		Message: resp.Message,
	})
}

// VerifyEmail handles email verification
// @Summary		Verify user email
// @Description	Verify user email with verification code sent to email
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		models.VerifyEmailRequest	true	"Email verification request"
// @Success	200		{object}	models.VerifyEmailResponse
// @Failure	400		{object}	models.ErrorResponse
// @Failure	500		{object}	models.ErrorResponse
// @Router		/auth/verify-email [post]
func (s *Server) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	// Extract client info for audit logging
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("VerifyEmail: Invalid Content-Type header", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.VerifyEmailRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("VerifyEmail: Invalid request format", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &models.VerifyEmailRequest{
		Email: req.Email,
		Code:  req.Code,
	}

	resp, err := s.authService.VerifyEmail(r.Context(), authReq)
	if err != nil {
		// Log failed verification attempt
		slog.Error("VerifyEmail: Failed to verify email", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.auditService.LogAction(r.Context(), "unknown", "", models.AuditEmailVerified, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"email":  req.Email,
			"reason": err.Error(),
		})

		errorMsg := err.Error()
		// Check if email is already verified
		if strings.Contains(errorMsg, "Email already verified") {
			s.writeJSON(w, http.StatusOK, models.VerifyEmailResponse{
				Message: resp.Message,
				Success: resp.Success,
			})
			return
		}
		slog.Error("VerifyEmail: Failed to verify email", "error", errorMsg, "user_agent", userAgent, "ip_address", ipAddress)
		if errorMsg == "invalid email format" ||
			strings.Contains(errorMsg, "invalid email format") ||
			strings.Contains(errorMsg, "user not found") ||
			strings.Contains(errorMsg, "verification code expired") ||
			strings.Contains(errorMsg, "validation error in") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else if strings.Contains(errorMsg, "invalid verification code") {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// Log successful verification
	s.auditService.LogAction(r.Context(), "unknown", "", models.AuditEmailVerified, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"email": req.Email,
	})

	s.writeJSON(w, http.StatusOK, models.VerifyEmailResponse{
		Message: resp.Message,
		Success: resp.Success,
	})
}

// Login handles user login
// @Summary		User login
// @Description	Authenticate user with email and password
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		models.LoginRequest	true	"Login request"
// @Success	200		{object}	models.LoginResponse
// @Failure	401		{object}	models.ErrorResponse
// @Failure	403		{object}	models.ErrorResponse
// @Failure	400		{object}	models.ErrorResponse
// @Router		/auth/login [post]
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	// Extract client info for audit logging
	// ipAddress := r.Header.Get("X-Forwarded-For")
	// if ipAddress == "" {
	// 	ipAddress = r.RemoteAddr
	// }
	// userAgent := r.Header.Get("User-Agent")

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("Login: Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.LoginRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("Login: Invalid request format", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &models.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := s.authService.Login(r.Context(), authReq)
	if err != nil {
		// We don't log failed login attempts, since it is not useful for the client
		// Log failed login attempt
		// s.auditService.LogAction(r.Context(), "unknown", "", models.AuditLoginFailure, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
		// 	"email":  req.Email,
		// 	"reason": err.Error(),
		// })

		// Проверяем тип ошибки и возвращаем соответствующий код
		errorMsg := err.Error()
		slog.Error("Login error", "error", errorMsg)
		if strings.Contains(strings.ToLower(errorMsg), "email not verified") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else if strings.Contains(errorMsg, "is required") ||
			strings.Contains(errorMsg, "invalid email format") ||
			strings.Contains(errorMsg, "must be less than") ||
			strings.Contains(errorMsg, "validation error in") ||
			strings.Contains(errorMsg, "invalid credentials") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			s.writeError(w, http.StatusUnauthorized, errorMsg)
		}
		return
	}

	// Log successful login
	// s.auditService.LogAction(r.Context(), resp.User.UserID, resp.User.OrgID, models.AuditLoginSuccess, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
	// 	"email": req.Email,
	// })

	userInfo := &models.UserInfo{
		UserID:        resp.User.UserID,
		Email:         resp.User.Email,
		FullName:      resp.User.FullName,
		Role:          resp.User.Role,
		OrgID:         resp.User.OrgID,
		EmailVerified: resp.User.EmailVerified,
		CreatedAt:     resp.User.CreatedAt,
		UpdatedAt:     resp.User.UpdatedAt,
	}

	s.writeJSON(w, http.StatusOK, models.LoginResponse{
		AccessToken:   resp.AccessToken,
		RefreshToken:  resp.RefreshToken,
		ExpiresAt:     resp.ExpiresAt,
		User:          userInfo,
		Organizations: resp.Organizations,
	})
}

// RefreshToken handles token refresh
// @Summary		Refresh access token
// @Description	Refresh access token using refresh token
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		models.RefreshTokenRequest	true	"Refresh token request"
// @Success	200		{object}	models.RefreshTokenResponse
// @Failure	401		{object}	models.ErrorResponse
// @Failure	400		{object}	models.ErrorResponse
// @Router		/auth/refresh [post]
func (s *Server) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("RefreshToken: Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.RefreshTokenRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("RefreshToken: Invalid request format", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// check if refresh token trailing spaces
	if strings.TrimSpace(req.RefreshToken) != req.RefreshToken {
		slog.Error("RefreshToken: Refresh token cannot contain trailing spaces")
		s.writeError(w, http.StatusBadRequest, "Refresh token cannot contain trailing spaces")
		return
	}

	if req.RefreshToken == "" {
		slog.Error("RefreshToken: Refresh token is required")
		s.writeError(w, http.StatusBadRequest, "Refresh token is required")
		return
	}
	authReq := &models.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := s.authService.RefreshToken(r.Context(), authReq)
	if err != nil {
		slog.Error("RefreshToken: Failed to refresh token", "error", err.Error())
		s.writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, models.RefreshTokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    resp.ExpiresAt,
	})
}

// Logout handles user logout
// @Summary		User logout
// @Description	Logout user and invalidate refresh token
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		models.LogoutRequest	true	"Logout request"
// @Security		BearerAuth
// @Success	200		{object}	models.LogoutResponse
// @Failure	401		{object}	models.ErrorResponse
// @Failure	400		{object}	models.ErrorResponse
// @Failure	500		{object}	models.ErrorResponse
// @Router		/auth/logout [post]
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	// Extract client info for audit logging
	// ipAddress := r.Header.Get("X-Forwarded-For")
	// if ipAddress == "" {
	// 	ipAddress = r.RemoteAddr
	// }
	// userAgent := r.Header.Get("User-Agent")

	// // Extract JWT claims
	// claims := r.Context().Value("claims").(*jwt.Claims)

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("Logout: Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.LogoutRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("Logout: Invalid request format", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// Check if refresh token is empty (could be due to wrong field name)
	if req.RefreshToken == "" {
		slog.Error("Logout: Refresh token is required")
		s.writeError(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	authReq := &models.LogoutRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := s.authService.Logout(r.Context(), authReq)
	if err != nil {
		errorMsg := err.Error()
		slog.Error("Logout: Failed to logout", "error", errorMsg)
		if strings.Contains(errorMsg, "refresh token not found") || strings.Contains(errorMsg, "refresh token expired") {
			s.writeError(w, http.StatusUnauthorized, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	// Log successful logout
	// if claims != nil {
	// 	s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditLogout, models.AuditResultSuccess, ipAddress, userAgent, nil)
	// }

	s.writeJSON(w, http.StatusOK, models.LogoutResponse{
		Message: resp.Message,
	})
}

// GetProfile handles getting user profile
// @Summary		Get user profile
// @Description	Get current user profile information
// @Tags		auth
// @Accept		json
// @Produce	json
// @Security		BearerAuth
// @Success	200	{object}	models.UserInfo
// @Failure	401	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/auth/profile [get]
func (s *Server) GetProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	resp, err := s.authService.GetProfile(r.Context(), claims.UserID, claims.OrgID)
	if err != nil {
		slog.Error("GetProfile: Failed to get profile", "error", err.Error())
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	userInfo := &models.UserInfo{
		UserID:        resp.User.UserID,
		Email:         resp.User.Email,
		FullName:      resp.User.FullName,
		Role:          resp.User.Role,
		OrgID:         resp.User.OrgID,
		EmailVerified: resp.User.EmailVerified,
		CreatedAt:     resp.User.CreatedAt,
		UpdatedAt:     resp.User.UpdatedAt,
	}

	s.writeJSON(w, http.StatusOK, userInfo)
}

// UpdateProfile handles updating user profile
// @Summary		Update user profile
// @Description	Update current user profile information
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		models.UpdateProfileRequest	true	"Profile update request"
// @Security		BearerAuth
// @Success	200	{object}	models.UserInfo
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/auth/profile [put]
func (s *Server) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("UpdateProfile: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("UpdateProfile: Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.UpdateProfileRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("UpdateProfile: Invalid request format", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.authService.UpdateProfile(r.Context(), claims.UserID, claims.OrgID, &req)
	if err != nil {
		// Проверяем тип ошибки и возвращаем соответствующий код
		errorMsg := err.Error()
		slog.Error("UpdateProfile: Failed to update profile", "error", errorMsg)
		if strings.Contains(errorMsg, "is required") ||
			strings.Contains(errorMsg, "must be at least") ||
			strings.Contains(errorMsg, "must be less than") ||
			strings.Contains(errorMsg, "contains invalid characters") ||
			strings.Contains(errorMsg, "contains potentially dangerous") ||
			strings.Contains(errorMsg, "contains XSS") ||
			strings.Contains(errorMsg, "validation error") ||
			strings.Contains(errorMsg, "contains SQL injection") ||
			strings.Contains(errorMsg, "contains Unicode security") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else if strings.Contains(errorMsg, "user not found") {
			s.writeError(w, http.StatusNotFound, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.writeJSON(w, http.StatusOK, resp.User)
}

// Video Handlers

// InitiateMultipartUpload handles initiating multipart upload
// @Summary		Initiate multipart upload
// @Description	Initiate multipart upload for video file
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		request	body		models.InitiateMultipartUploadRequest	true	"Multipart upload initiation request"
// @Security		BearerAuth
// @Success	200	{object}	models.InitiateMultipartUploadResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/upload/initiate [post]
func (s *Server) InitiateMultipartUpload(w http.ResponseWriter, r *http.Request) {
	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("InitiateMultipartUpload: Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("InitiateMultipartUpload: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Limit request body size to 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var req models.InitiateMultipartUploadRequest

	// Используем потоковый декодер вместо io.ReadAll + двойной Unmarshal
	dec := json.NewDecoder(r.Body)
	// Запретить неизвестные поля
	// dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		slog.Error("InitiateMultipartUpload: Invalid request format", "error", err.Error())
		// Обработка ошибок типов (например, строка вместо числа)
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			if typeErr.Value == "string" {
				if typeErr.Field == "file_size_bytes" {
					s.writeError(w, http.StatusBadRequest, "file_size_bytes must be a number, not a string")
					return
				}
				if typeErr.Field == "duration_seconds" {
					s.writeError(w, http.StatusBadRequest, "duration_seconds must be a number, not a string")
					return
				}
			}
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid type for field %s: expected %s, got %s", typeErr.Field, typeErr.Type, typeErr.Value))
			return
		}

		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// Manual validation of all required fields using validation package
	var validationErrors []string

	// Validate FileName using validation package
	if req.FileName == "" {
		slog.Error("InitiateMultipartUpload: file_name is required")
		validationErrors = append(validationErrors, "file_name is required")
	} else {
		// Use Unicode-friendly filename validation that includes homograph attack detection
		if err := validation.ValidateFilenameUnicode(req.FileName, "file_name"); err != nil {
			slog.Error("InitiateMultipartUpload: file_name is invalid", "error", err.Error())
			validationErrors = append(validationErrors, err.Error())
		}

		// Additional checks for SQL injection, XSS, and Unicode security attacks
		options := validation.CombineOptions(
			validation.WithSQLInjectionCheck(),
			validation.WithXSSCheck(),
			validation.WithUnicodeSecurityCheck(),
		)
		result := validation.ValidateInput(req.FileName, options)
		if !result.IsValid {
			for _, errMsg := range result.Errors {
				slog.Error("InitiateMultipartUpload: file_name is invalid", "error", errMsg)
				validationErrors = append(validationErrors, fmt.Sprintf("file_name: %s", errMsg))
			}
		}
	}

	// Validate FileSizeBytes
	if req.FileSizeBytes <= 0 {
		slog.Error("InitiateMultipartUpload: file_size_bytes must be greater than 0")
		validationErrors = append(validationErrors, "file_size_bytes must be greater than 0")
	}

	// Validate DurationSeconds
	if req.DurationSeconds <= 0 {
		slog.Error("InitiateMultipartUpload: duration_seconds must be greater than 0")
		validationErrors = append(validationErrors, "duration_seconds must be greater than 0")
	}

	// If there are validation errors, return them
	if len(validationErrors) > 0 {
		errorMessage := strings.Join(validationErrors, "; ")
		slog.Error("InitiateMultipartUpload: Validation error", "error", errorMessage)
		s.writeError(w, http.StatusBadRequest, "Validation error: "+errorMessage)
		return
	}

	title := req.Title
	if title == "" {
		title = req.FileName
	}

	resp, err := s.videoService.InitiateMultipartUploadDirect(r.Context(), claims.UserID, claims.OrgID, title, req.FileName, req.FileSizeBytes, req.DurationSeconds)
	if err != nil {
		slog.Error("InitiateMultipartUpload: Failed to initiate multipart upload", "error", err.Error())
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, models.InitiateMultipartUploadResponse{
		VideoID:               resp.VideoID,
		UploadID:              resp.UploadID,
		RecommendedPartSizeMB: resp.RecommendedPartSizeMB,
	})
}

// GetPartUploadURLs handles getting part upload URLs
// @Summary		Get part upload URLs
// @Description	Get presigned URLs for multipart upload parts
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		request	body		models.GetPartUploadURLsRequest	true	"Part upload URLs request"
// @Security		BearerAuth
// @Success	200	{object}	models.GetPartUploadURLsResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/upload/urls [post]
func (s *Server) GetPartUploadURLs(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {

		slog.Error("User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.GetPartUploadURLsRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("Invalid request format", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	if req.TotalParts < 1 {
		slog.Error("Invalid request format", "error", "minimum 1 part required")
		s.writeError(w, http.StatusBadRequest, "Invalid request format: minimum 1 part required")
		return
	} else if req.TotalParts > 100 {
		slog.Error("Invalid request format", "error", "maximum 100 parts allowed")
		s.writeError(w, http.StatusBadRequest, "Invalid request format: maximum 100 parts allowed")
		return
	} else if req.VideoID == "" {
		slog.Error("Invalid request format", "error", "video_id is required")
		s.writeError(w, http.StatusBadRequest, "Invalid request format: video_id is required")
		return
	}

	// Additional checks for SQL injection and XSS
	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(req.VideoID, options)
	if !result.IsValid {
		errorMessage := strings.Join(result.Errors, "; ")
		slog.Error("Invalid video_id", "error", errorMessage, "video_id", req.VideoID)
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	// Validate video_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
		slog.Error("Invalid video_id using Unicode-friendly validation", "error", err.Error(), "video_id", req.VideoID)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := uuid.Validate(req.VideoID); err != nil {
		slog.Error("Invalid video_id", "error", err.Error(), "video_id", req.VideoID)
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: must be a valid UUID")
		return
	}

	resp, err := s.videoService.GetPartUploadURLsDirect(r.Context(), claims.UserID, claims.OrgID, req.VideoID, req.TotalParts)
	if err != nil {
		// Check if the error is related to video not found
		errorMsg := err.Error()
		slog.Error("GetPartUploadURLs: Failed to get part upload URLs", "error", errorMsg, "video_id", req.VideoID)
		if strings.Contains(errorMsg, "video not found") {
			s.writeError(w, http.StatusNotFound, "Invalid video_id: video not found")
		} else if strings.Contains(errorMsg, "access denied") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusOK, models.GetPartUploadURLsResponse{
		PartURLs:  resp.PartURLs,
		ExpiresAt: resp.ExpiresAt,
	})
}

// CompleteMultipartUpload handles completing multipart upload
// @Summary		Complete multipart upload
// @Description	Complete multipart upload and create video record
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		request	body		models.CompleteMultipartUploadRequest	true	"Multipart upload completion request"
// @Security		BearerAuth
// @Success	200	{object}	models.CompleteMultipartUploadResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/upload/complete [post]
func (s *Server) CompleteMultipartUpload(w http.ResponseWriter, r *http.Request) {
	// Extract client info for audit logging
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("CompleteMultipartUpload: User not authenticated", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("CompleteMultipartUpload: Invalid Content-Type header", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.CompleteMultipartUploadRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("CompleteMultipartUpload: Invalid request format", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	if req.VideoID == "" {
		slog.Error("CompleteMultipartUpload: video_id is required", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "video_id is required")
		return
	}

	// Validate video_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
		slog.Error("CompleteMultipartUpload: video_id is invalid", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Additional checks for SQL injection and XSS
	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(req.VideoID, options)
	if !result.IsValid {
		slog.Error("CompleteMultipartUpload: video_id is invalid", "error", result.Errors, "user_agent", userAgent, "ip_address", ipAddress)
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	if len(req.Parts) == 0 {
		slog.Error("CompleteMultipartUpload: parts is required", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "parts is required")
		return
	}

	for i, p := range req.Parts {
		if p.PartNumber <= 0 {
			slog.Error("CompleteMultipartUpload: part_number at index %d must be greater than 0", "user_agent", userAgent, "ip_address", ipAddress)
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("part_number at index %d must be greater than 0", i))
			return
		}
		if p.ETag == "" {
			slog.Error("CompleteMultipartUpload: etag at index %d is required", "user_agent", userAgent, "ip_address", ipAddress)
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("etag at index %d is required", i))
			return
		}
	}

	// Convert parts to internal format
	parts := make([]video.CompletedPart, len(req.Parts))
	for i, p := range req.Parts {
		parts[i] = video.CompletedPart{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
		}
	}

	resp, err := s.videoService.CompleteMultipartUploadDirect(r.Context(), claims.UserID, claims.OrgID, req.VideoID, parts)
	if err != nil {
		slog.Error("CompleteMultipartUpload: Failed to complete multipart upload", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		// Log failed completion attempt
		s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoUploadComplete, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"video_id": req.VideoID,
			"parts":    len(req.Parts),
			"reason":   err.Error(),
		})

		if strings.Contains(err.Error(), "video not found") {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		} else if strings.Contains(err.Error(), "access denied") {
			s.writeError(w, http.StatusForbidden, err.Error())
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Log successful completion
	s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoUploadComplete, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"video_id":  req.VideoID,
		"parts":     len(req.Parts),
		"video_url": resp.VideoURL,
	})

	s.writeJSON(w, http.StatusOK, models.CompleteMultipartUploadResponse{
		Message:  resp.Message,
		VideoURL: resp.VideoURL,
	})
}

// GetVideo handles getting video information
// @Summary		Get video information
// @Description	Get video information by video ID
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		video_id	query		string	true	"Video ID"
// @Security		BearerAuth
// @Success	200	{object}	models.Video
// @Failure	401	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video [get]
func (s *Server) GetVideo(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("GetVideo: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	videoID := r.URL.Query().Get("video_id")
	if videoID == "" {
		slog.Error("GetVideo: video_id is required")
		s.writeError(w, http.StatusBadRequest, "video_id is required")
		return
	}

	// Validate video_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(videoID, "video_id"); err != nil {
		slog.Error("GetVideo: video_id is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Additional checks for SQL injection and XSS
	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(videoID, options)
	if !result.IsValid {
		slog.Error("GetVideo: video_id is invalid", "error", result.Errors)
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(videoID); err != nil {
		slog.Error("GetVideo: video_id is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: must be a valid UUID")
		return
	}

	resp, err := s.videoService.GetVideoDirect(r.Context(), claims.UserID, claims.OrgID, claims.Role, videoID)
	if err != nil {
		// Check error type and return appropriate HTTP status
		errorMsg := err.Error()
		slog.Error("GetVideo: Failed to get video", "error", errorMsg)
		if strings.Contains(errorMsg, "video not found") {
			s.writeError(w, http.StatusNotFound, errorMsg)
		} else if strings.Contains(errorMsg, "access denied") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	// Convert VideoInfo to our Video model
	videoResp := &models.Video{
		VideoID:         resp.VideoID,
		Title:           resp.Title,
		FileName:        resp.FileName,
		FileSizeBytes:   resp.FileSizeBytes,
		DurationSeconds: resp.DurationSeconds,
		UploadStatus:    resp.UploadStatus,
		UploadedAt:      resp.UploadedAt,
	}

	s.writeJSON(w, http.StatusOK, videoResp)
}

// SearchVideos handles searching videos
// @Summary		Search videos
// @Description	Search videos with query and pagination
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		query		query		string	false	"Search query"
// @Param		page		query		int		false	"Page number"	default(1)
// @Param		page_size	query		int		false	"Page size"	default(10)
// @Security		BearerAuth
// @Success	200	{object}	models.SearchVideosResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/search [get]
func (s *Server) SearchVideos(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("SearchVideos: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	query := r.URL.Query().Get("query")
	pageStr := r.URL.Query().Get("page")
	pageSizeStr := r.URL.Query().Get("page_size")

	page := int32(1)
	pageSize := int32(10)

	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil {
			page = int32(p)
		}
	}

	if pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil {
			pageSize = int32(ps)
			// Ограничиваем максимальный размер страницы
			if pageSize > 100 {
				pageSize = 100
			}
			if pageSize <= 0 {
				pageSize = 10
			}
		}
	}
	// Validate query parameter if provided (for Unicode support)
	if query != "" {
		// Additional checks for SQL injection and XSS on search query
		options := validation.CombineOptions(
			validation.WithSQLInjectionCheck(),
			validation.WithXSSCheck(),
		)
		result := validation.ValidateInput(query, options)
		if !result.IsValid {
			errorMessage := strings.Join(result.Errors, "; ")
			s.writeError(w, http.StatusBadRequest, "Invalid query: "+errorMessage)
			return
		}
	}

	resp, err := s.videoService.SearchVideosDirect(r.Context(), claims.UserID, claims.OrgID, claims.Role, query, page, pageSize)
	if err != nil {
		slog.Error("SearchVideos: Failed to search videos", "error", err.Error())
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Convert VideoInfo to our Video model
	videos := make([]*models.Video, len(resp.Videos))
	for i, v := range resp.Videos {
		videos[i] = &models.Video{
			VideoID:         v.VideoID,
			Title:           v.Title,
			FileName:        v.FileName,
			FileSizeBytes:   v.FileSizeBytes,
			DurationSeconds: v.DurationSeconds,
			UploadStatus:    v.UploadStatus,
			UploadedAt:      v.UploadedAt,
		}
	}

	s.writeJSON(w, http.StatusOK, models.SearchVideosResponse{
		Videos:     videos,
		TotalCount: resp.TotalCount,
	})
}

// GetPublicVideo handles getting public video (no authentication required)
// @Summary		Get public video
// @Description	Get public video by public token
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		token	query		string	true	"Public access token"
// @Success	200	{object}	models.PublicVideoResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	410	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/public [get]
func (s *Server) GetPublicVideo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract token from query parameter
	token := r.URL.Query().Get("token")
	if token == "" {
		slog.Error("GetPublicVideo: Missing or invalid token parameter")
		s.writeError(w, http.StatusBadRequest, "Missing or invalid token parameter")
		return
	}

	// Validate token format (base64 URL-safe, 43-44 characters for 32 bytes)
	if len(token) < 40 || len(token) > 50 {
		slog.Error("GetPublicVideo: Invalid token format")
		s.writeError(w, http.StatusBadRequest, "Invalid token format")
		return
	}

	// Validate token using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(token, "token"); err != nil {
		slog.Error("GetPublicVideo: token is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Additional checks for SQL injection and XSS
	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(token, options)
	if !result.IsValid {
		slog.Error("GetPublicVideo: token is invalid", "error", result.Errors)
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid token: "+errorMessage)
		return
	}

	// Get public video by token
	publicVideo, err := s.videoService.GetPublicVideo(ctx, token)
	if err != nil {
		errorMsg := err.Error()
		slog.Error("GetPublicVideo: Failed to get public video", "error", errorMsg, "token", token)
		if strings.Contains(errorMsg, "video not found") || strings.Contains(errorMsg, "token is invalid") {
			s.writeError(w, http.StatusNotFound, "Video not found or token is invalid")
			return
		}
		if strings.Contains(errorMsg, "public access revoked") {
			s.writeError(w, http.StatusGone, "Public access to this video has been revoked")
			return
		}
		slog.Error("Failed to get public video", "error", err, "token", token)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve video")
		return
	}

	s.writeJSON(w, http.StatusOK, publicVideo)
}

// Health handles health check (undocumented in Swagger)
func (s *Server) Health(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, models.HealthResponse{
		Status:    "ok",
		Version:   runtime.Version(),
		Timestamp: time.Now(),
	})
}

// SwitchOrganization handles organization switching
// @Summary		Switch organization
// @Description	Switch active organization for the current user and rotate tokens
// @Tags		auth
// @Accept		json
// @Produce		json
// @Param		request	body		models.SwitchOrganizationRequest	true	"Switch organization request"
// @Security	BearerAuth
// @Success	200		{object}	models.SwitchOrganizationResponse
// @Failure	400		{object}	models.ErrorResponse
// @Failure	401		{object}	models.ErrorResponse
// @Failure	500		{object}	models.ErrorResponse
// @Router		/auth/switch-organization [post]
func (s *Server) SwitchOrganization(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("SwitchOrganization: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("SwitchOrganization: Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.SwitchOrganizationRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("SwitchOrganization: Invalid request format", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// Validate org_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(req.OrgID, "org_id"); err != nil {
		slog.Error("SwitchOrganization: org_id is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.RefreshToken == "" {
		slog.Error("SwitchOrganization: refresh_token is required")
		s.writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	// Additional checks for SQL injection and XSS
	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(req.OrgID, options)
	if !result.IsValid {
		errorMessage := strings.Join(result.Errors, "; ")
		slog.Error("SwitchOrganization: org_id is invalid", "error", errorMessage)
		s.writeError(w, http.StatusBadRequest, "Invalid org_id: "+errorMessage)
		return
	}

	resp, err := s.authService.SwitchOrganization(r.Context(), claims.UserID, &req)
	if err != nil {
		// Проверяем тип ошибки и возвращаем соответствующий код
		errorMsg := err.Error()
		slog.Error("SwitchOrganization: Failed to switch organization", "error", errorMsg)
		if strings.Contains(errorMsg, "user is not a member") ||
			strings.Contains(errorMsg, "membership is not active") ||
			strings.Contains(errorMsg, "refresh token not found or revoked") ||
			strings.Contains(errorMsg, "user not found") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// CreateOrganization handles organization creation by admins
// @Summary	Create organization
// @Description	Create a new organization (admin only)
// @Tags	organization
// @Accept	json
// @Produce	json
// @Param	request	body	models.CreateOrganizationRequest	true	"Create organization request"
// @Security	BearerAuth
// @Success	201	{object}	models.CreateOrganizationResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	409	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/organization/create [post]
func (s *Server) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("CreateOrganization: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	if claims.Role != string(rbac.RoleAdmin) {
		slog.Error("CreateOrganization: Only admins can create organizations")
		s.writeError(w, http.StatusForbidden, "Only admins can create organizations")
		return
	}

	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("CreateOrganization: Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.CreateOrganizationRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("CreateOrganization: Invalid request format", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.authService.CreateOrganization(r.Context(), claims.UserID, &req)
	if err != nil {
		slog.Error("CreateOrganization: Failed to create organization", "error", err.Error())
		var validationErr validation.ValidationError

		switch {
		case strings.Contains(err.Error(), "only admins"):
			s.writeError(w, http.StatusForbidden, err.Error())
		case strings.Contains(err.Error(), "already exists"):
			s.writeError(w, http.StatusConflict, err.Error())
		case errors.As(err, &validationErr):
			s.writeError(w, http.StatusBadRequest, validationErr.Error())
		default:
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusCreated, resp)
}

// DownloadVideo handles private video download
// @Summary		Download private video
// @Description	Get temporary presigned URL for private video download (1 hour)
// @Tags		video
// @Accept		json
// @Produce	json
// @Security	BearerAuth
// @Param		video_id	query		string	true	"Video ID"
// @Success	200	{object}	models.DownloadURLResult
// @Failure	401	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/download [get]
func (s *Server) DownloadVideo(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {

		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("DownloadVideo: User not authenticated", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	videoID := r.URL.Query().Get("video_id")
	if videoID == "" {
		slog.Error("DownloadVideo: video_id is required", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "video_id is required")
		return
	}

	// Validate video_id using validation package
	if err := validation.ValidateFilenameUnicode(videoID, "video_id"); err != nil {
		slog.Error("DownloadVideo: video_id is invalid", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Additional checks for SQL injection and XSS
	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(videoID, options)
	if !result.IsValid {
		slog.Error("DownloadVideo: video_id is invalid", "error", result.Errors, "user_agent", userAgent, "ip_address", ipAddress)
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	resp, err := s.videoService.GetPrivateDownloadURL(r.Context(), claims.UserID, claims.OrgID, claims.Role, videoID)
	if err != nil {
		s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoDownloadPrivate, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"video_id": videoID,
			"reason":   err.Error(),
		})

		errorMsg := err.Error()
		slog.Error("DownloadVideo: Failed to get private download URL", "error", errorMsg, "video_id", videoID)

		if strings.Contains(errorMsg, "video not found") {
			s.writeError(w, http.StatusNotFound, errorMsg)
		} else if strings.Contains(errorMsg, "access denied") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoDownloadPrivate, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"video_id":     videoID,
		"download_url": resp.DownloadURL,
	})

	s.writeJSON(w, http.StatusOK, resp)
}

// DeleteVideo removes a video and records audit trail
// @Summary	Delete video
// @Description	Soft-delete a video belonging to current organization
// @Tags	video
// @Produce	json
// @Security	BearerAuth
// @Param	id	path	string	true	"Video ID"
// @Success	200	{object}	models.DeleteVideoResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/{id} [delete]
func (s *Server) DeleteVideo(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("DeleteVideo: User not authenticated", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Get ID from context (set by router)
	videoID, ok := r.Context().Value("path_id").(string)
	if !ok {
		videoID = r.PathValue("id") // fallback for compatibility
	}

	if err := validation.ValidateFilenameUnicode(videoID, "video_id"); err != nil {
		slog.Error("DeleteVideo: video_id is invalid", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(videoID, options)
	if !result.IsValid {
		errorMessage := strings.Join(result.Errors, "; ")
		slog.Error("DeleteVideo: video_id is invalid", "error", errorMessage, "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	resp, err := s.videoService.DeleteVideoDirect(r.Context(), claims.UserID, claims.OrgID, claims.Role, videoID)
	if err != nil {
		s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoDelete, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"video_id": videoID,
			"error":    err.Error(),
		})

		errorMsg := err.Error()
		slog.Error("DeleteVideo: Failed to delete video", "error", errorMsg, "user_agent", userAgent, "ip_address", ipAddress)
		switch {
		case strings.Contains(errorMsg, "video not found"):
			s.writeError(w, http.StatusNotFound, errorMsg)
		case strings.Contains(errorMsg, "access denied"):
			s.writeError(w, http.StatusForbidden, errorMsg)
		default:
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoDelete, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"video_id": videoID,
	})

	s.writeJSON(w, http.StatusOK, resp)
}

// Organization and Membership Handlers

// InviteUser handles user invitation to organization
// @Summary		Invite user to organization
// @Description	Invite user to organization with specific role (admin/manager only)
// @Tags		organization
// @Accept		json
// @Produce	json
// @Param		request	body		models.InviteUserRequest	true	"Invite user request"
// @Security	BearerAuth
// @Success	200	{object}	models.InviteUserResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	409	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/organization/invite [post]
func (s *Server) InviteUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("InviteUser: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("InviteUser: Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.InviteUserRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("InviteUser: Invalid request format", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	if req.OrgID == "" {
		slog.Error("InviteUser: org_id is required")
		s.writeError(w, http.StatusBadRequest, "org_id is required")
		return
	}

	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	resp, err := s.authService.InviteUser(r.Context(), claims.UserID, req.OrgID, &req)
	if err != nil {

		// Check if it's a validation error and return 400 instead of 500
		var valErr validation.ValidationError
		if errors.As(err, &valErr) {
			slog.Error("InviteUser: Validation error", "error", valErr.Error(), "user_agent", userAgent, "ip_address", ipAddress)
			s.writeError(w, http.StatusBadRequest, valErr.Message)
			return
		}
		s.auditService.LogAction(r.Context(), claims.UserID, req.OrgID, models.AuditOrgUserInvite, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"email": req.Email,
			"role":  req.Role,
			"error": err.Error(),
		})

		errorMsg := err.Error()
		slog.Error("InviteUser: Failed to invite user", "error", errorMsg, "user_agent", userAgent, "ip_address", ipAddress)
		if errors.Is(err, app_errors.ErrOrgCanHaveOnlyOneAdmin) {
			s.writeError(w, http.StatusConflict, err.Error())
			return
		} else if strings.Contains(errorMsg, "already a member") || strings.Contains(errorMsg, "already invited") {
			s.writeError(w, http.StatusConflict, errorMsg)
			return
		} else if strings.Contains(errorMsg, "only admins and managers") || strings.Contains(errorMsg, "inviter is not a member of this organization") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else if strings.Contains(errorMsg, "invalid") || strings.Contains(errorMsg, "required") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.auditService.LogAction(r.Context(), claims.UserID, req.OrgID, models.AuditOrgUserInvite, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"email":     req.Email,
		"role":      req.Role,
		"invite_id": resp.InvitationID,
	})

	s.writeJSON(w, http.StatusOK, resp)
}

// AcceptInvitation handles accepting invitation to organization
// @Summary		Accept invitation
// @Description	Accept invitation to organization using invite code
// @Tags		organization
// @Accept		json
// @Produce	json
// @Param		request	body		models.AcceptInvitationRequest	true	"Accept invitation request"
// @Security	BearerAuth
// @Success	200	{object}	models.AcceptInvitationResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/organization/invitations/accept [post]
func (s *Server) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("AcceptInvitation: User not authenticated", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("AcceptInvitation: Invalid Content-Type header", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.AcceptInvitationRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("AcceptInvitation: Invalid request format", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.authService.AcceptInvitation(r.Context(), claims.UserID, &req)
	if err != nil {
		s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditOrgInvitationAccepted, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"invite_code": req.InviteCode,
			"error":       err.Error(),
		})

		errorMsg := err.Error()
		slog.Error("AcceptInvitation: Failed to accept invitation", "error", errorMsg, "user_agent", userAgent, "ip_address", ipAddress)

		if strings.Contains(errorMsg, "invalid") || strings.Contains(errorMsg, "expired") || strings.Contains(errorMsg, "not pending") || strings.Contains(errorMsg, "is required") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.auditService.LogAction(r.Context(), claims.UserID, resp.OrgID, models.AuditOrgInvitationAccepted, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"invite_code": req.InviteCode,
		"org_id":      resp.OrgID,
		"role":        resp.Role,
	})

	s.writeJSON(w, http.StatusOK, resp)
}

// ListInvitations handles listing invitations for organization
// @Summary		List invitations
// @Description	List all invitations for organization (admin/manager only)
// @Tags		organization
// @Produce	json
// @Param		org_id	query		string	true	"Organization ID"
// @Security	BearerAuth
// @Success	200	{object}	models.ListInvitationsResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/organization/invitations [get]
func (s *Server) ListInvitations(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("ListInvitations: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		slog.Error("ListInvitations: org_id is required")
		s.writeError(w, http.StatusBadRequest, "org_id is required")
		return
	}

	// Validate org_id
	if err := validation.ValidateFilenameUnicode(orgID, "org_id"); err != nil {
		slog.Error("ListInvitations: org_id is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// IDOR check
	if claims.OrgID != orgID {
		slog.Error("ListInvitations: Access denied: you are not a member of this organization")
		s.writeError(w, http.StatusForbidden, "Access denied: you are not a member of this organization")
		return
	}

	// RBAC check
	if claims.Role != string(rbac.RoleAdmin) && claims.Role != string(rbac.RoleManager) {
		slog.Error("ListInvitations: Only admins and managers can list invitations")
		s.writeError(w, http.StatusForbidden, "Only admins and managers can list invitations")
		return
	}

	invitations, err := s.authService.ListInvitations(r.Context(), orgID)
	if err != nil {
		slog.Error("ListInvitations: Failed to list invitations", "error", err.Error())
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, models.ListInvitationsResponse{
		Invitations: invitations,
		Total:       len(invitations),
	})
}

// CancelInvitation handles canceling invitation
// @Summary		Cancel invitation
// @Description	Cancel pending invitation (admin/manager only)
// @Tags		organization
// @Produce	json
// @Param		invitation_id	path		string	true	"Invitation ID"
// @Security	BearerAuth
// @Success	200	{object}	map[string]string
// @Failure	401	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/organization/invitations/{invitation_id} [delete]
func (s *Server) CancelInvitation(w http.ResponseWriter, r *http.Request) {

	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("CancelInvitation: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Get ID from context (set by router)
	invitationID, ok := r.Context().Value("path_id").(string)
	if !ok {
		invitationID = r.PathValue("id") // fallback for compatibility
	}

	if invitationID == "" {
		slog.Error("CancelInvitation: invitation_id is required")
		s.writeError(w, http.StatusBadRequest, "invitation_id is required")
		return
	}
	if err := uuid.Validate(invitationID); err != nil {
		slog.Error("CancelInvitation: invitation_id is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid invitation_id: must be a valid UUID")
		return
	}

	// Validate invitation_id format (UUID expected)
	if err := validation.ValidateFilenameUnicode(invitationID, "invitation_id"); err != nil {
		slog.Error("CancelInvitation: invitation_id is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Additional security checks
	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(invitationID, options)
	if !result.IsValid {
		slog.Error("CancelInvitation: invitation_id is invalid", "error", result.Errors)
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid invitation_id: "+errorMessage)
		return
	}

	// Check admin/manager role
	if claims.Role != "admin" && claims.Role != "manager" {
		slog.Error("CancelInvitation: Only admins and managers can cancel invitations")
		s.writeError(w, http.StatusForbidden, "Only admins and managers can cancel invitations")
		return
	}

	err := s.authService.CancelInvitation(r.Context(), invitationID)
	if err != nil {
		// Log failed cancellation

		errorMsg := err.Error()
		slog.Error("CancelInvitation: Failed to cancel invitation", "error", errorMsg)
		if strings.Contains(errorMsg, "not found") {
			s.writeError(w, http.StatusNotFound, errorMsg)
		} else if strings.Contains(errorMsg, "only pending") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"message": "Invitation cancelled successfully"})
}

// ListMembers handles listing organization members
// @Summary		List organization members
// @Description	List all members of organization (admin only)
// @Tags		organization
// @Produce	json
// @Param		org_id	query		string	true	"Organization ID"
// @Security	BearerAuth
// @Success	200	{object}	models.ListMembersResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/organization/members [get]
func (s *Server) ListMembers(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("ListMembers: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		slog.Error("ListMembers: org_id is required")
		s.writeError(w, http.StatusBadRequest, "org_id is required")
		return
	}
	// IDOR check
	if claims.OrgID != orgID {
		slog.Error("ListMembers: Access denied: you are not a member of this organization")
		s.writeError(w, http.StatusForbidden, "Access denied: you are not a member of this organization")
		return
	}

	// Check admin role
	if claims.Role != "admin" {
		slog.Error("ListMembers: Only admins can list members")
		s.writeError(w, http.StatusForbidden, "Only admins can list members")
		return
	}

	members, err := s.authService.ListOrgMembers(r.Context(), orgID)
	if err != nil {
		slog.Error("ListMembers: Failed to list members", "error", err.Error())
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, models.ListMembersResponse{
		Members: members,
		Total:   len(members),
	})
}

// UpdateMemberRole handles updating member role
// @Summary		Update member role
// @Description	Update organization member role (admin only)
// @Tags		organization
// @Accept		json
// @Produce	json
// @Param		user_id	path		string	true	"User ID"
// @Param		request	body		models.UpdateMemberRoleRequest	true	"Update member role request"
// @Security	BearerAuth
// @Success	200	{object}	map[string]string
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/organization/members/{user_id}/role [put]
func (s *Server) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {

		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("UpdateMemberRole: User not authenticated", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Check admin role
	if claims.Role != "admin" {
		slog.Error("UpdateMemberRole: Only admins can update member roles", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusForbidden, "Only admins can update member roles")
		return
	}

	// TODO: remove this after testing
	log.Println("UpdateMemberRole: org_id", claims.OrgID, "user_id", claims.UserID)
	// Get user_id from context (set by router)
	userID, ok := r.Context().Value("path_user_id").(string)
	if !ok {
		userID = r.PathValue("user_id") // fallback for compatibility
	}

	if userID == "" {
		slog.Error("UpdateMemberRole: user_id is required", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	// Validate Content-Type header
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("UpdateMemberRole: Invalid Content-Type header", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.UpdateMemberRoleRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("UpdateMemberRole: Invalid request format", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	err := s.authService.UpdateMemberRole(r.Context(), claims.UserID, claims.OrgID, userID, req.NewRole)
	if err != nil {
		s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditOrgRoleChanged, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"target_user_id": userID,
			"new_role":       req.NewRole,
			"error":          err.Error(),
		})

		errorMsg := err.Error()
		slog.Error("UpdateMemberRole: Failed to update member role", "error", errorMsg, "user_agent", userAgent, "ip_address", ipAddress)
		if strings.Contains(errorMsg, "only admins") || strings.Contains(errorMsg, "not a member") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else if strings.Contains(errorMsg, "invalid") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditOrgRoleChanged, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"target_user_id": userID,
		"new_role":       req.NewRole,
	})

	s.writeJSON(w, http.StatusOK, map[string]string{"message": "Member role updated successfully"})
}

// UpdateMemberStatus handles updating member status (block/unblock)
// @Summary		Update member status
// @Description	Update organization member status (active/suspended)
// @Tags		organization
// @Accept		json
// @Produce	json
// @Param		user_id	path		string	true	"User ID"
// @Param		request	body		models.UpdateMemberStatusRequest	true	"Update member status request"
// @Security	BearerAuth
// @Success	200	{object}	map[string]string
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/organization/members/{user_id}/status [put]
func (s *Server) UpdateMemberStatus(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("UpdateMemberStatus: User not authenticated", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Get user_id from context (set by router)
	userID, ok := r.Context().Value("path_user_id").(string)
	if !ok {
		userID = r.PathValue("user_id") // fallback for compatibility
	}

	if userID == "" {
		slog.Error("UpdateMemberStatus: user_id is required", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	var req models.UpdateMemberStatusRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("UpdateMemberStatus: Invalid request format", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// TODO: remove this after testing
	log.Println("UpdateMemberStatus: org_id", claims.OrgID, "admin_user_id", claims.UserID, "target_user_id", userID)
	err := s.authService.UpdateMemberStatus(r.Context(), claims.UserID, claims.OrgID, userID, req.Status)
	if err != nil {
		errorMsg := err.Error()
		slog.Error("UpdateMemberStatus: Failed to update member status", "error", errorMsg, "user_agent", userAgent, "ip_address", ipAddress)
		if strings.Contains(errorMsg, "managers cannot manage admins or other managers") || strings.Contains(errorMsg, "insufficient permissions") {
			s.writeError(w, http.StatusForbidden, err.Error())
		} else {
			s.writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditOrgMemberStatusChanged, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"target_user_id": userID,
		"new_status":     req.Status,
	})

	s.writeJSON(w, http.StatusOK, map[string]string{"message": "Member status updated successfully"})
}

// RemoveMember handles removing member from organization
// @Summary		Remove member
// @Description	Remove member from organization (admin only)
// @Tags		organization
// @Produce	json
// @Param		org_id	query		string	true	"Organization ID"
// @Param		user_id	path		string	true	"User ID"
// @Security	BearerAuth
// @Success	200	{object}	map[string]string
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/organization/members/{user_id} [delete]
func (s *Server) RemoveMember(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("RemoveMember: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		slog.Error("RemoveMember: org_id is required")
		s.writeError(w, http.StatusBadRequest, "org_id is required")
		return
	}

	if err := validation.ValidateFilenameUnicode(orgID, "org_id"); err != nil {
		slog.Error("RemoveMember: org_id is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// IDOR check
	if claims.OrgID != orgID && claims.Role != "admin" {
		if claims.OrgID != orgID {
			slog.Error("RemoveMember: Access denied: you are not a member of this organization")
			s.writeError(w, http.StatusForbidden, "Access denied: you are not a member of this organization")
			return
		}
	}

	if claims.OrgID != orgID && claims.Role != "admin" {
		// Примечание: если claims.Role == "admin", он админ только в claims.OrgID.
		// Поэтому строгая проверка:
		if claims.OrgID != orgID {
			slog.Error("RemoveMember: Access denied: you are not a member of this organization")
			s.writeError(w, http.StatusForbidden, "Access denied: you are not a member of this organization")
			return
		}
	}

	// Check admin role
	if claims.Role != "admin" {
		slog.Error("RemoveMember: Only admins can remove members")
		s.writeError(w, http.StatusForbidden, "Only admins can remove members")
		return
	}

	// Get user_id from context (set by router)
	userID, ok := r.Context().Value("path_user_id").(string)
	if !ok {
		userID = r.PathValue("user_id") // fallback for compatibility
	}
	if userID == "" {
		slog.Error("RemoveMember: user_id is required")
		s.writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	err := s.authService.RemoveMember(r.Context(), claims.UserID, claims.OrgID, userID)
	if err != nil {
		errorMsg := err.Error()
		slog.Error("RemoveMember: Failed to remove member", "error", errorMsg)
		if strings.Contains(errorMsg, "cannot remove") || strings.Contains(errorMsg, "only admins") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else if strings.Contains(errorMsg, "not a member") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"message": "Member removed successfully"})
}

// PublishVideo handles video publishing to public bucket
// @Summary		Publish video
// @Description	Publish video to public bucket (admin/manager only)
// @Tags		video
// @Accept		json
// @Produce	json
// @Security	BearerAuth
// @Param		request	body		models.PublishVideoRequest	true	"Publish video request"
// @Success	200	{object}	models.PublishVideoResult
// @Failure	401	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	415	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/publish [post]
func (s *Server) PublishVideo(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("PublishVideo: User not authenticated")
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Проверка прав (только admin/manager)
	if claims.Role != "admin" && claims.Role != "manager" {
		slog.Error("PublishVideo: Only admins and managers can publish videos")
		s.writeError(w, http.StatusForbidden, "Only admins and managers can publish videos")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("PublishVideo: Invalid Content-Type header", "error", err.Error())
		s.writeError(w, http.StatusUnsupportedMediaType, err.Error())
		return
	}

	var req models.PublishVideoRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("PublishVideo: Invalid request format", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}
	if req.VideoID == "" {
		slog.Error("PublishVideo: Missing required field: video_id")
		s.writeError(w, http.StatusBadRequest, "Missing required field: video_id")
		return
	}
	if _, err := uuid.Parse(req.VideoID); err != nil {
		slog.Error("PublishVideo: video_id is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: must be a valid UUID")
		return
	}

	// Validate video_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
		slog.Error("PublishVideo: video_id is invalid", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Additional checks for SQL injection and XSS
	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(req.VideoID, options)
	if !result.IsValid {
		slog.Error("PublishVideo: video_id is invalid", "error", result.Errors)
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	resp, err := s.videoService.PublishVideo(r.Context(), claims.UserID, claims.OrgID, claims.Role, req.VideoID)
	if err != nil {

		errorMsg := err.Error()
		slog.Error("PublishVideo: Failed to publish video", "error", errorMsg)
		if strings.Contains(errorMsg, "video not found") {
			s.writeError(w, http.StatusNotFound, errorMsg)
		} else if strings.Contains(errorMsg, "access denied") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// RevokeVideo handles revoking public access to a video
// @Summary		Revoke video publication
// @Description	Move video from public bucket back to private (admin/manager only)
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		request	body		models.RevokeVideoRequest	true	"Revoke video request"
// @Security		BearerAuth
// @Success	200	{object}	models.RevokeVideoResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/revoke [post]
func (s *Server) RevokeVideo(w http.ResponseWriter, r *http.Request) {
	// Extract client info for audit logging
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("RevokeVideo: User not authenticated", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		slog.Error("RevokeVideo: Invalid Content-Type header", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.RevokeVideoRequest
	if err := s.validateRequest(r, &req); err != nil {
		slog.Error("RevokeVideo: Invalid request format", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	if req.VideoID == "" {
		slog.Error("RevokeVideo: video_id is required", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "video_id is required")
		return
	}

	// Validate video_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
		slog.Error("RevokeVideo: video_id is invalid", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Additional checks for SQL injection and XSS
	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(req.VideoID, options)
	if !result.IsValid {
		slog.Error("RevokeVideo: video_id is invalid", "error", result.Errors, "user_agent", userAgent, "ip_address", ipAddress)
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(req.VideoID); err != nil {
		slog.Error("RevokeVideo: video_id is invalid", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: must be a valid UUID")
		return
	}

	// Check permissions (admin or manager only)
	if claims.Role != "admin" && claims.Role != "manager" {
		slog.Error("RevokeVideo: Only admins and managers can revoke video access", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusForbidden, "Only admins and managers can revoke video access")
		return
	}

	// Check if video is published by getting it from the database directly
	// We need to access the database layer to get the full video info including publish status
	dbVideo, err := s.videoService.GetVideoForRevocation(r.Context(), claims.UserID, claims.OrgID, req.VideoID)
	if err != nil {
		slog.Error("RevokeVideo: Failed to get video for revocation", "error", err.Error(), "user_agent", userAgent, "ip_address", ipAddress)
		if strings.Contains(err.Error(), "video not found") {
			s.writeError(w, http.StatusNotFound, "Video not found")
			return
		} else if strings.Contains(err.Error(), "access denied") {
			s.writeError(w, http.StatusForbidden, "Access denied")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to get video")
		return
	}

	if dbVideo.PublishStatus != "published" {
		slog.Error("RevokeVideo: Video is not published", "user_agent", userAgent, "ip_address", ipAddress)
		s.writeError(w, http.StatusBadRequest, "Video is not published")
		return
	}

	// Revoke public access
	err = s.videoService.RevokePublicShare(r.Context(), claims.UserID, claims.OrgID, claims.Role, req.VideoID)
	if err != nil {

		s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoRevoked, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"video_id": req.VideoID,
			"reason":   err.Error(),
		})

		errorMsg := err.Error()
		slog.Error("RevokeVideo: Failed to revoke video", "error", errorMsg, "user_agent", userAgent, "ip_address", ipAddress)
		if strings.Contains(errorMsg, "video not found") {
			s.writeError(w, http.StatusNotFound, errorMsg)
		} else if strings.Contains(errorMsg, "access denied") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	// Log successful revocation
	s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoRevoked, models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{
		"video_id": req.VideoID,
	})

	s.writeJSON(w, http.StatusOK, models.RevokeVideoResponse{
		Message: "Video access revoked successfully",
		VideoID: req.VideoID,
		Status:  "private",
	})
}

// GetAuditLogs retrieves audit logs with filtering and pagination
// @Summary Get audit logs
// @Description Retrieve audit logs with optional filtering by user_id, org_id, action_type, result, and date range
// @Tags admin
// @Security BearerAuth
// @Param user_id query string false "Filter by user ID"
// @Param org_id query string false "Filter by organization ID"
// @Param action_type query string false "Filter by action type"
// @Param result query string false "Filter by result (success/failure)"
// @Param from query string false "Filter from date (YYYY-MM-DD)"
// @Param to query string false "Filter to date (YYYY-MM-DD)"
// @Param limit query int false "Limit results (default 100, max 1000)"
// @Param offset query int false "Offset for pagination (default 0)"
// @Produce json
// @Success 200 {object} models.GetAuditLogsResponse "Audit logs retrieved successfully"
// @Failure 400 {object} models.ErrorResponse "Bad request - invalid parameters"
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /admin/audit-logs [get]
func (s *Server) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	// Extract JWT claims
	claims, ok := GetUserClaims(r)
	if !ok {
		slog.Error("GetAuditLogs: Unauthorized")
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Check permission
	rbacManager := rbac.NewRBAC()
	hasPermission := rbacManager.CheckPermissionWithRole(rbac.Role(claims.Role), rbac.PermissionAdminViewLogs)
	if !hasPermission {
		slog.Error("GetAuditLogs: Insufficient permissions to access audit logs")
		s.writeError(w, http.StatusForbidden, "Insufficient permissions to access audit logs")
		return
	} // Parse query parameters
	userID := r.URL.Query().Get("user_id")
	// orgID := r.URL.Query().Get("org_id")
	actionType := r.URL.Query().Get("action_type")
	result := r.URL.Query().Get("result")
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")

	// Parse limit and offset
	limit := 1000
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			if l > 0 && l <= 1000 {
				limit = l
			}
		}
	}

	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			// Limit offset to prevent DoS via deep pagination
			if o > 10000 {
				s.writeError(w, http.StatusBadRequest, "offset cannot exceed 10000. Please use date filters to narrow down results.")
				return
			}
			offset = o
		}
	}

	// Build filters map
	filters := make(map[string]interface{})

	// IDOR
	filters["org_id"] = claims.OrgID

	if userID != "" {
		filters["user_id"] = userID
	}

	if actionType != "" {
		filters["action_type"] = actionType
	}
	if result != "" {
		filters["result"] = result
	}
	if from != "" {
		filters["from"] = from
	}
	if to != "" {
		filters["to"] = to
	}

	// Get audit logs from service
	logs, total, err := s.auditService.GetLogs(r.Context(), filters, limit, offset)
	if err != nil {
		slog.Error("Failed to retrieve audit logs", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve audit logs")
		return
	}

	// Return response
	response := &models.GetAuditLogsResponse{
		Logs:   logs,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// ForgotPassword handles password reset request
// @Summary		Request password reset
// @Description	Initiate password reset process by sending a code to email
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		models.ForgotPasswordRequest	true	"Forgot password request"
// @Success	200		{object}	models.ForgotPasswordResponse
// @Failure	400		{object}	models.ErrorResponse
// @Failure	500		{object}	models.ErrorResponse
// @Router		/auth/forgot-password [post]
func (s *Server) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.ForgotPasswordRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.authService.RequestPasswordReset(r.Context(), &req)
	if err != nil {
		slog.Error("ForgotPassword: Failed to request reset", "error", err.Error())
		var valErr validation.ValidationError
		if errors.As(err, &valErr) || strings.Contains(err.Error(), "invalid email") {
			s.writeError(w, http.StatusBadRequest, err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, "Failed to process request")
		}
		return
	}

	s.auditService.LogAction(r.Context(), "unknown", "", "password_reset_request", models.AuditResultSuccess, ipAddress, userAgent, map[string]interface{}{"email": req.Email})
	s.writeJSON(w, http.StatusOK, resp)
}

// ResetPassword handles password reset confirmation
// @Summary		Reset password
// @Description	Reset password using verification code
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		models.ResetPasswordRequest	true	"Reset password request"
// @Success	200		{object}	models.ResetPasswordResponse
// @Failure	400		{object}	models.ErrorResponse
// @Failure	500		{object}	models.ErrorResponse
// @Router		/auth/reset-password [post]
func (s *Server) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.ResetPasswordRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.authService.ResetPassword(r.Context(), &req)
	if err != nil {
		slog.Error("ResetPassword: Failed to reset password", "error", err.Error())
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// GetUserOrganizations handles getting user organizations
// @Summary		Get user organizations
// @Description	Get list of organizations the user belongs to
// @Tags		auth
// @Accept		json
// @Produce		json
// @Security	BearerAuth
// @Success	200		{object}	models.GetUserOrganizationsResponse
// @Failure	401		{object}	models.ErrorResponse
// @Failure	500		{object}	models.ErrorResponse
// @Router		/auth/organizations [get]
func (s *Server) GetUserOrganizations(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	resp, err := s.authService.GetUserOrganizations(r.Context(), claims.UserID)
	if err != nil {
		slog.Error("GetUserOrganizations: Failed to get organizations", "error", err.Error())
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, resp)
}
