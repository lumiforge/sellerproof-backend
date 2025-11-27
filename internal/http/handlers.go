package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lumiforge/sellerproof-backend/internal/audit"
	"github.com/lumiforge/sellerproof-backend/internal/auth"
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
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.RegisterRequest
	if err := s.validateRequest(r, &req); err != nil {
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
		// Log failed registration attempt
		s.auditService.LogAction(r.Context(), "unknown", "", models.AuditRegisterSuccess, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"email":  req.Email,
			"reason": err.Error(),
		})

		// Проверяем тип ошибки и возвращаем соответствующий код
		errorMsg := err.Error()
		if errorMsg == "email already exists" {
			s.writeError(w, http.StatusConflict, errorMsg)
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
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
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
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.VerifyEmailRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &models.VerifyEmailRequest{
		Email: req.Email,
		Code:  req.Code,
	}

	resp, err := s.authService.VerifyEmail(r.Context(), authReq)
	// Заменить текущую обработку ошибки на:
	if err != nil {
		// Log failed verification attempt
		s.auditService.LogAction(r.Context(), "unknown", "", models.AuditEmailVerified, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"email":  req.Email,
			"reason": err.Error(),
		})

		errorMsg := err.Error()
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
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.LoginRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &models.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := s.authService.Login(r.Context(), authReq)
	if err != nil {
		// Log failed login attempt
		// s.auditService.LogAction(r.Context(), "unknown", "", models.AuditLoginFailure, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
		// 	"email":  req.Email,
		// 	"reason": err.Error(),
		// })

		// Проверяем тип ошибки и возвращаем соответствующий код
		errorMsg := err.Error()
		slog.Error("Login error", "error", errorMsg) // Добавляем логирование для отладки
		if strings.Contains(errorMsg, "is required") ||
			strings.Contains(errorMsg, "invalid email format") ||
			strings.Contains(errorMsg, "must be less than") ||
			strings.Contains(errorMsg, "validation error in") ||
			strings.Contains(errorMsg, "invalid credentials") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else if strings.Contains(strings.ToLower(errorMsg), "email not verified") {
			s.writeError(w, http.StatusForbidden, errorMsg)
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
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.RefreshTokenRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// check if refresh token trailing spaces
	if strings.TrimSpace(req.RefreshToken) != req.RefreshToken {
		s.writeError(w, http.StatusBadRequest, "Refresh token cannot contain trailing spaces")
		return
	}

	if req.RefreshToken == "" {
		s.writeError(w, http.StatusBadRequest, "Refresh token is required")
		return
	}
	authReq := &models.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := s.authService.RefreshToken(r.Context(), authReq)
	if err != nil {
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
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.LogoutRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// Check if refresh token is empty (could be due to wrong field name)
	if req.RefreshToken == "" {
		s.writeError(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	authReq := &models.LogoutRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := s.authService.Logout(r.Context(), authReq)
	if err != nil {
		errorMsg := err.Error()
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

	resp, err := s.authService.GetProfile(r.Context(), claims.UserID)
	if err != nil {
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
// @Router		/auth/profile [put]
func (s *Server) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.UpdateProfileRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.authService.UpdateProfile(r.Context(), claims.UserID, &req)
	if err != nil {
		// Проверяем тип ошибки и возвращаем соответствующий код
		errorMsg := err.Error()
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
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Read the body once
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Failed to read request body: "+err.Error())
		return
	}

	// Parse raw JSON to check data types
	var rawBody map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &rawBody); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON format: "+err.Error())
		return
	}

	// Check for string values instead of numbers
	if fileSizeStr, ok := rawBody["file_size_bytes"].(string); ok {
		if _, err := strconv.ParseInt(fileSizeStr, 10, 64); err != nil {
			s.writeError(w, http.StatusBadRequest, "file_size_bytes must be a number, not a string")
			return
		}
	}
	if durationStr, ok := rawBody["duration_seconds"].(string); ok {
		if _, err := strconv.ParseInt(durationStr, 10, 64); err != nil {
			s.writeError(w, http.StatusBadRequest, "duration_seconds must be a number, not a string")
			return
		}
	}

	// Now decode into the struct
	var req models.InitiateMultipartUploadRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// Manual validation of all required fields using validation package
	var validationErrors []string

	// Validate FileName using validation package
	if req.FileName == "" {
		validationErrors = append(validationErrors, "file_name is required")
	} else {
		// Use Unicode-friendly filename validation that includes homograph attack detection
		if err := validation.ValidateFilenameUnicode(req.FileName, "file_name"); err != nil {
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
				validationErrors = append(validationErrors, fmt.Sprintf("file_name: %s", errMsg))
			}
		}
	}

	// Validate FileSizeBytes
	if req.FileSizeBytes <= 0 {
		validationErrors = append(validationErrors, "file_size_bytes must be greater than 0")
	}

	// Validate DurationSeconds
	if req.DurationSeconds <= 0 {
		validationErrors = append(validationErrors, "duration_seconds must be greater than 0")
	}

	// If there are validation errors, return them
	if len(validationErrors) > 0 {
		errorMessage := strings.Join(validationErrors, "; ")
		s.writeError(w, http.StatusBadRequest, "Validation error: "+errorMessage)
		return
	}

	resp, err := s.videoService.InitiateMultipartUploadDirect(r.Context(), claims.UserID, claims.OrgID, req.FileName, req.FileSizeBytes, req.DurationSeconds)
	if err != nil {
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
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/upload/urls [post]
func (s *Server) GetPartUploadURLs(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.GetPartUploadURLsRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	if req.TotalParts < 1 {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: minimum 1 part required")
		return
	} else if req.TotalParts > 100 {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: maximum 100 parts allowed")
		return
	} else if req.VideoID == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: video_id is required")
		return
	}

	// Validate video_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
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
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	resp, err := s.videoService.GetPartUploadURLsDirect(r.Context(), claims.UserID, claims.OrgID, req.VideoID, req.TotalParts)
	if err != nil {
		// Check if the error is related to video not found
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "video not found") {
			s.writeError(w, http.StatusNotFound, "Invalid video_id: video not found")
		} else if strings.Contains(errorMsg, "access denied") {
			s.writeError(w, http.StatusForbidden, "access denied")
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
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.CompleteMultipartUploadRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	if req.VideoID == "" {
		s.writeError(w, http.StatusBadRequest, "video_id is required")
		return
	}

	// Validate video_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
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
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	if len(req.Parts) == 0 {
		s.writeError(w, http.StatusBadRequest, "parts is required")
		return
	} else if req.Parts[0].PartNumber == 0 {
		s.writeError(w, http.StatusBadRequest, "part_number must be greater than 0")
		return
	} else if req.Parts[0].ETag == "" {
		s.writeError(w, http.StatusBadRequest, "etag is required")
		return
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
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video [get]
func (s *Server) GetVideo(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	videoID := r.URL.Query().Get("video_id")
	if videoID == "" {
		s.writeError(w, http.StatusBadRequest, "video_id is required")
		return
	}

	// Validate video_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(videoID, "video_id"); err != nil {
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
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	resp, err := s.videoService.GetVideoDirect(r.Context(), claims.UserID, claims.OrgID, videoID)
	if err != nil {
		// Check error type and return appropriate HTTP status
		errorMsg := err.Error()
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
// @Failure	401	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/search [get]
func (s *Server) SearchVideos(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
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

		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Convert VideoInfo to our Video model
	videos := make([]*models.Video, len(resp.Videos))
	for i, v := range resp.Videos {
		videos[i] = &models.Video{
			VideoID:         v.VideoID,
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
// @Description	Get public video by share token
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		share_token	query		string	true	"Share token"
// @Success	200	{object}	GetPublicVideoResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/public [get]
// func (s *Server) GetPublicVideo(w http.ResponseWriter, r *http.Request) {
// 	shareToken := r.URL.Query().Get("share_token")
// 	if shareToken == "" {
// 		s.writeError(w, http.StatusBadRequest, "share_token is required")
// 		return
// 	}

// 	// Validate share_token using Unicode-friendly validation
// 	if err := validation.ValidateFilenameUnicode(shareToken, "share_token"); err != nil {
// 		s.writeError(w, http.StatusBadRequest, err.Error())
// 		return
// 	}

// 	// Additional checks for SQL injection and XSS
// 	options := validation.CombineOptions(
// 		validation.WithSQLInjectionCheck(),
// 		validation.WithXSSCheck(),
// 	)
// 	result := validation.ValidateInput(shareToken, options)
// 	if !result.IsValid {
// 		errorMessage := strings.Join(result.Errors, "; ")
// 		s.writeError(w, http.StatusBadRequest, "Invalid share_token: "+errorMessage)
// 		return
// 	}

// 	resp, err := s.videoService.GetPublicVideoDirect(r.Context(), shareToken)
// 	if err != nil {
// 		s.writeError(w, http.StatusInternalServerError, err.Error())
// 		return
// 	}

// 	s.writeJSON(w, http.StatusOK, resp)
// }

// CreatePublicShareLink handles creating public share link
// @Summary		Create public share link
// @Description	Create public share link for video
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		request	body		CreateShareLinkRequest	true	"Share link creation request"
// @Security		BearerAuth
// @Success	200	{object}	CreateShareLinkResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/share [post]
// func (s *Server) CreatePublicShareLink(w http.ResponseWriter, r *http.Request) {
// 	claims, ok := GetUserClaims(r)
// 	if !ok {
// 		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
// 		return
// 	}

// 	// Validate Content-Type header using validation package
// 	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
// 		s.writeError(w, http.StatusBadRequest, err.Error())
// 		return
// 	}

// 	var req models.CreateShareLinkRequest
// 	if err := s.validateRequest(r, &req); err != nil {
// 		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
// 		return
// 	}

// 	// Validate video_id using Unicode-friendly validation
// 	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
// 		s.writeError(w, http.StatusBadRequest, err.Error())
// 		return
// 	}

// 	// Additional checks for SQL injection and XSS
// 	options := validation.CombineOptions(
// 		validation.WithSQLInjectionCheck(),
// 		validation.WithXSSCheck(),
// 	)
// 	result := validation.ValidateInput(req.VideoID, options)
// 	if !result.IsValid {
// 		errorMessage := strings.Join(result.Errors, "; ")
// 		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
// 		return
// 	}

// 	resp, err := s.videoService.CreatePublicShareLinkDirect(r.Context(), claims.UserID, claims.OrgID, claims.Role, req.VideoID, req.ExpiresInHours)
// 	if err != nil {
// 		s.writeError(w, http.StatusInternalServerError, err.Error())
// 		return
// 	}

// 	s.writeJSON(w, http.StatusOK, models.CreateShareLinkResponse{
// 		ShareURL:  resp.ShareURL,
// 		ExpiresAt: resp.ExpiresAt,
// 	})
// }

// RevokeShareLink handles revoking share link
// @Summary		Revoke share link
// @Description	Revoke public share link for video
// @Tags		video
// @Accept		json
// @Produce	json
// @Param		request	body		RevokeShareLinkRequest	true	"Share link revocation request"
// @Security		BearerAuth
// @Success	200	{object}	RevokeShareLinkResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/share/revoke [post]
// func (s *Server) RevokeShareLink(w http.ResponseWriter, r *http.Request) {
// 	_, ok := GetUserClaims(r)
// 	if !ok {
// 		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
// 		return
// 	}

// 	// Validate Content-Type header using validation package
// 	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
// 		s.writeError(w, http.StatusBadRequest, err.Error())
// 		return
// 	}

// 	var req models.RevokeShareLinkRequest
// 	if err := s.validateRequest(r, &req); err != nil {
// 		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
// 		return
// 	}

// 	// Validate video_id using Unicode-friendly validation
// 	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
// 		s.writeError(w, http.StatusBadRequest, err.Error())
// 		return
// 	}

// 	// Additional checks for SQL injection and XSS
// 	options := validation.CombineOptions(
// 		validation.WithSQLInjectionCheck(),
// 		validation.WithXSSCheck(),
// 	)
// 	result := validation.ValidateInput(req.VideoID, options)
// 	if !result.IsValid {
// 		errorMessage := strings.Join(result.Errors, "; ")
// 		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
// 		return
// 	}

// 	// TODO: For now, return a placeholder response
// 	// This will be implemented when we update the video service
// 	s.writeJSON(w, http.StatusOK, models.RevokeShareLinkResponse{
// 		Success: true,
// 	})
// }

// Health handles health check
// @Summary		Health check
// @Description	Check API health status
// @Tags		health
// @Accept		json
// @Produce	json
// @Success	200	{object}	models.HealthResponse
// @Router		/health [get]
func (s *Server) Health(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, models.HealthResponse{
		Status:    "ok",
		Timestamp: time.Now(),
	})
}

// SwitchOrganization handles organization switching
func (s *Server) SwitchOrganization(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.SwitchOrganizationRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// Validate org_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(req.OrgID, "org_id"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
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
		s.writeError(w, http.StatusBadRequest, "Invalid org_id: "+errorMessage)
		return
	}

	resp, err := s.authService.SwitchOrganization(r.Context(), claims.UserID, &req)
	if err != nil {
		// Проверяем тип ошибки и возвращаем соответствующий код
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "user is not a member") ||
			strings.Contains(errorMsg, "membership is not active") ||
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
// @Router	/api/v1/organization/create [post]
func (s *Server) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	if claims.Role != string(rbac.RoleAdmin) {
		s.writeError(w, http.StatusForbidden, "Only admins can create organizations")
		return
	}

	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.CreateOrganizationRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.authService.CreateOrganization(r.Context(), claims.UserID, &req)
	if err != nil {
		var validationErr validation.ValidationError

		switch {
		case strings.Contains(err.Error(), "only admins"):
			s.writeError(w, http.StatusForbidden, err.Error())
		case errors.As(err, &validationErr):
			s.writeError(w, http.StatusBadRequest, validationErr.Error())
		case strings.Contains(err.Error(), "already exists"):
			s.writeError(w, http.StatusConflict, err.Error())
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
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	videoID := r.URL.Query().Get("video_id")
	if videoID == "" {
		s.writeError(w, http.StatusBadRequest, "video_id is required")
		return
	}

	// Validate video_id using validation package
	if err := validation.ValidateFilenameUnicode(videoID, "video_id"); err != nil {
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
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	resp, err := s.videoService.GetPrivateDownloadURL(r.Context(), claims.UserID, claims.OrgID, videoID)
	if err != nil {
		s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoDownloadPrivate, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"video_id": videoID,
			"reason":   err.Error(),
		})

		errorMsg := err.Error()
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
// @Accept	json
// @Produce	json
// @Security	BearerAuth
// @Param	request	body	models.DeleteVideoRequest	true	"Delete video request"
// @Success	200	{object}	models.DeleteVideoResponse
// @Failure	400	{object}	models.ErrorResponse
// @Failure	401	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	404	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router	/api/v1/video/delete [post]
func (s *Server) DeleteVideo(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.DeleteVideoRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	if req.VideoID == "" {
		s.writeError(w, http.StatusBadRequest, "video_id is required")
		return
	}

	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	options := validation.CombineOptions(
		validation.WithSQLInjectionCheck(),
		validation.WithXSSCheck(),
	)
	result := validation.ValidateInput(req.VideoID, options)
	if !result.IsValid {
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	resp, err := s.videoService.DeleteVideoDirect(r.Context(), claims.UserID, claims.OrgID, claims.Role, req.VideoID)
	if err != nil {
		s.auditService.LogAction(r.Context(), claims.UserID, claims.OrgID, models.AuditVideoDelete, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"video_id": req.VideoID,
			"error":    err.Error(),
		})

		errorMsg := err.Error()
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
		"video_id": req.VideoID,
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
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/api/v1/organization/invite [post]
func (s *Server) InviteUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.InviteUserRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	resp, err := s.authService.InviteUser(r.Context(), claims.UserID, req.OrgID, &req)
	if err != nil {
		s.auditService.LogAction(r.Context(), claims.UserID, req.OrgID, models.AuditOrgUserInvite, models.AuditResultFailure, ipAddress, userAgent, map[string]interface{}{
			"email": req.Email,
			"role":  req.Role,
			"error": err.Error(),
		})

		errorMsg := err.Error()
		if strings.Contains(errorMsg, "only admins and managers") {
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
// @Failure	400	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/api/v1/organization/invitations/accept [post]
func (s *Server) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Validate Content-Type header
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.AcceptInvitationRequest
	if err := s.validateRequest(r, &req); err != nil {
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
		if strings.Contains(errorMsg, "invalid") || strings.Contains(errorMsg, "expired") || strings.Contains(errorMsg, "not pending") {
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
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/api/v1/organization/invitations [get]
func (s *Server) ListInvitations(w http.ResponseWriter, r *http.Request) {
	_, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		s.writeError(w, http.StatusBadRequest, "org_id is required")
		return
	}

	// Validate org_id
	if err := validation.ValidateFilenameUnicode(orgID, "org_id"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	invitations, err := s.authService.ListInvitations(r.Context(), orgID)
	if err != nil {
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
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/api/v1/organization/invitations/{id} [delete]
func (s *Server) CancelInvitation(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	invitationID := r.PathValue("id")
	if invitationID == "" {
		s.writeError(w, http.StatusBadRequest, "invitation_id is required")
		return
	}

	// Check admin/manager role
	if claims.Role != "admin" && claims.Role != "manager" {
		s.writeError(w, http.StatusForbidden, "Only admins and managers can cancel invitations")
		return
	}

	err := s.authService.CancelInvitation(r.Context(), invitationID)
	if err != nil {
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "not pending") {
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
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/api/v1/organization/members [get]
func (s *Server) ListMembers(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		s.writeError(w, http.StatusBadRequest, "org_id is required")
		return
	}

	// Check admin role
	if claims.Role != "admin" {
		s.writeError(w, http.StatusForbidden, "Only admins can list members")
		return
	}

	members, err := s.authService.ListOrgMembers(r.Context(), orgID)
	if err != nil {
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
// @Failure	400	{object}	models.ErrorResponse
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/api/v1/organization/members/{user_id}/role [put]
func (s *Server) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}
	userAgent := r.Header.Get("User-Agent")

	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Check admin role
	if claims.Role != "admin" {
		s.writeError(w, http.StatusForbidden, "Only admins can update member roles")
		return
	}

	userID := r.PathValue("user_id")
	if userID == "" {
		s.writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	// Validate Content-Type header
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.UpdateMemberRoleRequest
	if err := s.validateRequest(r, &req); err != nil {
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

// RemoveMember handles removing member from organization
// @Summary		Remove member
// @Description	Remove member from organization (admin only)
// @Tags		organization
// @Produce	json
// @Param		user_id	path		string	true	"User ID"
// @Security	BearerAuth
// @Success	200	{object}	map[string]string
// @Failure	403	{object}	models.ErrorResponse
// @Failure	500	{object}	models.ErrorResponse
// @Router		/api/v1/organization/members/{user_id} [delete]
func (s *Server) RemoveMember(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Check admin role
	if claims.Role != "admin" {
		s.writeError(w, http.StatusForbidden, "Only admins can remove members")
		return
	}

	userID := r.PathValue("user_id")
	if userID == "" {
		s.writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	err := s.authService.RemoveMember(r.Context(), claims.UserID, claims.OrgID, userID)
	if err != nil {
		errorMsg := err.Error()
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
// @Failure	500	{object}	models.ErrorResponse
// @Router		/video/publish [post]
func (s *Server) PublishVideo(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Проверка прав (только admin/manager)
	if claims.Role != "admin" && claims.Role != "manager" {
		s.writeError(w, http.StatusForbidden, "Only admins and managers can publish videos")
		return
	}

	// Validate Content-Type header using validation package
	if err := validation.ValidateContentType(r.Header.Get("Content-Type"), "application/json"); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.PublishVideoRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}
	if req.VideoID == "" {
		s.writeError(w, http.StatusBadRequest, "Missing required field: video_id")
		return
	} else if len(req.VideoID) > 255 {
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: maximum 255 characters")
		return
	}

	// Validate video_id using Unicode-friendly validation
	if err := validation.ValidateFilenameUnicode(req.VideoID, "video_id"); err != nil {
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
		errorMessage := strings.Join(result.Errors, "; ")
		s.writeError(w, http.StatusBadRequest, "Invalid video_id: "+errorMessage)
		return
	}

	resp, err := s.videoService.PublishVideoToPublicBucket(r.Context(), claims.UserID, claims.OrgID, claims.Role, req.VideoID)
	if err != nil {
		errorMsg := err.Error()
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
// @Failure 401 {object} models.ErrorResponse "Unauthorized"
// @Failure 403 {object} models.ErrorResponse "Forbidden - insufficient permissions"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /admin/audit-logs [get]
func (s *Server) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	// Extract JWT claims
	claims := r.Context().Value("claims").(*jwt.Claims)
	if claims == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Check permission
	rbacManager := rbac.NewRBAC()
	hasPermission := rbacManager.CheckPermissionWithRole(rbac.Role(claims.Role), rbac.PermissionAdminViewLogs)
	if !hasPermission {
		s.writeError(w, http.StatusForbidden, "Insufficient permissions to access audit logs")
		return
	} // Parse query parameters
	userID := r.URL.Query().Get("user_id")
	orgID := r.URL.Query().Get("org_id")
	actionType := r.URL.Query().Get("action_type")
	result := r.URL.Query().Get("result")
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")

	// Parse limit and offset
	limit := 100
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
			offset = o
		}
	}

	// Build filters map
	filters := make(map[string]interface{})
	if userID != "" {
		filters["user_id"] = userID
	}
	if orgID != "" {
		filters["org_id"] = orgID
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
