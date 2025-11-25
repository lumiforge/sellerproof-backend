package http

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lumiforge/sellerproof-backend/internal/auth"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/validation"
	"github.com/lumiforge/sellerproof-backend/internal/video"
)

// Server represents HTTP server
type Server struct {
	authService  *auth.Service
	videoService *video.Service
	jwtManager   *jwt.JWTManager
}

// NewServer creates a new HTTP server
func NewServer(authService *auth.Service, videoService *video.Service, jwtManager *jwt.JWTManager) *Server {
	return &Server{
		authService:  authService,
		videoService: videoService,
		jwtManager:   jwtManager,
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
// @Param		request	body		RegisterRequest	true	"Registration request"
// @Success	201	{object}	RegisterResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	409	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
// @Router		/auth/register [post]
func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
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
// @Param		request	body		VerifyEmailRequest	true	"Email verification request"
// @Success	200		{object}	VerifyEmailResponse
// @Failure	400		{object}	ErrorResponse
// @Failure	500		{object}	ErrorResponse
// @Router		/auth/verify-email [post]
func (s *Server) VerifyEmail(w http.ResponseWriter, r *http.Request) {
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
// @Param		request	body		LoginRequest	true	"Login request"
// @Success	200		{object}	LoginResponse
// @Failure	401		{object}	ErrorResponse
// @Failure	400		{object}	ErrorResponse
// @Router		/auth/login [post]
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
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
// @Param		request	body		RefreshTokenRequest	true	"Refresh token request"
// @Success	200		{object}	RefreshTokenResponse
// @Failure	401		{object}	ErrorResponse
// @Failure	400		{object}	ErrorResponse
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
// @Param		request	body		LogoutRequest	true	"Logout request"
// @Security		BearerAuth
// @Success	200		{object}	LogoutResponse
// @Failure	401		{object}	ErrorResponse
// @Failure	400		{object}	ErrorResponse
// @Failure	500		{object}	ErrorResponse
// @Router		/auth/logout [post]
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
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
		if strings.Contains(errorMsg, "refresh token not found") {
			s.writeError(w, http.StatusNotFound, errorMsg)
		} else if strings.Contains(errorMsg, "refresh token expired") {
			s.writeError(w, http.StatusUnauthorized, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

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
// @Success	200	{object}	UserInfo
// @Failure	401	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
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
// @Param		request	body		UpdateProfileRequest	true	"Profile update request"
// @Security		BearerAuth
// @Success	200	{object}	UserInfo
// @Failure	401	{object}	ErrorResponse
// @Failure	400	{object}	ErrorResponse
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
// @Param		request	body		InitiateMultipartUploadRequest	true	"Multipart upload initiation request"
// @Security		BearerAuth
// @Success	200	{object}	InitiateMultipartUploadResponse
// @Failure	401	{object}	ErrorResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
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
		// Use Unicode-friendly filename validation
		if err := validation.ValidateFilenameUnicode(req.FileName, "file_name"); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}

		// Additional checks for SQL injection and XSS only (skip Unicode security for filenames)
		options := validation.CombineOptions(
			validation.WithSQLInjectionCheck(),
			validation.WithXSSCheck(),
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
// @Param		request	body		GetPartUploadURLsRequest	true	"Part upload URLs request"
// @Security		BearerAuth
// @Success	200	{object}	GetPartUploadURLsResponse
// @Failure	401	{object}	ErrorResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
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
// @Param		request	body		CompleteMultipartUploadRequest	true	"Multipart upload completion request"
// @Security		BearerAuth
// @Success	200	{object}	CompleteMultipartUploadResponse
// @Failure	401	{object}	ErrorResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
// @Router		/video/upload/complete [post]
func (s *Server) CompleteMultipartUpload(w http.ResponseWriter, r *http.Request) {
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
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

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
// @Success	200	{object}	Video
// @Failure	401	{object}	ErrorResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
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
// @Success	200	{object}	SearchVideosResponse
// @Failure	401	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
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
// @Failure	400	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
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
// @Failure	401	{object}	ErrorResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
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
// @Failure	401	{object}	ErrorResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
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
// @Success	200	{object}	HealthResponse
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

// DownloadVideo handles private video download
// @Summary		Download private video
// @Description	Get temporary presigned URL for private video download (1 hour)
// @Tags		video
// @Accept		json
// @Produce	json
// @Security	BearerAuth
// @Param		video_id	query		string	true	"Video ID"
// @Success	200	{object}	models.DownloadURLResult
// @Failure	401	{object}	ErrorResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
// @Router		/video/download [get]
func (s *Server) DownloadVideo(w http.ResponseWriter, r *http.Request) {
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

// PublishVideo handles video publishing to public bucket
// @Summary		Publish video
// @Description	Publish video to public bucket (admin/manager only)
// @Tags		video
// @Accept		json
// @Produce	json
// @Security	BearerAuth
// @Param		request	body		models.PublishVideoRequest	true	"Publish video request"
// @Success	200	{object}	models.PublishVideoResult
// @Failure	401	{object}	ErrorResponse
// @Failure	403	{object}	ErrorResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
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
