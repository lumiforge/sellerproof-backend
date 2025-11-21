package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lumiforge/sellerproof-backend/internal/auth"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
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
	s.writeJSON(w, status, ErrorResponse{
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
	var req RegisterRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &auth.RegisterRequest{
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
			strings.Contains(errorMsg, "contains invalid characters") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, errorMsg)
		}
		return
	}

	s.writeJSON(w, http.StatusCreated, RegisterResponse{
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
	var req VerifyEmailRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &auth.VerifyEmailRequest{
		Email: req.Email,
		Code:  req.Code,
	}

	resp, err := s.authService.VerifyEmail(r.Context(), authReq)
	// Заменить текущую обработку ошибки на:
	if err != nil {
		errorMsg := err.Error()
		if errorMsg == "invalid email format" || strings.Contains(errorMsg, "invalid email format") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else {
			s.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusOK, VerifyEmailResponse{
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
	var req LoginRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &auth.LoginRequest{
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
			strings.Contains(errorMsg, "invalid credentials") ||
			strings.Contains(errorMsg, "must be less than") {
			s.writeError(w, http.StatusBadRequest, errorMsg)
		} else if strings.Contains(strings.ToLower(errorMsg), "email not verified") {
			s.writeError(w, http.StatusForbidden, errorMsg)
		} else {
			s.writeError(w, http.StatusUnauthorized, errorMsg)
		}
		return
	}

	userInfo := &UserInfo{
		UserID:        resp.User.UserID,
		Email:         resp.User.Email,
		FullName:      resp.User.FullName,
		Role:          resp.User.Role,
		OrgID:         resp.User.OrgID,
		EmailVerified: resp.User.EmailVerified,
		CreatedAt:     resp.User.CreatedAt,
		UpdatedAt:     resp.User.UpdatedAt,
	}

	s.writeJSON(w, http.StatusOK, LoginResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    resp.ExpiresAt,
		User:         userInfo,
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
	var req RefreshTokenRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &auth.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := s.authService.RefreshToken(r.Context(), authReq)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, RefreshTokenResponse{
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
	var req LogoutRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	authReq := &auth.LogoutRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := s.authService.Logout(r.Context(), authReq)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, LogoutResponse{
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

	userInfo := &UserInfo{
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

	var req UpdateProfileRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// TODO: Implement profile update logic in auth service
	// For now, return updated profile
	userInfo := &UserInfo{
		UserID:        claims.UserID,
		Email:         claims.Email,
		FullName:      req.FullName,
		Role:          claims.Role,
		OrgID:         claims.OrgID,
		EmailVerified: true, // Assuming email is verified
		CreatedAt:     0,    // TODO: Get from database
		UpdatedAt:     0,    // TODO: Get from database
	}

	s.writeJSON(w, http.StatusOK, userInfo)
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
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var req InitiateMultipartUploadRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.videoService.InitiateMultipartUploadDirect(r.Context(), claims.UserID, claims.OrgID, req.FileName, req.FileSizeBytes, req.DurationSeconds)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, InitiateMultipartUploadResponse{
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

	var req GetPartUploadURLsRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.videoService.GetPartUploadURLsDirect(r.Context(), claims.UserID, claims.OrgID, req.VideoID, req.TotalParts)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, GetPartUploadURLsResponse{
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

	var req CompleteMultipartUploadRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
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

	s.writeJSON(w, http.StatusOK, CompleteMultipartUploadResponse{
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

	resp, err := s.videoService.GetVideoDirect(r.Context(), claims.UserID, claims.OrgID, videoID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Convert VideoInfo to our Video model
	videoResp := &Video{
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

	resp, err := s.videoService.SearchVideosDirect(r.Context(), claims.UserID, claims.OrgID, claims.Role, query, page, pageSize)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Convert VideoInfo to our Video model
	videos := make([]*Video, len(resp.Videos))
	for i, v := range resp.Videos {
		videos[i] = &Video{
			VideoID:         v.VideoID,
			FileName:        v.FileName,
			FileSizeBytes:   v.FileSizeBytes,
			DurationSeconds: v.DurationSeconds,
			UploadStatus:    v.UploadStatus,
			UploadedAt:      v.UploadedAt,
		}
	}

	s.writeJSON(w, http.StatusOK, SearchVideosResponse{
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
func (s *Server) GetPublicVideo(w http.ResponseWriter, r *http.Request) {
	shareToken := r.URL.Query().Get("share_token")
	if shareToken == "" {
		s.writeError(w, http.StatusBadRequest, "share_token is required")
		return
	}

	resp, err := s.videoService.GetPublicVideoDirect(r.Context(), shareToken)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, resp)
}

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
func (s *Server) CreatePublicShareLink(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var req CreateShareLinkRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.videoService.CreatePublicShareLinkDirect(r.Context(), claims.UserID, claims.OrgID, claims.Role, req.VideoID, req.ExpiresInHours)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, CreateShareLinkResponse{
		ShareURL:  resp.ShareURL,
		ExpiresAt: resp.ExpiresAt,
	})
}

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
func (s *Server) RevokeShareLink(w http.ResponseWriter, r *http.Request) {
	_, ok := GetUserClaims(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var req RevokeShareLinkRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	// TODO: For now, return a placeholder response
	// This will be implemented when we update the video service
	s.writeJSON(w, http.StatusOK, RevokeShareLinkResponse{
		Success: true,
	})
}

// Health handles health check
// @Summary		Health check
// @Description	Check API health status
// @Tags		health
// @Accept		json
// @Produce	json
// @Success	200	{object}	HealthResponse
// @Router		/health [get]
func (s *Server) Health(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, HealthResponse{
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

	var req SwitchOrganizationRequest
	if err := s.validateRequest(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request format: "+err.Error())
		return
	}

	resp, err := s.authService.SwitchOrganization(r.Context(), claims.UserID, &req)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, resp)
}
