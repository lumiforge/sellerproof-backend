package http

import "time"

// Auth Request/Response Models

// RegisterRequest represents a registration request
// @Description	Registration request with user details
type RegisterRequest struct {
	Email            string `json:"email" validate:"required,email"`
	Password         string `json:"password" validate:"required,min=8"`
	FullName         string `json:"full_name" validate:"required"`
	OrganizationName string `json:"organization_name"`
}

// RegisterResponse represents a registration response
// @Description	Registration response with user ID and message
type RegisterResponse struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

// VerifyEmailRequest represents an email verification request
// @Description	Email verification request with email and code
type VerifyEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required"`
}

// VerifyEmailResponse represents an email verification response
// @Description	Email verification response with success status
type VerifyEmailResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// LoginRequest represents a login request
// @Description	Login request with email and password
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse represents a login response
// @Description	Login response with tokens and user info
type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    int64     `json:"expires_at"`
	User         *UserInfo `json:"user"`
}

// SwitchOrganizationRequest представляет запрос на переключение организации
type SwitchOrganizationRequest struct {
	OrgID string `json:"org_id"`
}

// SwitchOrganizationResponse представляет ответ на переключение организации
type SwitchOrganizationResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"`
	OrgID       string `json:"org_id"`
}

// RefreshTokenRequest represents a refresh token request
// @Description	Refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// RefreshTokenResponse represents a refresh token response
// @Description	Refresh token response with new tokens
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// LogoutRequest represents a logout request
// @Description	Logout request with refresh token
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// LogoutResponse represents a logout response
// @Description	Logout response with message
type LogoutResponse struct {
	Message string `json:"message"`
}

// UpdateProfileRequest represents a profile update request
// @Description	Profile update request with full name
type UpdateProfileRequest struct {
	FullName string `json:"full_name" validate:"required"`
}

// UserInfo represents user information
// @Description	User profile information
type UserInfo struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	FullName      string `json:"full_name"`
	Role          string `json:"role"`
	OrgID         string `json:"org_id"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
}

// Video Request/Response Models

// InitiateMultipartUploadRequest represents a request to initiate multipart upload
// @Description	Multipart upload initiation request
type InitiateMultipartUploadRequest struct {
	FileName        string `json:"file_name" validate:"required"`
	FileSizeBytes   int64  `json:"file_size_bytes" validate:"required,min=1"`
	DurationSeconds int32  `json:"duration_seconds" validate:"min=0"`
}

// InitiateMultipartUploadResponse represents a response for initiated multipart upload
// @Description	Multipart upload initiation response
type InitiateMultipartUploadResponse struct {
	VideoID               string `json:"video_id"`
	UploadID              string `json:"upload_id"`
	RecommendedPartSizeMB int32  `json:"recommended_part_size_mb"`
}

// GetPartUploadURLsRequest represents a request to get part upload URLs
// @Description	Part upload URLs request
type GetPartUploadURLsRequest struct {
	VideoID    string `json:"video_id" validate:"required"`
	TotalParts int32  `json:"total_parts" validate:"required,min=1"`
}

// GetPartUploadURLsResponse represents a response with part upload URLs
// @Description	Part upload URLs response
type GetPartUploadURLsResponse struct {
	PartURLs  []string `json:"part_urls"`
	ExpiresAt int64    `json:"expires_at"`
}

// CompletedPart represents a completed multipart upload part
// @Description	Completed multipart upload part
type CompletedPart struct {
	PartNumber int32  `json:"part_number"`
	ETag       string `json:"etag"`
}

// CompleteMultipartUploadRequest represents a request to complete multipart upload
// @Description	Multipart upload completion request
type CompleteMultipartUploadRequest struct {
	VideoID string          `json:"video_id" validate:"required"`
	Parts   []CompletedPart `json:"parts" validate:"required,min=1"`
}

// CompleteMultipartUploadResponse represents a response for completed multipart upload
// @Description	Multipart upload completion response
type CompleteMultipartUploadResponse struct {
	Message  string `json:"message"`
	VideoURL string `json:"video_url"`
}

// Video represents video information
// @Description	Video information
type Video struct {
	VideoID         string `json:"video_id"`
	FileName        string `json:"file_name"`
	FileSizeBytes   int64  `json:"file_size_bytes"`
	DurationSeconds int32  `json:"duration_seconds"`
	UploadStatus    string `json:"upload_status"`
	UploadedAt      int64  `json:"uploaded_at"`
}

// GetVideoRequest represents a request to get video information
// @Description	Get video information request
type GetVideoRequest struct {
	VideoID string `json:"video_id" validate:"required"`
}

// GetVideoResponse represents a response with video information
// @Description	Get video information response
type GetVideoResponse struct {
	Video *Video `json:"video"`
}

// SearchVideosRequest represents a request to search videos
// @Description	Search videos request
type SearchVideosRequest struct {
	Query    string `json:"query"`
	Page     int32  `json:"page" validate:"min=1"`
	PageSize int32  `json:"page_size" validate:"min=1,max=100"`
}

// SearchVideosResponse represents a response with search results
// @Description	Search videos response
type SearchVideosResponse struct {
	Videos     []*Video `json:"videos"`
	TotalCount int64    `json:"total_count"`
}

// CreateShareLinkRequest represents a request to create a share link
// @Description	Create share link request
type CreateShareLinkRequest struct {
	VideoID        string `json:"video_id" validate:"required"`
	ExpiresInHours int32  `json:"expires_in_hours" validate:"min=0"`
}

// CreateShareLinkResponse represents a response with created share link
// @Description	Create share link response
type CreateShareLinkResponse struct {
	ShareURL  string `json:"share_url"`
	ExpiresAt int64  `json:"expires_at"`
}

// GetPublicVideoRequest represents a request to get public video
// @Description	Get public video request
type GetPublicVideoRequest struct {
	ShareToken string `json:"share_token" validate:"required"`
}

// GetPublicVideoResponse represents a response with public video information
// @Description	Get public video response
type GetPublicVideoResponse struct {
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	DownloadURL string `json:"download_url"`
	ExpiresAt   int64  `json:"expires_at"`
}

// RevokeShareLinkRequest represents a request to revoke share link
// @Description	Revoke share link request
type RevokeShareLinkRequest struct {
	VideoID string `json:"video_id" validate:"required"`
}

// RevokeShareLinkResponse represents a response for revoked share link
// @Description	Revoke share link response
type RevokeShareLinkResponse struct {
	Success bool `json:"success"`
}

// Common Response Models

// ErrorResponse represents an error response
// @Description	Error response with details
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// SuccessResponse represents a generic success response
// @Description	Generic success response
type SuccessResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

// HealthResponse represents a health check response
// @Description	Health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version,omitempty"`
}
