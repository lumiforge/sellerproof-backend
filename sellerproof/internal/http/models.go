package http

import "time"

// Auth Request/Response Models

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	FullName string `json:"full_name" validate:"required"`
}

// RegisterResponse represents a registration response
type RegisterResponse struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

// VerifyEmailRequest represents an email verification request
type VerifyEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required"`
}

// VerifyEmailResponse represents an email verification response
type VerifyEmailResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    int64     `json:"expires_at"`
	User         *UserInfo `json:"user"`
}

// RefreshTokenRequest represents a refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// RefreshTokenResponse represents a refresh token response
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// LogoutResponse represents a logout response
type LogoutResponse struct {
	Message string `json:"message"`
}

// UpdateProfileRequest represents a profile update request
type UpdateProfileRequest struct {
	FullName string `json:"full_name" validate:"required"`
}

// UserInfo represents user information
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
type InitiateMultipartUploadRequest struct {
	FileName        string `json:"file_name" validate:"required"`
	FileSizeBytes   int64  `json:"file_size_bytes" validate:"required,min=1"`
	DurationSeconds int32  `json:"duration_seconds" validate:"min=0"`
}

// InitiateMultipartUploadResponse represents a response for initiated multipart upload
type InitiateMultipartUploadResponse struct {
	VideoID               string `json:"video_id"`
	UploadID              string `json:"upload_id"`
	RecommendedPartSizeMB int32  `json:"recommended_part_size_mb"`
}

// GetPartUploadURLsRequest represents a request to get part upload URLs
type GetPartUploadURLsRequest struct {
	VideoID    string `json:"video_id" validate:"required"`
	TotalParts int32  `json:"total_parts" validate:"required,min=1"`
}

// GetPartUploadURLsResponse represents a response with part upload URLs
type GetPartUploadURLsResponse struct {
	PartURLs  []string `json:"part_urls"`
	ExpiresAt int64    `json:"expires_at"`
}

// CompletedPart represents a completed multipart upload part
type CompletedPart struct {
	PartNumber int32  `json:"part_number"`
	ETag       string `json:"etag"`
}

// CompleteMultipartUploadRequest represents a request to complete multipart upload
type CompleteMultipartUploadRequest struct {
	VideoID string          `json:"video_id" validate:"required"`
	Parts   []CompletedPart `json:"parts" validate:"required,min=1"`
}

// CompleteMultipartUploadResponse represents a response for completed multipart upload
type CompleteMultipartUploadResponse struct {
	Message  string `json:"message"`
	VideoURL string `json:"video_url"`
}

// Video represents video information
type Video struct {
	VideoID         string `json:"video_id"`
	FileName        string `json:"file_name"`
	FileSizeBytes   int64  `json:"file_size_bytes"`
	DurationSeconds int32  `json:"duration_seconds"`
	UploadStatus    string `json:"upload_status"`
	UploadedAt      int64  `json:"uploaded_at"`
}

// GetVideoRequest represents a request to get video information
type GetVideoRequest struct {
	VideoID string `json:"video_id" validate:"required"`
}

// GetVideoResponse represents a response with video information
type GetVideoResponse struct {
	Video *Video `json:"video"`
}

// SearchVideosRequest represents a request to search videos
type SearchVideosRequest struct {
	Query    string `json:"query"`
	Page     int32  `json:"page" validate:"min=1"`
	PageSize int32  `json:"page_size" validate:"min=1,max=100"`
}

// SearchVideosResponse represents a response with search results
type SearchVideosResponse struct {
	Videos     []*Video `json:"videos"`
	TotalCount int64    `json:"total_count"`
}

// CreateShareLinkRequest represents a request to create a share link
type CreateShareLinkRequest struct {
	VideoID        string `json:"video_id" validate:"required"`
	ExpiresInHours int32  `json:"expires_in_hours" validate:"min=0"`
}

// CreateShareLinkResponse represents a response with created share link
type CreateShareLinkResponse struct {
	ShareURL  string `json:"share_url"`
	ExpiresAt int64  `json:"expires_at"`
}

// GetPublicVideoRequest represents a request to get public video
type GetPublicVideoRequest struct {
	ShareToken string `json:"share_token" validate:"required"`
}

// GetPublicVideoResponse represents a response with public video information
type GetPublicVideoResponse struct {
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	DownloadURL string `json:"download_url"`
	ExpiresAt   int64  `json:"expires_at"`
}

// RevokeShareLinkRequest represents a request to revoke share link
type RevokeShareLinkRequest struct {
	VideoID string `json:"video_id" validate:"required"`
}

// RevokeShareLinkResponse represents a response for revoked share link
type RevokeShareLinkResponse struct {
	Success bool `json:"success"`
}

// Common Response Models

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// SuccessResponse represents a generic success response
type SuccessResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version,omitempty"`
}
