package models

// Video Request/Response Models

// InitiateMultipartUploadRequest represents a request to initiate multipart upload
// @Description	Multipart upload initiation request
type InitiateMultipartUploadRequest struct {
	Title           string `json:"title"`
	FileName        string `json:"file_name"`
	FileSizeBytes   int64  `json:"file_size_bytes"`
	DurationSeconds int32  `json:"duration_seconds"`
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
	VideoID    string `json:"video_id"`
	TotalParts int32  `json:"total_parts"`
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
	VideoID string          `json:"video_id"`
	Parts   []CompletedPart `json:"parts"`
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
	Title           string `json:"title"`
	AuthorName      string `json:"author_name"`
	FileName        string `json:"file_name"`
	FileSizeBytes   int64  `json:"file_size_bytes"`
	DurationSeconds int32  `json:"duration_seconds"`
	UploadStatus    string `json:"upload_status"`
	PublishStatus   string `json:"publish_status"`
	UploadedAt      int64  `json:"uploaded_at"`
}

// GetVideoRequest represents a request to get video information
// @Description	Get video information request
type GetVideoRequest struct {
	VideoID string `json:"video_id"`
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
	Page     int32  `json:"page"`
	PageSize int32  `json:"page_size"`
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
	VideoID        string `json:"video_id"`
	ExpiresInHours int32  `json:"expires_in_hours"`
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
	ShareToken string `json:"share_token"`
}

// GetPublicVideoResponse represents a response with public video information
// @Description	Get public video response
type GetPublicVideoResponse struct {
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	DownloadURL string `json:"download_url"`
	ExpiresAt   int64  `json:"expires_at"`
}

// PublicVideoResponse represents a response with public video information for new endpoint
// @Description	Get public video response
type PublicVideoResponse struct {
	VideoID         string `json:"video_id"`
	Title           string `json:"title"`
	Description     string `json:"description"`
	FileName        string `json:"file_name"`
	ThumbnailURL    string `json:"thumbnail_url"`
	DurationSeconds int    `json:"duration_seconds"`
	FileSizeBytes   int64  `json:"file_size_bytes"`
	StreamURL       string `json:"stream_url"`
	ExpiresAt       int64  `json:"expires_at"`
	UploadedAt      int64  `json:"uploaded_at"`
}

// RevokeShareLinkRequest represents a request to revoke share link
// @Description	Revoke share link request
type RevokeShareLinkRequest struct {
	VideoID string `json:"video_id"`
}

// RevokeShareLinkResponse represents a response for revoked share link
// @Description	Revoke share link response
type RevokeShareLinkResponse struct {
	Success bool `json:"success"`
}

// DownloadURLResult represents the result of getting private download URL
// @Description	Private download URL result
type DownloadURLResult struct {
	DownloadURL string `json:"download_url"`
	ExpiresAt   int64  `json:"expires_at"`
}

// PublishVideoRequest represents a request to publish video to public bucket
// @Description	Publish video request
type PublishVideoRequest struct {
	VideoID string `json:"video_id"`
}

// PublishVideoResult represents the result of publishing video
// @Description	Publish video result
type PublishVideoResult struct {
	PublicURL   string `json:"public_url"`
	PublicToken string `json:"public_token"`
	Message     string `json:"message"`
}

// RevokeVideoRequest represents a request to revoke public access to a video
// @Description	Revoke video public access request
type RevokeVideoRequest struct {
	VideoID string `json:"video_id"`
}

// RevokeVideoResponse represents a response for revoked video access
// @Description	Revoke video public access response
type RevokeVideoResponse struct {
	Message string `json:"message"`
	VideoID string `json:"video_id"`
	Status  string `json:"status"`
}

// ReplaceVideoRequest represents a request to replace an existing video
// @Description	Video replacement request
type ReplaceVideoRequest struct {
	VideoID         string `json:"video_id"`
	FileName        string `json:"file_name"`
	FileSizeBytes   int64  `json:"file_size_bytes"`
	DurationSeconds int32  `json:"duration_seconds"`
}
