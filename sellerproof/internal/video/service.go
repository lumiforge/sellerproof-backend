package video

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/storage"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

type Service struct {
	db      ydb.Database
	storage *storage.Client
	rbac    *rbac.RBAC
}

func NewService(db ydb.Database, storage *storage.Client, rbac *rbac.RBAC) *Service {
	return &Service{
		db:      db,
		storage: storage,
		rbac:    rbac,
	}
}

// CompletedPart represents a completed multipart upload part
type CompletedPart struct {
	PartNumber int32  `json:"part_number"`
	ETag       string `json:"etag"`
}

// VideoInfo represents video information
type VideoInfo struct {
	VideoID         string `json:"video_id"`
	FileName        string `json:"file_name"`
	FileSizeBytes   int64  `json:"file_size_bytes"`
	DurationSeconds int32  `json:"duration_seconds"`
	UploadStatus    string `json:"upload_status"`
	UploadedAt      int64  `json:"uploaded_at"`
}

// SearchVideosResult represents search results
type SearchVideosResult struct {
	Videos     []*VideoInfo `json:"videos"`
	TotalCount int64        `json:"total_count"`
}

// InitiateMultipartUploadDirect initiates multipart upload with direct parameters
func (s *Service) InitiateMultipartUploadDirect(ctx context.Context, userID, orgID, fileName string, fileSizeBytes int64, durationSeconds int32) (*InitiateMultipartUploadResult, error) {
	// Проверка прав
	// TODO: Реализовать проверку прав через RBAC

	// Проверка квоты
	sub, err := s.db.GetSubscriptionByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subscription: %w", err)
	}

	currentUsage, err := s.db.GetStorageUsage(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get storage usage: %w", err)
	}

	limitBytes := sub.StorageLimitGB * 1024 * 1024 * 1024
	if sub.StorageLimitGB > 0 && (currentUsage+fileSizeBytes) > limitBytes {
		return nil, fmt.Errorf("storage limit exceeded")
	}

	videoID := uuid.New().String()
	objectKey := fmt.Sprintf("videos/%s/%s/%s", orgID, videoID, fileName)

	uploadID, err := s.storage.InitiateMultipartUpload(ctx, objectKey, "video/mp4")
	if err != nil {
		return nil, fmt.Errorf("failed to initiate s3 upload: %w", err)
	}

	video := &ydb.Video{
		VideoID:         videoID,
		OrgID:           orgID,
		UploadedBy:      userID,
		FileName:        fileName,
		FileNameSearch:  strings.ToLower(fileName),
		FileSizeBytes:   fileSizeBytes,
		StoragePath:     objectKey,
		DurationSeconds: durationSeconds,
		UploadID:        uploadID,
		UploadStatus:    "pending",
		IsDeleted:       false,
	}

	if err := s.db.CreateVideo(ctx, video); err != nil {
		return nil, fmt.Errorf("failed to create video record: %w", err)
	}

	return &InitiateMultipartUploadResult{
		VideoID:               videoID,
		UploadID:              uploadID,
		RecommendedPartSizeMB: 10,
	}, nil
}

// InitiateMultipartUploadResult represents the result of initiating multipart upload
type InitiateMultipartUploadResult struct {
	VideoID               string `json:"video_id"`
	UploadID              string `json:"upload_id"`
	RecommendedPartSizeMB int32  `json:"recommended_part_size_mb"`
}

// GetPartUploadURLsDirect gets part upload URLs with direct parameters
func (s *Service) GetPartUploadURLsDirect(ctx context.Context, userID, orgID, videoID string, totalParts int32) (*GetPartUploadURLsResult, error) {
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, fmt.Errorf("video not found")
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	urls := make([]string, totalParts)
	for i := 0; i < int(totalParts); i++ {
		url, err := s.storage.GeneratePresignedPartURL(ctx, video.StoragePath, video.UploadID, int32(i+1), 1*time.Hour)
		if err != nil {
			return nil, fmt.Errorf("failed to generate url for part %d: %w", i+1, err)
		}
		urls[i] = url
	}

	video.TotalParts = totalParts
	video.UploadStatus = "uploading"
	s.db.UpdateVideo(ctx, video)

	return &GetPartUploadURLsResult{
		PartURLs:  urls,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}, nil
}

// GetPartUploadURLsResult represents the result of getting part upload URLs
type GetPartUploadURLsResult struct {
	PartURLs  []string `json:"part_urls"`
	ExpiresAt int64    `json:"expires_at"`
}

// CompleteMultipartUploadDirect completes multipart upload with direct parameters
func (s *Service) CompleteMultipartUploadDirect(ctx context.Context, userID, orgID, videoID string, parts []CompletedPart) (*CompleteMultipartUploadResult, error) {
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, fmt.Errorf("video not found")
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	s3Parts := make([]types.CompletedPart, len(parts))
	for i, p := range parts {
		s3Parts[i] = types.CompletedPart{
			ETag:       aws.String(p.ETag),
			PartNumber: aws.Int32(p.PartNumber),
		}
	}

	if err := s.storage.CompleteMultipartUpload(ctx, video.StoragePath, video.UploadID, s3Parts); err != nil {
		return nil, fmt.Errorf("failed to complete s3 upload: %w", err)
	}

	video.UploadStatus = "completed"
	now := time.Now()
	video.UploadedAt = &now
	s.db.UpdateVideo(ctx, video)

	// Генерация URL для просмотра (опционально)
	url, _ := s.storage.GeneratePresignedDownloadURL(ctx, video.StoragePath, 1*time.Hour)

	return &CompleteMultipartUploadResult{
		Message:  "Upload completed",
		VideoURL: url,
	}, nil
}

// CompleteMultipartUploadResult represents the result of completing multipart upload
type CompleteMultipartUploadResult struct {
	Message  string `json:"message"`
	VideoURL string `json:"video_url"`
}

// GetVideoDirect gets video information with direct parameters
func (s *Service) GetVideoDirect(ctx context.Context, userID, orgID, videoID string) (*VideoInfo, error) {
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, err
	}
	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	var uploadedAt int64
	if video.UploadedAt != nil {
		uploadedAt = video.UploadedAt.Unix()
	}

	return &VideoInfo{
		VideoID:         video.VideoID,
		FileName:        video.FileName,
		FileSizeBytes:   video.FileSizeBytes,
		DurationSeconds: video.DurationSeconds,
		UploadStatus:    video.UploadStatus,
		UploadedAt:      uploadedAt,
	}, nil
}

// CreatePublicShareLinkDirect creates public share link with direct parameters
func (s *Service) CreatePublicShareLinkDirect(ctx context.Context, userID, orgID, role, videoID string, expiresInHours int32) (*CreatePublicShareLinkResult, error) {
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, err
	}
	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	// RBAC: User can only share own videos
	if rbac.Role(role) == rbac.RoleUser && video.UploadedBy != userID {
		return nil, fmt.Errorf("access denied: can only share own videos")
	}

	var expiresAt int64
	if video.ShareExpiresAt != nil {
		expiresAt = video.ShareExpiresAt.Unix()
	}

	token := generateToken(32)
	video.PublicShareToken = token
	if expiresInHours > 0 {
		t := time.Now().Add(time.Duration(expiresInHours) * time.Hour)
		video.ShareExpiresAt = &t
	} else {
		video.ShareExpiresAt = nil
	}

	if err := s.db.UpdateVideo(ctx, video); err != nil {
		return nil, err
	}

	return &CreatePublicShareLinkResult{
		ShareURL:  fmt.Sprintf("https://sellerproof.ru/share/%s", token),
		ExpiresAt: expiresAt,
	}, nil
}

// CreatePublicShareLinkResult represents the result of creating public share link
type CreatePublicShareLinkResult struct {
	ShareURL  string `json:"share_url"`
	ExpiresAt int64  `json:"expires_at"`
}

// GetPublicVideoDirect gets public video with direct parameters
func (s *Service) GetPublicVideoDirect(ctx context.Context, shareToken string) (*GetPublicVideoResult, error) {
	video, err := s.db.GetVideoByShareToken(ctx, shareToken)
	if err != nil {
		return nil, fmt.Errorf("video not found or link invalid")
	}

	if video.ShareExpiresAt != nil && time.Now().After(*video.ShareExpiresAt) {
		return nil, fmt.Errorf("link expired")
	}

	url, err := s.storage.GeneratePresignedDownloadURL(ctx, video.StoragePath, 1*time.Hour)
	if err != nil {
		return nil, err
	}

	return &GetPublicVideoResult{
		FileName:    video.FileName,
		FileSize:    video.FileSizeBytes,
		DownloadURL: url,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}, nil
}

// GetPublicVideoResult represents the result of getting public video
type GetPublicVideoResult struct {
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	DownloadURL string `json:"download_url"`
	ExpiresAt   int64  `json:"expires_at"`
}

// RevokeShareLinkDirect revokes share link with direct parameters
func (s *Service) RevokeShareLinkDirect(ctx context.Context, userID, orgID, role, videoID string) error {
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return err
	}
	if video.OrgID != orgID {
		return fmt.Errorf("access denied")
	}

	// RBAC: User can only revoke own videos
	if rbac.Role(role) == rbac.RoleUser && video.UploadedBy != userID {
		return fmt.Errorf("access denied: can only revoke own videos")
	}

	video.PublicShareToken = ""
	video.ShareExpiresAt = nil

	return s.db.UpdateVideo(ctx, video)
}

// SearchVideosDirect searches videos with direct parameters
func (s *Service) SearchVideosDirect(ctx context.Context, userID, orgID, role, query string, page, pageSize int32) (*SearchVideosResult, error) {
	if !s.rbac.CheckPermissionWithRole(rbac.Role(role), rbac.PermissionVideoSearch) {
		return nil, fmt.Errorf("access denied")
	}

	filterUserID := ""
	if rbac.Role(role) == rbac.RoleUser {
		filterUserID = userID
	}

	limit := int(pageSize)
	if limit <= 0 {
		limit = 10
	}
	offset := (int(page) - 1) * limit
	if offset < 0 {
		offset = 0
	}

	videos, total, err := s.db.SearchVideos(ctx, orgID, filterUserID, query, limit, offset)
	if err != nil {
		return nil, err
	}

	videoInfos := make([]*VideoInfo, len(videos))
	for i, v := range videos {
		var uploadedAt int64
		if v.UploadedAt != nil {
			uploadedAt = v.UploadedAt.Unix()
		}

		videoInfos[i] = &VideoInfo{
			VideoID:         v.VideoID,
			FileName:        v.FileName,
			FileSizeBytes:   v.FileSizeBytes,
			DurationSeconds: v.DurationSeconds,
			UploadStatus:    v.UploadStatus,
			UploadedAt:      uploadedAt,
		}
	}

	return &SearchVideosResult{
		Videos:     videoInfos,
		TotalCount: total,
	}, nil
}

func generateToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}
