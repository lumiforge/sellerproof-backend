package video

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/storage"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

type Service struct {
	db      ydb.Database
	storage *storage.Client
	rbac    *rbac.RBAC
	baseURL string
}

func NewService(db ydb.Database, storage *storage.Client, rbac *rbac.RBAC, baseURL string) *Service {
	return &Service{
		db:      db,
		storage: storage,
		rbac:    rbac,
		baseURL: baseURL,
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
	Title           string `json:"title"`
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

// DeleteVideoResult represents the result of a delete operation
type DeleteVideoResult struct {
	Message string `json:"message"`
}

// DeleteVideoDirect deletes a video and removes associated storage objects
func (s *Service) DeleteVideoDirect(ctx context.Context, userID, orgID, role, videoID string) (*DeleteVideoResult, error) {
	if !s.rbac.CheckPermissionWithRole(rbac.Role(role), rbac.PermissionVideoDelete) {
		return nil, fmt.Errorf("access denied")
	}

	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		if strings.Contains(err.Error(), "video not found") {
			return nil, fmt.Errorf("video not found")
		}
		return nil, fmt.Errorf("failed to read video: %w", err)
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	if rbac.Role(role) == rbac.RoleUser && video.UploadedBy != userID {
		return nil, fmt.Errorf("access denied")
	}

	if !video.IsDeleted {
		if err := s.storage.DeletePrivateObject(ctx, video.StoragePath); err != nil {
			return nil, fmt.Errorf("failed to delete video from storage: %w", err)
		}

		if video.PublicURL != nil && *video.PublicURL != "" {
			publicKey := fmt.Sprintf("public/%s/%s/%s", video.OrgID, video.VideoID, video.FileName)
			if err := s.storage.DeletePublicObject(ctx, publicKey); err != nil {
				log.Printf("failed to delete public object for video %s: %v", video.VideoID, err)
			}
		}
	}

	video.IsDeleted = true
	video.UploadStatus = "deleted"
	video.PublishStatus = "deleted"
	video.PublicURL = nil
	video.PublicShareToken = nil
	video.ShareExpiresAt = nil

	if err := s.db.UpdateVideo(ctx, video); err != nil {
		return nil, fmt.Errorf("failed to update video record: %w", err)
	}

	return &DeleteVideoResult{Message: "Video deleted"}, nil
}

// InitiateMultipartUploadDirect initiates multipart upload with direct parameters
func (s *Service) InitiateMultipartUploadDirect(ctx context.Context, userID, orgID, title, fileName string, fileSizeBytes int64, durationSeconds int32) (*InitiateMultipartUploadResult, error) {

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

	var limitBytes int64 = sub.StorageLimitMB * 1024 * 1024
	if sub.StorageLimitMB > 0 && (currentUsage+fileSizeBytes) > limitBytes {

		return nil, fmt.Errorf("storage limit exceeded")
	}

	videoID := uuid.New().String()
	objectKey := fmt.Sprintf("videos/%s/%s/%s", orgID, videoID, fileName)

	uploadID, err := s.storage.InitiateMultipartUpload(ctx, objectKey, "video/mp4")
	if err != nil {

		return nil, fmt.Errorf("failed to initiate s3 upload: %w", err)
	}

	fileNameSearch := strings.ToLower(fileName)
	uploadStatus := "pending"

	createdAt := time.Now()
	video := &ydb.Video{
		VideoID:         videoID,
		OrgID:           orgID,
		UploadedBy:      userID,
		FileName:        fileName,
		FileNameSearch:  fileNameSearch,
		FileSizeBytes:   fileSizeBytes,
		StoragePath:     objectKey,
		DurationSeconds: durationSeconds,
		UploadID:        uploadID,
		UploadStatus:    uploadStatus,
		IsDeleted:       false,
		PublishStatus:   "private",
		CreatedAt:       createdAt,
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
		// Check if the error is specifically "video not found"
		if strings.Contains(err.Error(), "video not found") {
			return nil, fmt.Errorf("video not found")
		}
		return nil, fmt.Errorf("video not found %w", err)
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	urls := make([]string, totalParts)
	for i := 0; i < int(totalParts); i++ {
		storagePath := video.StoragePath
		uploadID := video.UploadID
		url, err := s.storage.GeneratePresignedPartURL(ctx, storagePath, uploadID, int32(i+1), 1*time.Hour)
		if err != nil {
			return nil, fmt.Errorf("failed to generate url for part %d: %w", i+1, err)
		}
		urls[i] = url
	}

	video.TotalParts = &totalParts
	uploadStatus := "uploading"
	video.UploadStatus = uploadStatus
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
	log.Println("CompleteMultipartUploadDirect with userID", userID, "orgID", orgID, "videoID", videoID)
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

	storagePath := video.StoragePath
	uploadID := video.UploadID
	if err := s.storage.CompleteMultipartUpload(ctx, storagePath, uploadID, s3Parts); err != nil {
		return nil, fmt.Errorf("failed to complete s3 upload: %w", err)
	}

	uploadStatus := "completed"
	video.UploadStatus = uploadStatus
	now := time.Now()
	video.UploadedAt = &now
	s.db.UpdateVideo(ctx, video)

	// Генерация URL для просмотра (опционально)
	url, _ := s.storage.GeneratePresignedDownloadURL(ctx, storagePath, 1*time.Hour)

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
	fileName := video.FileName
	fileSizeBytes := video.FileSizeBytes
	durationSeconds := video.DurationSeconds
	uploadStatus := video.UploadStatus
	return &VideoInfo{
		VideoID:         video.VideoID,
		FileName:        fileName,
		FileSizeBytes:   fileSizeBytes,
		DurationSeconds: durationSeconds,
		UploadStatus:    uploadStatus,
		UploadedAt:      uploadedAt,
	}, nil
}

// // CreatePublicShareLinkDirect creates public share link with direct parameters
// func (s *Service) CreatePublicShareLinkDirect(ctx context.Context, userID, orgID, role, videoID string, expiresInHours int32) (*CreatePublicShareLinkResult, error) {
// 	video, err := s.db.GetVideo(ctx, videoID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if video.OrgID != orgID {
// 		return nil, fmt.Errorf("access denied")
// 	}

// 	// RBAC: User can only share own videos
// 	if rbac.Role(role) == rbac.RoleUser && video.UploadedBy != userID {
// 		return nil, fmt.Errorf("access denied: can only share own videos")
// 	}

// 	// var expiresAt int64
// 	// if video.ShareExpiresAt != nil && !video.ShareExpiresAt.IsZero() {
// 	// 	expiresAt = video.ShareExpiresAt.Unix()
// 	// }

// 	token := generateToken(32)
// 	video.PublicShareToken = &token
// 	if expiresInHours > 0 {
// 		t := time.Now().Add(time.Duration(expiresInHours) * time.Hour)
// 		video.ShareExpiresAt = &t
// 	} else {
// 		video.ShareExpiresAt = nil
// 	}

// 	if err := s.db.UpdateVideo(ctx, video); err != nil {
// 		return nil, err
// 	}

// 	// Генерируем pre-signed URL на S3 сразу
// 	// TODO HARD
// 	duration := time.Duration(expiresInHours) * time.Hour
// 	if duration == 0 {
// 		duration = 24 * time.Hour // по умолчанию 24 часа
// 	}

// 	presignedURL, err := s.storage.GeneratePresignedDownloadURL(
// 		ctx,
// 		video.StoragePath,
// 		duration,
// 	)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate presigned URL: %w", err)
// 	}

// 	return &CreatePublicShareLinkResult{
// 		ShareURL:  presignedURL, // Прямая ссылка на S3
// 		ExpiresAt: time.Now().Add(duration).Unix(),
// 	}, nil

// 	// return &CreatePublicShareLinkResult{
// 	// 	ShareURL:  fmt.Sprintf("https://sellerproof.ru/share/%s", token),
// 	// 	ExpiresAt: expiresAt,
// 	// }, nil
// }

// // CreatePublicShareLinkResult represents the result of creating public share link
// type CreatePublicShareLinkResult struct {
// 	ShareURL  string `json:"share_url"`
// 	ExpiresAt int64  `json:"expires_at"`
// }

// // GetPublicVideoDirect gets public video with direct parameters
// func (s *Service) GetPublicVideoDirect(ctx context.Context, shareToken string) (*GetPublicVideoResult, error) {
// 	video, err := s.db.GetVideoByShareToken(ctx, shareToken)
// 	if err != nil {
// 		return nil, fmt.Errorf("video not found or link invalid")
// 	}

// 	if video.ShareExpiresAt != nil && !video.ShareExpiresAt.IsZero() && time.Now().After(*video.ShareExpiresAt) {
// 		return nil, fmt.Errorf("link expired")
// 	}

// 	storagePath := video.StoragePath
// 	url, err := s.storage.GeneratePresignedDownloadURL(ctx, storagePath, 1*time.Hour)
// 	if err != nil {
// 		return nil, err
// 	}

// 	fileName := video.FileName
// 	fileSize := video.FileSizeBytes
// 	return &GetPublicVideoResult{
// 		FileName:    fileName,
// 		FileSize:    fileSize,
// 		DownloadURL: url,
// 		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
// 	}, nil
// }

// // GetPublicVideoResult represents the result of getting public video
// type GetPublicVideoResult struct {
// 	FileName    string `json:"file_name"`
// 	FileSize    int64  `json:"file_size"`
// 	DownloadURL string `json:"download_url"`
// 	ExpiresAt   int64  `json:"expires_at"`
// }

// // RevokeShareLinkDirect revokes share link with direct parameters
// func (s *Service) RevokeShareLinkDirect(ctx context.Context, userID, orgID, role, videoID string) error {
// 	video, err := s.db.GetVideo(ctx, videoID)
// 	if err != nil {
// 		return err
// 	}
// 	if video.OrgID != orgID {
// 		return fmt.Errorf("access denied")
// 	}

// 	// RBAC: User can only revoke own videos
// 	if rbac.Role(role) == rbac.RoleUser && video.UploadedBy != userID {
// 		return fmt.Errorf("access denied: can only revoke own videos")
// 	}

// 	video.PublicShareToken = nil
// 	video.ShareExpiresAt = nil

// 	return s.db.UpdateVideo(ctx, video)
// }

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
		fileName := v.FileName
		fileSizeBytes := v.FileSizeBytes
		durationSeconds := v.DurationSeconds
		uploadStatus := v.UploadStatus
		videoInfos[i] = &VideoInfo{
			VideoID:         v.VideoID,
			FileName:        fileName,
			FileSizeBytes:   fileSizeBytes,
			DurationSeconds: durationSeconds,
			UploadStatus:    uploadStatus,
			UploadedAt:      uploadedAt,
		}
	}

	return &SearchVideosResult{
		Videos:     videoInfos,
		TotalCount: total,
	}, nil
}

// GetPrivateDownloadURL генерирует временный URL для скачивания приватного видео
func (s *Service) GetPrivateDownloadURL(ctx context.Context, userID, orgID, videoID string) (*models.DownloadURLResult, error) {
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, fmt.Errorf("video not found")
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	// Генерируем временный URL на приватный bucket (1 час)
	url, err := s.storage.GeneratePresignedDownloadURL(ctx, video.StoragePath, 1*time.Hour)
	if err != nil {
		return nil, err
	}

	return &models.DownloadURLResult{
		DownloadURL: url,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}, nil
}

// PublishVideoToPublicBucket публикует видео в публичный bucket
func (s *Service) PublishVideoToPublicBucket(ctx context.Context, userID, orgID, role, videoID string) (*models.PublishVideoResult, error) {
	// Проверка прав - только admin и manager могут публиковать
	if rbac.Role(role) != rbac.RoleAdmin && rbac.Role(role) != rbac.RoleManager {
		return nil, fmt.Errorf("access denied: only admins and managers can publish")
	}

	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, fmt.Errorf("video not found")
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	// Проверяем, не опубликован ли уже
	if video.PublicURL != nil && *video.PublicURL != "" {
		return &models.PublishVideoResult{
			PublicURL: *video.PublicURL,
			Message:   "Video already published",
		}, nil
	}

	// Копируем файл в публичный bucket
	publicKey := fmt.Sprintf("public/%s/%s/%s", orgID, videoID, video.FileName)
	publicURL, err := s.storage.CopyToPublicBucket(ctx, video.StoragePath, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to publish video: %w", err)
	}

	// Сохраняем публичный URL в БД
	video.PublicURL = &publicURL
	video.PublishedAt = aws.Time(time.Now())
	video.PublishStatus = "published"
	if err := s.db.UpdateVideo(ctx, video); err != nil {
		return nil, fmt.Errorf("failed to update video record: %w", err)
	}

	return &models.PublishVideoResult{
		PublicURL: publicURL,
		Message:   "Video published successfully",
	}, nil
}

// generatePublicToken генерирует криптографически стойкий публичный токен
func generatePublicToken() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	// URL-safe base64 encoding
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	return token, nil
}

// PublishVideo публикует видео и создает публичный токен
func (s *Service) PublishVideo(ctx context.Context, userID, orgID, role, videoID string) (*models.PublishVideoResult, error) {
	// Проверка прав - только admin и manager могут публиковать
	if rbac.Role(role) != rbac.RoleAdmin && rbac.Role(role) != rbac.RoleManager {
		return nil, fmt.Errorf("access denied: only admins and managers can publish")
	}

	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, fmt.Errorf("video not found")
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	// Проверяем, что видео полностью загружено
	if video.UploadStatus != "completed" {
		return nil, fmt.Errorf("video upload not completed")
	}

	// 1. Проверяем, есть ли уже активный токен (Идемпотентность)
	existingShare, err := s.db.GetActivePublicVideoShare(ctx, videoID)
	if err == nil && existingShare != nil {
		publicURL := fmt.Sprintf("%s/api/v1/video/public?token=%s", s.baseURL, existingShare.PublicToken)
		return &models.PublishVideoResult{
			PublicURL:   publicURL,
			PublicToken: existingShare.PublicToken,
			Message:     "Video already published",
		}, nil
	}

	// Генерируем публичный токен
	publicToken, err := generatePublicToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate public token: %w", err)
	}

	// Создаем запись в public_video_shares
	shareID := uuid.New().String()
	now := time.Now()
	publicShare := &ydb.PublicVideoShare{
		ShareID:     shareID,
		VideoID:     videoID,
		PublicToken: publicToken,
		CreatedAt:   now,
		CreatedBy:   userID,
		Revoked:     false,
		AccessCount: 0,
	}

	if err := s.db.CreatePublicVideoShare(ctx, publicShare); err != nil {
		return nil, fmt.Errorf("failed to create public share: %w", err)
	}

	// Копируем видео в публичный bucket (если еще не скопировано)
	if video.PublicURL == nil || *video.PublicURL == "" {
		publicKey := fmt.Sprintf("public/%s/%s/%s", orgID, videoID, video.FileName)
		publicURL, err := s.storage.CopyToPublicBucket(ctx, video.StoragePath, publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to copy video to public bucket: %w", err)
		}

		// Обновляем видео с публичным URL
		video.PublicURL = &publicURL
		video.PublishedAt = aws.Time(now)
		video.PublishStatus = "published"
		if err := s.db.UpdateVideo(ctx, video); err != nil {
			return nil, fmt.Errorf("failed to update video record: %w", err)
		}
	}

	publicURL := fmt.Sprintf("%s/api/v1/video/public?token=%s", s.baseURL, publicToken)

	return &models.PublishVideoResult{
		PublicURL:   publicURL,
		PublicToken: publicToken,
		Message:     "Video published successfully",
	}, nil
}

// GetPublicVideo получает публичное видео по токену
func (s *Service) GetPublicVideo(ctx context.Context, token string) (*models.PublicVideoResponse, error) {
	// Получаем информацию о публичном шаринге
	publicShare, err := s.db.GetPublicVideoShareByToken(ctx, token)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("video not found or token is invalid")
		}
		return nil, fmt.Errorf("failed to get public share: %w", err)
	}

	// Проверяем, не отозван ли доступ
	if publicShare.Revoked {
		return nil, fmt.Errorf("public access to this video has been revoked")
	}

	// Получаем информацию о видео
	video, err := s.db.GetVideo(ctx, publicShare.VideoID)
	if err != nil {
		return nil, fmt.Errorf("failed to get video: %w", err)
	}

	// Генерируем временную ссылку на видео (presigned URL на 1 час)
	streamURL, err := s.GeneratePublicStreamURL(ctx, publicShare.VideoID, 1*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to generate stream URL: %w", err)
	}
	if err := s.db.IncrementAccessCount(ctx, token); err != nil {
		// Логируем ошибку, но НЕ прерываем выполнение, чтобы пользователь все равно получил видео
		// Используем slog, так как он инициализирован в проекте, вместо стандартного log
		slog.Error("Failed to increment access count", "error", err, "token", token)
	}

	// Подготавливаем ответ
	var uploadedAt int64
	if video.UploadedAt != nil {
		uploadedAt = video.UploadedAt.Unix()
	}
	displayTitle := video.Title
	if displayTitle == "" {
		displayTitle = video.FileName
	}
	response := &models.PublicVideoResponse{
		VideoID:         video.VideoID,
		Title:           displayTitle,
		Description:     "", // TODO: добавить description в Video
		FileName:        video.FileName,
		ThumbnailURL:    "", // TODO: генерировать thumbnail
		DurationSeconds: int(video.DurationSeconds),
		FileSizeBytes:   video.FileSizeBytes,
		StreamURL:       streamURL,
		ExpiresAt:       time.Now().Add(1 * time.Hour).Unix(),
		UploadedAt:      uploadedAt,
	}

	return response, nil
}

// GeneratePublicStreamURL генерирует presigned URL для публичного видео
func (s *Service) GeneratePublicStreamURL(ctx context.Context, videoID string, expiration time.Duration) (string, error) {
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return "", fmt.Errorf("failed to get video: %w", err)
	}

	// Генерируем ключ для публичного bucket
	publicKey := fmt.Sprintf("public/%s/%s/%s", video.OrgID, videoID, video.FileName)

	// Генерируем presigned URL
	url, err := s.storage.GeneratePresignedDownloadURL(ctx, publicKey, expiration)
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	return url, nil
}

// GetVideoForRevocation получает видео с полной информацией для отзыва публикации
func (s *Service) GetVideoForRevocation(ctx context.Context, userID, orgID, videoID string) (*ydb.Video, error) {
	// Проверка прав доступа
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, err
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	return video, nil
}

// RevokePublicShare отзывает публичный доступ к видео
func (s *Service) RevokePublicShare(ctx context.Context, userID, orgID, role, videoID string) error {
	// Проверка прав - только admin и manager могут отзывать
	if rbac.Role(role) != rbac.RoleAdmin && rbac.Role(role) != rbac.RoleManager {
		return fmt.Errorf("access denied: only admins and managers can revoke")
	}

	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return fmt.Errorf("video not found")
	}

	if video.OrgID != orgID {
		return fmt.Errorf("access denied")
	}

	// Проверяем, что видео опубликовано
	if video.PublishStatus != "published" {
		return fmt.Errorf("video is not published")
	}

	// Перемещаем видео из публичного bucket в приватный
	if video.PublicURL != nil && *video.PublicURL != "" {
		// Формируем ключи для публичного и приватного bucket
		publicKey := fmt.Sprintf("public/%s/%s/%s", orgID, videoID, video.FileName)
		privateKey := video.StoragePath

		// Копируем видео из публичного bucket в приватный (если еще не там)
		err = s.storage.CopyObject(ctx, s.storage.GetPublicBucket(), publicKey, s.storage.GetPrivateBucket(), privateKey)
		if err != nil {
			return fmt.Errorf("failed to copy video to private bucket: %w", err)
		}

		// Удаляем видео из публичного bucket
		err = s.storage.DeleteObject(ctx, s.storage.GetPublicBucket(), publicKey)
		if err != nil {
			// Логируем ошибку, но продолжаем, так как видео уже скопировано
			log.Printf("Failed to delete video from public bucket: %v", err)
		}
	}

	// Обновляем статус видео в БД
	err = s.db.UpdateVideoStatus(ctx, videoID, "private", "")
	if err != nil {
		return fmt.Errorf("failed to update video status: %w", err)
	}

	// Отзываем все публичные шаринги для этого видео
	return s.db.RevokePublicVideoShare(ctx, videoID, userID)
}
