package video

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/config"
	app_errors "github.com/lumiforge/sellerproof-backend/internal/errors"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/storage"
	"github.com/lumiforge/sellerproof-backend/internal/validation"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

type Service struct {
	db      ydb.Database
	storage storage.StorageProvider
	rbac    *rbac.RBAC
	config  *config.Config
}

func NewService(db ydb.Database, storage storage.StorageProvider, rbac *rbac.RBAC, cfg *config.Config) *Service {
	return &Service{
		db:      db,
		storage: storage,
		rbac:    rbac,
		config:  cfg,
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
	AuthorName      string `json:"author_name"`
	FileName        string `json:"file_name"`
	FileSizeBytes   int64  `json:"file_size_bytes"`
	DurationSeconds int32  `json:"duration_seconds"`
	UploadStatus    string `json:"upload_status"`
	PublishStatus   string `json:"publish_status"`
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

// InitiateMultipartUploadDirect initiates multipart upload with direct parameters
func (s *Service) InitiateMultipartUploadDirect(ctx context.Context, userID, orgID, title, fileName string, fileSizeBytes int64, durationSeconds int32) (*InitiateMultipartUploadResult, error) {

	// Получаем организацию для определения владельца
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetOrganizationInfo
	}

	// Проверка квоты
	sub, err := s.db.GetSubscriptionByUser(ctx, org.OwnerID)
	if err != nil {

		return nil, app_errors.ErrFailedToGetSubscription
	}
	// Check VideoLimitMB
	limitBytes := sub.VideoLimitMB * 1024 * 1024
	if fileSizeBytes > limitBytes {
		return nil, app_errors.ErrVideoSizeLimitExceeded
	}
	// TODO Race Condition при проверке квоты хранилища
	videoCount, err := s.db.GetStorageUsage(ctx, org.OwnerID, sub.StartedAt)
	if err != nil {

		return nil, app_errors.ErrFailedToGetStorageUsage
	}

	if sub.OrdersPerMonthLimit > 0 && videoCount >= sub.OrdersPerMonthLimit {
		return nil, fmt.Errorf("video count limit exceeded")
	}

	videoID := uuid.New().String()
	objectKey := fmt.Sprintf("videos/%s/%s/%s", orgID, videoID, fileName)

	contentType := validation.GetContentTypeFromExtension(fileName)

	if contentType == "" || !validation.IsVideoContentType(contentType) {
		return nil, app_errors.ErrInvalidFileType
	}

	// Determine bucket based on plan
	bucket := s.config.SPObjStoreBucketStart // Default fallback
	switch sub.PlanID {
	case "pro":
		bucket = s.config.SPObjStoreBucketPro
	case "business":
		bucket = s.config.SPObjStoreBucketBusiness
	case "start":
		bucket = s.config.SPObjStoreBucketStart
	}

	uploadID, err := s.storage.InitiateMultipartUpload(ctx, bucket, objectKey, contentType)
	if err != nil {

		return nil, app_errors.ErrFailedToInitiateS3Upload
	}

	fileNameSearch := strings.ToLower(fileName)
	uploadStatus := "pending"

	createdAt := time.Now()
	ttl := createdAt.Add(24 * time.Hour)
	video := &ydb.Video{
		VideoID:         videoID,
		OrgID:           orgID,
		UploadedBy:      userID,
		Title:           title,
		FileName:        fileName,
		FileNameSearch:  fileNameSearch,
		FileSizeBytes:   fileSizeBytes,
		StoragePath:     objectKey,
		DurationSeconds: durationSeconds,
		UploadID:        uploadID,
		UploadStatus:    uploadStatus,
		PublishStatus:   "private",
		CreatedAt:       createdAt,
		UploadExpiresAt: &ttl,
		BucketName:      bucket,
	}

	if err := s.db.CreateVideo(ctx, video); err != nil {

		return nil, app_errors.ErrFailedToCreateVideoRecord
	}

	return &InitiateMultipartUploadResult{
		VideoID:               videoID,
		UploadID:              uploadID,
		RecommendedPartSizeMB: s.config.RecommendedPartSizeMB,
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
			return nil, app_errors.ErrVideoNotFound
		}
		return nil, fmt.Errorf("video not found %w", err)
	}

	if video.OrgID != orgID {
		return nil, app_errors.ErrAccessDenied
	}

	// Security fix: Only the uploader can generate upload urls
	if video.UploadedBy != userID {
		return nil, app_errors.ErrUploaderOnlyCanGenUploadURLs
	}

	if video.UploadStatus == "completed" {
		return nil, app_errors.ErrVideoUploadAlreadyCompleted
	}

	urls := make([]string, totalParts)
	for i := 0; i < int(totalParts); i++ {
		storagePath := video.StoragePath
		uploadID := video.UploadID
		url, err := s.storage.GeneratePresignedPartURL(ctx, video.BucketName, storagePath, uploadID, int32(i+1), 1*time.Hour)
		if err != nil {
			return nil, app_errors.ErrFailedToGenerateURLForPart
		}
		urls[i] = url
	}

	video.TotalParts = &totalParts
	uploadStatus := "uploading"
	video.UploadStatus = uploadStatus
	if err := s.db.UpdateVideo(ctx, video); err != nil {
		return nil, app_errors.ErrFailedToUpdateVideoStatus
	}

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
		return nil, app_errors.ErrVideoNotFound
	}

	// Проверка UploadedBy вместо OrgID позволяет завершить загрузку своего видео
	// даже если он переключил активную организацию
	// При этом это защищает от доступа к чужим видео
	if video.UploadedBy != userID {
		return nil, app_errors.ErrAccessDenied
	}

	// Если видео уже загружено, не идем в S3, а возвращаем успех.
	if video.UploadStatus == "completed" {
		url, _ := s.storage.GeneratePresignedDownloadURL(ctx, video.BucketName, video.StoragePath, 1*time.Hour)
		return &CompleteMultipartUploadResult{
			Message:  "Upload already completed",
			VideoURL: url,
		}, nil
	}

	// S3 требует, чтобы части были отсортированы по возрастанию номера
	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})

	s3Parts := make([]types.CompletedPart, len(parts))
	for i, p := range parts {
		s3Parts[i] = types.CompletedPart{
			ETag:       aws.String(p.ETag),
			PartNumber: aws.Int32(p.PartNumber),
		}
	}

	storagePath := video.StoragePath
	uploadID := video.UploadID
	if err := s.storage.CompleteMultipartUpload(ctx, video.BucketName, storagePath, uploadID, s3Parts); err != nil {
		return nil, app_errors.ErrFailedToCompleteS3Upload
	}
	headerBytes, err := s.storage.GetObjectHeader(ctx, video.BucketName, storagePath)
	if err != nil {
		slog.Error("Failed to get object header for verification", "error", err, "video_id", videoID)
		// В случае ошибки чтения S3 лучше прервать процесс, чем пропустить потенциально опасный файл
		return nil, app_errors.ErrFailedToVerifyFileIntegrity
	}
	// Определяем реальный тип контента
	detectedType := http.DetectContentType(headerBytes)

	// http.DetectContentType определяет только ограниченный набор типов.
	// Если тип video/* - доверяем (Go stdlib проверяет сигнатуры для них).
	// Если application/octet-stream - проверяем магические байты вручную.

	isValidVideo := strings.HasPrefix(detectedType, "video/")

	if detectedType == "application/octet-stream" {
		// Проверяем сигнатуры популярных видео-форматов
		if len(headerBytes) >= 12 {
			// MP4/MOV/3GP (обычно содержат 'ftyp' с 4 по 8 байт)
			if string(headerBytes[4:8]) == "ftyp" {
				isValidVideo = true
			}
			// AVI (RIFF .... AVI )
			if string(headerBytes[:4]) == "RIFF" && string(headerBytes[8:12]) == "AVI " {
				isValidVideo = true
			}
		}
		// MKV / WebM (0x1A 0x45 0xDF 0xA3)
		if len(headerBytes) >= 4 && bytes.Equal(headerBytes[:4], []byte{0x1A, 0x45, 0xDF, 0xA3}) {
			isValidVideo = true
		}
		// MPEG-TS (Sync byte 0x47)
		if len(headerBytes) > 0 && headerBytes[0] == 0x47 {
			isValidVideo = true
		}
	}

	// Дополнительная защита: Явный запрет исполняемых файлов (MZ, ELF, Mach-O, Scripts)
	// Даже если каким-то образом они прошли проверку выше (маловероятно), блокируем их.
	if len(headerBytes) >= 4 {
		// Windows PE (EXE, DLL)
		if string(headerBytes[:2]) == "MZ" {
			isValidVideo = false
		}
		// Linux ELF
		if string(headerBytes[:4]) == "\x7fELF" {
			isValidVideo = false
		}
		// Mach-O (macOS) - различные варианты magic bytes
		if bytes.Equal(headerBytes[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}) ||
			bytes.Equal(headerBytes[:4], []byte{0xfe, 0xed, 0xfa, 0xce}) ||
			bytes.Equal(headerBytes[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) {
			isValidVideo = false
		}
		// Shell scripts / XML / HTML
		if strings.HasPrefix(strings.TrimSpace(string(headerBytes)), "<!") ||
			strings.HasPrefix(strings.TrimSpace(string(headerBytes)), "<?xml") ||
			strings.HasPrefix(strings.TrimSpace(string(headerBytes)), "#!") {
			isValidVideo = false
		}
	}

	if !isValidVideo {
		slog.Warn("Malicious file upload attempt detected",
			"user_id", userID,
			"video_id", videoID,
			"detected_type", detectedType,
			"claimed_filename", video.FileName)

		// Удаляем файл из S3
		if err := s.storage.CleanupObject(ctx, video.BucketName, storagePath); err != nil {
			slog.Error("Failed to delete malicious file", "error", err)
		}

		// Помечаем как failed (не перемещаем в корзину, так как корзины нет)
		video.UploadStatus = "failed"

		return nil, app_errors.ErrInvalidFileContent
	}

	// Размер файла
	actualSize, err := s.storage.GetObjectSize(ctx, video.BucketName, storagePath)

	if err != nil {
		slog.Error("Failed to get object size after upload", "error", err, "video_id", videoID)
		return nil, app_errors.ErrFailedToVerifyUploadIntegrity
	}

	// Получаем организацию для определения владельца
	org, err := s.db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetOrganizationInfo
	}

	// Подписка
	sub, err := s.db.GetSubscriptionByUser(ctx, org.OwnerID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetSubscription
	}

	// Check VideoLimitMB
	limitBytes := sub.VideoLimitMB * 1024 * 1024
	if actualSize > limitBytes {
		slog.Error("Video size limit exceeded", "user_id", userID, "video_id", videoID, "size", actualSize, "limit", limitBytes)
		_ = s.storage.CleanupObject(ctx, video.BucketName, storagePath)
		return nil, app_errors.ErrVideoSizeLimitExceeded
	}

	videoCount, err := s.db.GetStorageUsage(ctx, org.OwnerID, sub.StartedAt)
	if err != nil {
		return nil, app_errors.ErrFailedToGetStorageUsage
	}

	if sub.OrdersPerMonthLimit > 0 && videoCount >= sub.OrdersPerMonthLimit {
		return nil, fmt.Errorf("video count limit exceeded")
	}

	// Обновляем размер файла в БД на реальный
	video.FileSizeBytes = actualSize

	uploadStatus := "completed"
	video.UploadStatus = uploadStatus
	now := time.Now()
	video.UploadedAt = &now
	// Сбрасываем TTL, чтобы видео не удалилось
	video.UploadExpiresAt = nil
	if err := s.db.UpdateVideo(ctx, video); err != nil {
		slog.Error("Failed to update video status in DB, rolling back S3 upload", "error", err, "video_id", videoID)
		if delErr := s.storage.CleanupObject(ctx, video.BucketName, storagePath); delErr != nil {
			// Если не удалось удалить файл, логируем это как критическую ошибку,
			// так как теперь у нас есть файл, занимающий место.
			slog.Error("CRITICAL: Failed to rollback S3 object after DB failure", "error", delErr, "path", storagePath)
		}
		return nil, app_errors.ErrFailedToUpdateVideoStatus
	}

	url, _ := s.storage.GeneratePresignedDownloadURL(ctx, video.BucketName, video.StoragePath, 1*time.Hour)

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
func (s *Service) GetVideoDirect(ctx context.Context, userID, orgID, role, videoID string) (*VideoInfo, error) {
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, err
	}
	if video.OrgID != orgID {
		return nil, app_errors.ErrAccessDenied
	}

	if rbac.Role(role) == rbac.RoleUser && video.UploadedBy != userID {
		return nil, app_errors.ErrAccessDenied
	}

	user, err := s.db.GetUserByID(ctx, video.UploadedBy)
	authorName := ""
	if err == nil {
		authorName = user.FullName
	}

	var uploadedAt int64
	if video.UploadedAt != nil {
		uploadedAt = video.UploadedAt.Unix()
	}
	fileName := video.FileName
	fileSizeBytes := video.FileSizeBytes
	durationSeconds := video.DurationSeconds
	uploadStatus := video.UploadStatus
	publishStatus := video.PublishStatus
	return &VideoInfo{
		VideoID:         video.VideoID,
		Title:           video.Title,
		AuthorName:      authorName,
		FileName:        fileName,
		FileSizeBytes:   fileSizeBytes,
		DurationSeconds: durationSeconds,
		UploadStatus:    uploadStatus,
		PublishStatus:   publishStatus,
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
		return nil, app_errors.ErrAccessDenied
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
	userNames := make(map[string]string)
	for i, v := range videos {
		var uploadedAt int64
		if v.UploadedAt != nil {
			uploadedAt = v.UploadedAt.Unix()
		}
		fileName := v.FileName
		fileSizeBytes := v.FileSizeBytes
		durationSeconds := v.DurationSeconds
		uploadStatus := v.UploadStatus
		publishStatus := v.PublishStatus

		authorName := ""
		if name, ok := userNames[v.UploadedBy]; ok {
			authorName = name
		} else {
			if user, err := s.db.GetUserByID(ctx, v.UploadedBy); err == nil {
				authorName = user.FullName
			}
			userNames[v.UploadedBy] = authorName
		}

		videoInfos[i] = &VideoInfo{
			VideoID:         v.VideoID,
			Title:           v.Title,
			AuthorName:      authorName,
			FileName:        fileName,
			FileSizeBytes:   fileSizeBytes,
			DurationSeconds: durationSeconds,
			UploadStatus:    uploadStatus,
			PublishStatus:   publishStatus,
			UploadedAt:      uploadedAt,
		}
	}

	return &SearchVideosResult{
		Videos:     videoInfos,
		TotalCount: total,
	}, nil
}

// GetPrivateDownloadURL генерирует временный URL для скачивания приватного видео
func (s *Service) GetPrivateDownloadURL(ctx context.Context, userID, orgID, role, videoID string) (*models.DownloadURLResult, error) {
	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, app_errors.ErrVideoNotFound
	}

	if video.OrgID != orgID {
		return nil, app_errors.ErrAccessDenied
	}

	if rbac.Role(role) == rbac.RoleUser && video.UploadedBy != userID {
		return nil, app_errors.ErrAccessDenied
	}

	// Генерируем временный URL на приватный bucket (1 час)
	url, err := s.storage.GeneratePresignedDownloadURL(ctx, video.BucketName, video.StoragePath, 1*time.Hour)
	if err != nil {
		return nil, err
	}

	return &models.DownloadURLResult{
		DownloadURL: url,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}, nil
}

// PublishVideoToPublicBucket публикует видео в публичный bucket
// func (s *Service) PublishVideoToPublicBucket(ctx context.Context, userID, orgID, role, videoID string) (*models.PublishVideoResult, error) {
// 	// Проверка прав - только admin и manager могут публиковать
// 	if rbac.Role(role) != rbac.RoleAdmin && rbac.Role(role) != rbac.RoleManager {
// 		return nil, app_errors.ErrOnlyAdminsAndManagersCanPublish
// 	}

// 	video, err := s.db.GetVideo(ctx, videoID)
// 	if err != nil {
// 		return nil, app_errors.ErrVideoNotFound
// 	}

// 	if video.OrgID != orgID {
// 		return nil, app_errors.ErrAccessDenied
// 	}

// 	// Проверяем, не опубликован ли уже
// 	if video.PublicURL != nil && *video.PublicURL != "" {
// 		return &models.PublishVideoResult{
// 			PublicURL: *video.PublicURL,
// 			Message:   "Video already published",
// 		}, nil
// 	}

// 	// Копируем файл в публичный bucket
// 	publicKey := fmt.Sprintf("public/%s/%s/%s", orgID, videoID, video.FileName)
// 	publicURL, err := s.storage.CopyToPublicBucket(ctx, video.StoragePath, publicKey)
// 	if err != nil {
// 		return nil, app_errors.ErrFailedToPublishVideo
// 	}

// 	// Сохраняем публичный URL в БД
// 	video.PublicURL = &publicURL
// 	video.PublishedAt = aws.Time(time.Now())
// 	video.PublishStatus = "published"
// 	if err := s.db.UpdateVideo(ctx, video); err != nil {
// 		return nil, app_errors.ErrFailedToUpdateVideoRecord
// 	}

// 	return &models.PublishVideoResult{
// 		PublicURL: publicURL,
// 		Message:   "Video published successfully",
// 	}, nil
// }

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
		return nil, app_errors.ErrOnlyAdminsAndManagersCanPublish
	}

	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return nil, app_errors.ErrVideoNotFound
	}

	if video.OrgID != orgID {
		return nil, app_errors.ErrAccessDenied
	}

	// Проверяем, что видео полностью загружено
	if video.UploadStatus != "completed" {
		return nil, app_errors.ErrVideoUploadNotCompleted
	}

	// 1. Проверяем, есть ли уже активный токен (Идемпотентность)
	existingShare, err := s.db.GetActivePublicVideoShare(ctx, videoID)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return nil, app_errors.ErrFailedToCheckActiveShare
	}
	if existingShare != nil {
		publicURL := fmt.Sprintf("%s/api/v1/video/public?token=%s", s.config.APIBaseURL, existingShare.PublicToken)
		return &models.PublishVideoResult{
			PublicURL:   publicURL,
			PublicToken: existingShare.PublicToken,
			Message:     "Video already published",
		}, nil
	}

	// 2. ПРОВЕРКА КВОТЫ
	// Если видео еще не опубликовано, публикация создаст копию, занимающую место.
	if video.PublishStatus != "published" {
		// Получаем организацию для определения владельца
		org, err := s.db.GetOrganizationByID(ctx, orgID)
		if err != nil {
			return nil, app_errors.ErrFailedToGetOrganizationInfo
		}

		sub, err := s.db.GetSubscriptionByUser(ctx, org.OwnerID)
		if err != nil {
			return nil, app_errors.ErrFailedToGetSubscription
		}

		// In the new model, we don't check storage size limit for publishing
		// We only check if the user is allowed to publish (which is covered by RBAC)
		// and if the video exists and is uploaded.
		_, err = s.db.GetStorageUsage(ctx, org.OwnerID, sub.StartedAt)
		if err != nil {
			return nil, app_errors.ErrFailedToGetStorageUsage
		}

	}

	// 4. Подготовка данных для БД
	publicToken, err := generatePublicToken()
	if err != nil {
		return nil, app_errors.ErrFailedToGeneratePublicToken
	}

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

	// 5. Транзакционное сохранение в БД (Fix for Data Consistency: Atomic DB update)
	// TODO Race Condition
	// We don't have a static S3 public URL anymore, so we pass empty string or API URL.
	// Let's pass the API URL as public_url for consistency.
	apiPublicURL := fmt.Sprintf("%s/api/v1/video/public?token=%s", s.config.APIBaseURL, publicToken)
	err = s.db.PublishVideoTx(ctx, publicShare, videoID, apiPublicURL, "published")
	if err != nil {
		return nil, app_errors.ErrFailedToPublishVideoRecord
	}

	// Формируем ссылку для ответа API
	apiPublicURL = fmt.Sprintf("%s/api/v1/video/public?token=%s", s.config.APIBaseURL, publicToken)

	return &models.PublishVideoResult{
		PublicURL:   apiPublicURL,
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
			return nil, app_errors.ErrVideoNotFoundOrTokenInvalid
		}
		return nil, app_errors.ErrFailedToGetPublicShare
	}

	// Проверяем, не отозван ли доступ
	if publicShare.Revoked {
		return nil, app_errors.ErrPublicAccessRevoked
	}

	// Получаем информацию о видео
	video, err := s.db.GetVideo(ctx, publicShare.VideoID)
	if err != nil {
		return nil, app_errors.ErrFailedToGetVideo
	}

	// Генерируем временную ссылку на видео (presigned URL на 1 час)
	streamURL, err := s.GeneratePublicStreamURL(ctx, publicShare.VideoID, 1*time.Hour)
	if err != nil {
		return nil, app_errors.ErrFailedToGenerateStreamURL
	}

	// TODO Potentially DoS: Increment access count for each download
	// TODO: Safeguard against DoS will be added on proxy server (share.sellerproof.ru)
	if err := s.db.IncrementAccessCount(ctx, token); err != nil {
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
		return "", app_errors.ErrFailedToGetVideo
	}

	// Генерируем ключ для публичного bucket
	// _ := fmt.Sprintf("public/%s/%s/%s", video.OrgID, videoID, video.FileName)

	// Генерируем presigned URL
	url, err := s.storage.GeneratePresignedDownloadURL(ctx, video.BucketName, video.StoragePath, expiration)
	if err != nil {
		return "", app_errors.ErrFailedToGeneratePresignedURL
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
		return nil, app_errors.ErrAccessDenied
	}

	return video, nil
}

// RevokePublicShare отзывает публичный доступ к видео
func (s *Service) RevokePublicShare(ctx context.Context, userID, orgID, role, videoID string) error {
	// Проверка прав - только admin и manager могут отзывать
	if rbac.Role(role) != rbac.RoleAdmin && rbac.Role(role) != rbac.RoleManager {
		return app_errors.ErrOnlyAdminsAndManagersCanRevoke
	}

	video, err := s.db.GetVideo(ctx, videoID)
	if err != nil {
		return app_errors.ErrVideoNotFound
	}

	if video.OrgID != orgID {
		return app_errors.ErrAccessDenied
	}

	// Проверяем, что видео опубликовано
	if video.PublishStatus != "published" {
		return app_errors.ErrVideoNotPublished
	}

	// Обновляем статус видео в БД
	err = s.db.UpdateVideoStatus(ctx, videoID, "private", "")
	if err != nil {
		return app_errors.ErrFailedToUpdateVideoStatus
	}

	// Отзываем все публичные шаринги для этого видео
	return s.db.RevokePublicVideoShare(ctx, videoID, userID)
}
