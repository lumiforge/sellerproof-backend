package video

import (
	"context"
	"testing"
	"time"

	"github.com/lumiforge/sellerproof-backend/internal/config"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	storagemocks "github.com/lumiforge/sellerproof-backend/internal/storage/mocks"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
	ydbmocks "github.com/lumiforge/sellerproof-backend/internal/ydb/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupVideoService() (*Service, *ydbmocks.Database, *storagemocks.StorageProvider) {
	mockDB := new(ydbmocks.Database)
	mockStorage := new(storagemocks.StorageProvider)
	realRBAC := rbac.NewRBAC()
	cfg := &config.Config{
		APIBaseURL:            "https://api.test.com",
		SPObjStoreBucketStart: "free-bucket",
		SPObjStoreBucketPro:   "pro-bucket",
		// MaxVideoFileSizeMB:    2000,
	}

	service := NewService(mockDB, mockStorage, realRBAC, cfg)
	return service, mockDB, mockStorage
}

func TestService_InitiateMultipartUpload_VideoCountLimitExceeded(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	fileSize := int64(10 * 1024 * 1024)
	now := time.Now()

	// 0. Получение организации
	mockDB.On("GetOrganizationByID", ctx, orgID).Return(&ydb.Organization{OwnerID: userID}, nil)

	// 1. Получение подписки (Лимит 5 видео)
	mockDB.On("GetSubscriptionByUser", ctx, userID).Return(&ydb.Subscription{
		// VideoLimitMB:        100,
		OrdersPerMonthLimit: 5,
		PlanID:              "start",
		StartedAt:           now,
		ExpiresAt:           now.Add(24 * time.Hour),
	}, nil)

	// 2. Получение текущего использования (Уже 5 видео)
	mockDB.On("GetStorageUsage", ctx, userID, now).Return(int64(5), nil)

	// 5 >= 5 -> Ошибка
	resp, err := service.InitiateMultipartUploadDirect(ctx, userID, orgID, "Title", "video.mp4", fileSize, 60)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "video count limit exceeded", err.Error())

	mockDB.AssertExpectations(t)
}

func TestService_GetPartUploadURLs_Success(t *testing.T) {
	service, mockDB, mockStorage := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	videoID := "video-123"
	totalParts := int32(2)

	// 1. Получение видео
	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:      videoID,
		OrgID:        orgID,
		UploadedBy:   userID,
		BucketName:   "free-bucket",
		StoragePath:  "videos/org-1/video-123/file.mp4",
		UploadID:     "upload-id-s3",
		UploadStatus: "pending",
	}, nil)

	// 2. Генерация ссылок в S3 (вызывается 2 раза для 2 частей)
	mockStorage.On("GeneratePresignedPartURL", ctx, "free-bucket", "videos/org-1/video-123/file.mp4", "upload-id-s3", int32(1), time.Hour).Return("https://s3.com/part1", nil)
	mockStorage.On("GeneratePresignedPartURL", ctx, "free-bucket", "videos/org-1/video-123/file.mp4", "upload-id-s3", int32(2), time.Hour).Return("https://s3.com/part2", nil)

	// 3. Обновление статуса видео
	mockDB.On("UpdateVideo", ctx, mock.MatchedBy(func(v *ydb.Video) bool {
		return v.UploadStatus == "uploading" && *v.TotalParts == 2
	})).Return(nil)

	// Act
	resp, err := service.GetPartUploadURLsDirect(ctx, userID, orgID, videoID, totalParts)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.PartURLs, 2)
	assert.Equal(t, "https://s3.com/part1", resp.PartURLs[0])
	assert.Equal(t, "https://s3.com/part2", resp.PartURLs[1])

	mockDB.AssertExpectations(t)
	mockStorage.AssertExpectations(t)
}

func TestService_CompleteMultipartUpload_MaliciousFile(t *testing.T) {
	service, mockDB, mockStorage := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	videoID := "video-malicious"
	storagePath := "videos/org-1/video-malicious/file.mp4"

	// 1. Получение видео
	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:      videoID,
		OrgID:        orgID,
		UploadedBy:   userID,
		BucketName:   "free-bucket",
		StoragePath:  storagePath,
		UploadID:     "upload-id",
		UploadStatus: "uploading",
		FileName:     "file.mp4",
	}, nil)

	// 2. Завершение загрузки в S3 (успешно)
	mockStorage.On("CompleteMultipartUpload", ctx, "free-bucket", storagePath, "upload-id", mock.Anything).Return(nil)

	// 3. Проверка Magic Bytes: возвращаем заголовок EXE файла (MZ...)
	maliciousHeader := []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
	mockStorage.On("GetObjectHeader", ctx, "free-bucket", storagePath).Return(maliciousHeader, nil)

	// 4. Ожидаем удаление файла из S3
	mockStorage.On("CleanupObject", ctx, "free-bucket", storagePath).Return(nil)

	// Act
	parts := []CompletedPart{{PartNumber: 1, ETag: "etag1"}}
	resp, err := service.CompleteMultipartUploadDirect(ctx, userID, orgID, videoID, parts)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid file content")

	mockDB.AssertExpectations(t)
	mockStorage.AssertExpectations(t)
}

func TestService_CompleteMultipartUpload_Success(t *testing.T) {
	service, mockDB, mockStorage := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	videoID := "video-ok"
	storagePath := "videos/org-1/video-ok/file.mp4"
	now := time.Now()

	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:       videoID,
		OrgID:         orgID,
		UploadedBy:    userID,
		BucketName:    "free-bucket",
		StoragePath:   storagePath,
		UploadID:      "upload-id",
		UploadStatus:  "uploading",
		FileName:      "file.mp4",
		FileSizeBytes: 1024,
	}, nil)

	mockStorage.On("CompleteMultipartUpload", ctx, "free-bucket", storagePath, "upload-id", mock.Anything).Return(nil)
	// Valid MP4
	mockStorage.On("GetObjectHeader", ctx, "free-bucket", storagePath).Return([]byte{0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'm', 'p', '4', '2'}, nil)
	mockStorage.On("GetObjectSize", ctx, "free-bucket", storagePath).Return(int64(1024), nil)
	mockDB.On("GetOrganizationByID", ctx, orgID).Return(&ydb.Organization{OwnerID: userID}, nil)
	mockDB.On("GetSubscriptionByUser", ctx, userID).Return(&ydb.Subscription{VideoLimitMB: 100, StartedAt: now}, nil)
	mockDB.On("GetStorageUsage", ctx, userID, now).Return(int64(0), nil)

	// Update DB success
	mockDB.On("UpdateVideo", ctx, mock.MatchedBy(func(v *ydb.Video) bool {
		return v.UploadStatus == "completed" && v.UploadedAt != nil
	})).Return(nil)

	// Generate URL
	mockStorage.On("GeneratePresignedDownloadURL", ctx, "free-bucket", storagePath, time.Hour).Return("https://s3/video.mp4", nil)

	// Act
	parts := []CompletedPart{{PartNumber: 1, ETag: "etag1"}}
	resp, err := service.CompleteMultipartUploadDirect(ctx, userID, orgID, videoID, parts)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "https://s3/video.mp4", resp.VideoURL)
}

func TestService_PublishVideo_AccessDenied_UserRole(t *testing.T) {
	service, _, _ := setupVideoService()
	ctx := context.Background()

	// Act: Обычный юзер пытается опубликовать
	resp, err := service.PublishVideo(ctx, "user-1", "org-1", "user", "video-1")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "only admins and managers can publish")
}

func TestService_PublishVideo_Idempotency(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "admin-1"
	orgID := "org-1"
	videoID := "video-published"

	// 1. Видео найдено и принадлежит организации
	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:      videoID,
		OrgID:        orgID,
		UploadStatus: "completed",
	}, nil)

	// 2. Уже есть активный шаринг
	existingShare := &ydb.PublicVideoShare{
		PublicToken: "existing-token-123",
	}
	mockDB.On("GetActivePublicVideoShare", ctx, videoID).Return(existingShare, nil)

	// Act
	resp, err := service.PublishVideo(ctx, userID, orgID, "admin", videoID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "existing-token-123", resp.PublicToken)
	assert.Equal(t, "Video already published", resp.Message)
	// Важно: методы storage (CopyToPublicBucket) не должны вызываться
	mockDB.AssertExpectations(t)
}

func TestService_GetVideoDirect_Success(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	videoID := "video-1"

	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:       videoID,
		OrgID:         orgID,
		UploadedBy:    userID,
		BucketName:    "free-bucket",
		Title:         "Test Video",
		FileName:      "video.mp4",
		FileSizeBytes: 1024,
		UploadStatus:  "completed",
		PublishStatus: "published",
	}, nil)
	mockDB.On("GetUserByID", ctx, userID).Return(&ydb.User{FullName: "Test User"}, nil)

	info, err := service.GetVideoDirect(ctx, userID, orgID, "user", videoID)

	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "published", info.PublishStatus)
	assert.Equal(t, "Test User", info.AuthorName)
	mockDB.AssertExpectations(t)
}

func TestService_SearchVideosDirect_Success(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	role := "user"
	query := "test"

	// Mock SearchVideos
	videos := []*ydb.Video{
		{
			VideoID:       "v1",
			Title:         "Video 1",
			UploadedBy:    userID,
			FileSizeBytes: 100,
		},
		{
			VideoID:       "v2",
			Title:         "Video 2",
			UploadedBy:    "user-2",
			FileSizeBytes: 200,
		},
	}
	mockDB.On("SearchVideos", ctx, orgID, userID, query, 10, 0).Return(videos, int64(2), nil)

	// Mock GetUserByID for user-1
	mockDB.On("GetUserByID", ctx, userID).Return(&ydb.User{FullName: "User One"}, nil)
	// Mock GetUserByID for user-2
	mockDB.On("GetUserByID", ctx, "user-2").Return(&ydb.User{FullName: "User Two"}, nil)

	// Act
	result, err := service.SearchVideosDirect(ctx, userID, orgID, role, query, 1, 10)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, int64(2), result.TotalCount)
	assert.Equal(t, "User One", result.Videos[0].AuthorName)
	assert.Equal(t, "User Two", result.Videos[1].AuthorName)
	mockDB.AssertExpectations(t)
}
