package video

import (
	"context"
	"testing"
	"time"

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
	baseURL := "https://api.test.com"

	service := NewService(mockDB, mockStorage, realRBAC, baseURL)
	return service, mockDB, mockStorage
}

func TestService_InitiateMultipartUpload_StorageLimitExceeded(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	fileSize := int64(20 * 1024 * 1024) // 20 MB

	// 1. Получение подписки (Лимит 100 МБ)
	mockDB.On("GetSubscriptionByUser", ctx, userID).Return(&ydb.Subscription{
		StorageLimitMB: 100,
	}, nil)

	// 2. Получение текущего использования (Занято 90 МБ)
	currentUsage := int64(90 * 1024 * 1024)
	mockDB.On("GetStorageUsage", ctx, orgID).Return(currentUsage, nil)

	// Act
	// 90 + 20 = 110 > 100 -> Ошибка
	resp, err := service.InitiateMultipartUploadDirect(ctx, userID, orgID, "Title", "video.mp4", fileSize, 60)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "storage limit exceeded", err.Error())

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
		StoragePath:  "videos/org-1/video-123/file.mp4",
		UploadID:     "upload-id-s3",
		IsDeleted:    false,
		UploadStatus: "pending",
	}, nil)

	// 2. Генерация ссылок в S3 (вызывается 2 раза для 2 частей)
	mockStorage.On("GeneratePresignedPartURL", ctx, "videos/org-1/video-123/file.mp4", "upload-id-s3", int32(1), time.Hour).Return("https://s3.com/part1", nil)
	mockStorage.On("GeneratePresignedPartURL", ctx, "videos/org-1/video-123/file.mp4", "upload-id-s3", int32(2), time.Hour).Return("https://s3.com/part2", nil)

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
