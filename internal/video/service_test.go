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

	// 0. Получение организации
	mockDB.On("GetOrganizationByID", ctx, orgID).Return(&ydb.Organization{OwnerID: userID}, nil)

	// 1. Получение подписки (Лимит 100 МБ)
	mockDB.On("GetSubscriptionByUser", ctx, userID).Return(&ydb.Subscription{
		StorageLimitMB:  100,
		VideoCountLimit: 100,
	}, nil)

	// 2. Получение текущего использования (Занято 90 МБ)
	currentUsage := int64(90 * 1024 * 1024)
	mockDB.On("GetStorageUsage", ctx, userID).Return(currentUsage, int64(5), nil)

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
		StoragePath:  storagePath,
		UploadID:     "upload-id",
		UploadStatus: "uploading",
		FileName:     "file.mp4",
	}, nil)

	// 2. Завершение загрузки в S3 (успешно)
	mockStorage.On("CompleteMultipartUpload", ctx, storagePath, "upload-id", mock.Anything).Return(nil)

	// 3. Проверка Magic Bytes: возвращаем заголовок EXE файла (MZ...)
	maliciousHeader := []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
	mockStorage.On("GetObjectHeader", ctx, storagePath).Return(maliciousHeader, nil)

	// 4. Ожидаем удаление файла из S3
	mockStorage.On("DeletePrivateObject", ctx, storagePath).Return(nil)

	// 5. Ожидаем перемещение в корзину
	mockDB.On("MoveVideoToTrash", ctx, videoID).Return(nil)

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

func TestService_CompleteMultipartUpload_QuotaExceededPostUpload(t *testing.T) {
	service, mockDB, mockStorage := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	videoID := "video-quota"
	storagePath := "videos/org-1/video-quota/file.mp4"

	// 1. Получение видео (заявленный размер 10 МБ)
	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:       videoID,
		OrgID:         orgID,
		UploadedBy:    userID,
		StoragePath:   storagePath,
		UploadID:      "upload-id",
		UploadStatus:  "uploading",
		FileName:      "file.mp4",
		FileSizeBytes: 10 * 1024 * 1024, // 10 MB declared
	}, nil)

	// 2. S3 Complete
	mockStorage.On("CompleteMultipartUpload", ctx, storagePath, "upload-id", mock.Anything).Return(nil)

	// 3. Magic Bytes (Valid MP4 ftyp)
	validHeader := []byte{0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'm', 'p', '4', '2'}
	mockStorage.On("GetObjectHeader", ctx, storagePath).Return(validHeader, nil)

	// 4. Реальный размер файла оказался 100 МБ
	realSize := int64(100 * 1024 * 1024)
	mockStorage.On("GetObjectSize", ctx, storagePath).Return(realSize, nil)

	// 4.5 Get Org
	mockDB.On("GetOrganizationByID", ctx, orgID).Return(&ydb.Organization{OwnerID: userID}, nil)

	// 5. Подписка (Лимит 50 МБ)
	mockDB.On("GetSubscriptionByUser", ctx, userID).Return(&ydb.Subscription{
		StorageLimitMB: 50,
	}, nil)

	// 6. Текущее использование (0 МБ)
	mockDB.On("GetStorageUsage", ctx, userID).Return(int64(0), int64(0), nil)

	// 7. Ожидаем удаление и пометку failed, т.к. 100 > 50
	mockStorage.On("DeletePrivateObject", ctx, storagePath).Return(nil)
	mockDB.On("MoveVideoToTrash", ctx, videoID).Return(nil)

	// Act
	parts := []CompletedPart{{PartNumber: 1, ETag: "etag1"}}
	resp, err := service.CompleteMultipartUploadDirect(ctx, userID, orgID, videoID, parts)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "storage limit exceeded")

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

	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:       videoID,
		OrgID:         orgID,
		UploadedBy:    userID,
		StoragePath:   storagePath,
		UploadID:      "upload-id",
		UploadStatus:  "uploading",
		FileName:      "file.mp4",
		FileSizeBytes: 1024,
	}, nil)

	mockStorage.On("CompleteMultipartUpload", ctx, storagePath, "upload-id", mock.Anything).Return(nil)
	// Valid MP4
	mockStorage.On("GetObjectHeader", ctx, storagePath).Return([]byte{0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'm', 'p', '4', '2'}, nil)
	mockStorage.On("GetObjectSize", ctx, storagePath).Return(int64(1024), nil)
	mockDB.On("GetOrganizationByID", ctx, orgID).Return(&ydb.Organization{OwnerID: userID}, nil)
	mockDB.On("GetSubscriptionByUser", ctx, userID).Return(&ydb.Subscription{StorageLimitMB: 100}, nil)
	mockDB.On("GetStorageUsage", ctx, userID).Return(int64(0), int64(0), nil)

	// Update DB success
	mockDB.On("UpdateVideo", ctx, mock.MatchedBy(func(v *ydb.Video) bool {
		return v.UploadStatus == "completed" && v.UploadedAt != nil
	})).Return(nil)

	// Generate URL
	mockStorage.On("GeneratePresignedDownloadURL", ctx, storagePath, time.Hour).Return("https://s3/video.mp4", nil)

	// Act
	parts := []CompletedPart{{PartNumber: 1, ETag: "etag1"}}
	resp, err := service.CompleteMultipartUploadDirect(ctx, userID, orgID, videoID, parts)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "https://s3/video.mp4", resp.VideoURL)
}

func TestService_DeleteVideo_AccessDenied_OtherUser(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "user-attacker"
	orgID := "org-1"
	videoID := "video-victim"

	// Видео принадлежит другому пользователю той же организации
	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:    videoID,
		OrgID:      orgID,
		UploadedBy: "user-victim",
	}, nil)

	// Act: Роль "user" не позволяет удалять чужие видео
	resp, err := service.DeleteVideoDirect(ctx, userID, orgID, "user", videoID)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "access denied", err.Error())
}

func TestService_DeleteVideo_AccessDenied_IDOR(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "admin-org1"
	orgID := "org-1"
	videoID := "video-org2"

	// Видео принадлежит другой организации
	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:    videoID,
		OrgID:      "org-2", // Mismatch
		UploadedBy: "someone",
	}, nil)

	// Act: Даже админ не может удалить видео чужой организации
	resp, err := service.DeleteVideoDirect(ctx, userID, orgID, "admin", videoID)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "access denied", err.Error())
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

func TestService_InitiateMultipartUpload_MemberUpload_OwnerQuota(t *testing.T) {
	service, mockDB, mockStorage := setupVideoService()
	ctx := context.Background()

	memberID := "user-member"
	ownerID := "user-owner"
	orgID := "org-1"
	fileSize := int64(10 * 1024 * 1024) // 10 MB

	// 1. Get Organization to find owner
	mockDB.On("GetOrganizationByID", ctx, orgID).Return(&ydb.Organization{
		OrgID:   orgID,
		OwnerID: ownerID,
	}, nil)

	// 2. Get Owner's subscription (Limit 100MB)
	mockDB.On("GetSubscriptionByUser", ctx, ownerID).Return(&ydb.Subscription{
		StorageLimitMB:  100,
		VideoCountLimit: 100,
	}, nil)

	// 3. Get Owner's storage usage (Used 95MB)
	// 95 + 10 = 105 > 100 -> Error
	mockDB.On("GetStorageUsage", ctx, ownerID).Return(int64(95*1024*1024), int64(10), nil)

	// Act
	resp, err := service.InitiateMultipartUploadDirect(ctx, memberID, orgID, "Title", "video.mp4", fileSize, 60)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "storage limit exceeded", err.Error())

	mockDB.AssertExpectations(t)
	mockStorage.AssertExpectations(t)
}

func TestService_InitiateMultipartUpload_VideoCountLimitExceeded(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	fileSize := int64(10 * 1024 * 1024)

	mockDB.On("GetOrganizationByID", ctx, orgID).Return(&ydb.Organization{OwnerID: userID}, nil)
	mockDB.On("GetSubscriptionByUser", ctx, userID).Return(&ydb.Subscription{StorageLimitMB: 1000, VideoCountLimit: 5}, nil)
	mockDB.On("GetStorageUsage", ctx, userID).Return(int64(100), int64(5), nil) // Already 5 videos

	resp, err := service.InitiateMultipartUploadDirect(ctx, userID, orgID, "Title", "video.mp4", fileSize, 60)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "video count limit exceeded", err.Error())
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

func TestService_DeleteVideo_Success(t *testing.T) {
	service, mockDB, mockStorage := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	videoID := "video-to-delete"
	storagePath := "videos/org-1/video-to-delete/file.mp4"

	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
		VideoID:     videoID,
		OrgID:       orgID,
		UploadedBy:  userID,
		StoragePath: storagePath,
	}, nil)

	// Expect DeletePrivateObject to be called (which now moves to trash)
	mockStorage.On("DeletePrivateObject", ctx, storagePath).Return(nil)

	// Expect MoveVideoToTrash
	mockDB.On("MoveVideoToTrash", ctx, videoID).Return(nil)

	resp, err := service.DeleteVideoDirect(ctx, userID, orgID, "admin", videoID)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Video deleted", resp.Message)

	mockDB.AssertExpectations(t)
	mockStorage.AssertExpectations(t)
}

func TestService_RestoreVideo_Success(t *testing.T) {
	service, mockDB, mockStorage := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"
	videoID := "video-deleted"
	storagePath := "videos/org-1/video-deleted/file.mp4"

	// 1. Get Trash Video
	mockDB.On("GetTrashVideo", ctx, videoID).Return(&ydb.TrashVideo{
		VideoID:      videoID,
		OrgID:        orgID,
		UploadedBy:   userID,
		StoragePath:  storagePath,
		UploadStatus: "deleted",
	}, nil)

	// 2. Restore from Storage
	mockStorage.On("RestorePrivateObject", ctx, storagePath).Return(nil)

	// 3. Restore Video Record
	mockDB.On("RestoreVideoFromTrash", ctx, videoID).Return(nil)

	// Act
	resp, err := service.RestoreVideo(ctx, userID, orgID, "admin", videoID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Video restored successfully", resp.Message)

	mockDB.AssertExpectations(t)
	mockStorage.AssertExpectations(t)
}

func TestService_RestoreVideo_AccessDenied_UserNotOwner(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "user-attacker"
	orgID := "org-1"
	videoID := "video-victim"

	mockDB.On("GetTrashVideo", ctx, videoID).Return(&ydb.TrashVideo{
		VideoID:    videoID,
		OrgID:      orgID,
		UploadedBy: "user-victim",
	}, nil)

	resp, err := service.RestoreVideo(ctx, userID, orgID, "user", videoID)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, "access denied", err.Error())
}

func TestService_GetTrashVideos_Success(t *testing.T) {
	service, mockDB, _ := setupVideoService()
	ctx := context.Background()

	userID := "user-1"
	orgID := "org-1"

	mockDB.On("GetTrashVideos", ctx, orgID, 10, 0).Return([]*ydb.TrashVideo{
		{
			VideoID: "v1",
			Title:   "Deleted Video",
		},
	}, int64(1), nil)

	resp, err := service.GetTrashVideos(ctx, userID, orgID, "admin", 1, 10)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Videos, 1)
	assert.Equal(t, int64(1), resp.TotalCount)
	assert.Equal(t, "v1", resp.Videos[0].VideoID)
	mockDB.AssertExpectations(t)
}

// func TestService_InitiateReplacementUpload_Success(t *testing.T) {
// 	service, mockDB, mockStorage := setupVideoService()
// 	ctx := context.Background()

// 	userID := "user-1"
// 	orgID := "org-1"
// 	videoID := "video-1"
// 	role := "admin"

// 	req := &models.ReplaceVideoRequest{
// 		VideoID:         videoID,
// 		FileName:        "new_video.mp4",
// 		FileSizeBytes:   1024,
// 		DurationSeconds: 60,
// 	}

// 	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
// 		VideoID:     videoID,
// 		OrgID:       orgID,
// 		StoragePath: "videos/org-1/video-1/old.mp4",
// 		PublicURL:   aws.String("http://public"),
// 		FileName:    "old.mp4",
// 	}, nil)

// 	mockDB.On("GetOrganizationByID", ctx, orgID).Return(&ydb.Organization{OwnerID: userID}, nil)
// 	mockDB.On("GetSubscriptionByUser", ctx, userID).Return(&ydb.Subscription{StorageLimitMB: 100}, nil)
// 	mockDB.On("GetStorageUsage", ctx, userID).Return(int64(0), int64(0), nil)

// 	mockStorage.On("DeletePublicObject", ctx, "public/org-1/video-1/old.mp4").Return(nil)
// 	mockStorage.On("InitiateMultipartUpload", ctx, "videos/org-1/video-1/old.mp4", "video/mp4").Return("upload-id-new", nil)

// 	mockDB.On("UpdateVideo", ctx, mock.MatchedBy(func(v *ydb.Video) bool {
// 		return v.VideoID == videoID &&
// 			v.UploadStatus == "uploading" &&
// 			v.PublishStatus == "private" &&
// 			v.UploadID == "upload-id-new" &&
// 			v.FileName == "new_video.mp4"
// 	})).Return(nil)

// 	resp, err := service.InitiateReplacementUpload(ctx, userID, orgID, role, req)

// 	assert.NoError(t, err)
// 	assert.Equal(t, "upload-id-new", resp.UploadID)
// 	mockDB.AssertExpectations(t)
// 	mockStorage.AssertExpectations(t)
// }

// func TestService_InitiateReplacementUpload_QuotaExceeded(t *testing.T) {
// 	service, mockDB, _ := setupVideoService()
// 	ctx := context.Background()

// 	userID := "user-1"
// 	orgID := "org-1"
// 	videoID := "video-1"

// 	req := &models.ReplaceVideoRequest{
// 		VideoID:       videoID,
// 		FileName:      "new.mp4",
// 		FileSizeBytes: 20 * 1024 * 1024, // 20 MB
// 	}

// 	mockDB.On("GetVideo", ctx, videoID).Return(&ydb.Video{
// 		VideoID: videoID,
// 		OrgID:   orgID,
// 	}, nil)

// 	mockDB.On("GetOrganizationByID", ctx, orgID).Return(&ydb.Organization{OwnerID: userID}, nil)
// 	mockDB.On("GetSubscriptionByUser", ctx, userID).Return(&ydb.Subscription{StorageLimitMB: 100}, nil)
// 	// Used 90MB. 90 + 20 = 110 > 100
// 	mockDB.On("GetStorageUsage", ctx, userID).Return(int64(90*1024*1024), int64(5), nil)

// 	resp, err := service.InitiateReplacementUpload(ctx, userID, orgID, "admin", req)

// 	assert.Error(t, err)
// 	assert.Nil(t, resp)
// 	assert.Equal(t, "storage limit exceeded", err.Error())
// }

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
