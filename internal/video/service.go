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
	pb "github.com/lumiforge/sellerproof-backend/proto"
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

func (s *Service) InitiateMultipartUpload(ctx context.Context, userID, orgID string, req *pb.InitiateMultipartUploadRequest) (*pb.InitiateMultipartUploadResponse, error) {
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
	if sub.StorageLimitGB > 0 && (currentUsage+req.FileSizeBytes) > limitBytes {
		return nil, fmt.Errorf("storage limit exceeded")
	}

	videoID := uuid.New().String()
	objectKey := fmt.Sprintf("videos/%s/%s/%s", orgID, videoID, req.FileName)

	uploadID, err := s.storage.InitiateMultipartUpload(ctx, objectKey, "video/mp4")
	if err != nil {
		return nil, fmt.Errorf("failed to initiate s3 upload: %w", err)
	}

	video := &ydb.Video{
		VideoID:         videoID,
		OrgID:           orgID,
		UploadedBy:      userID,
		FileName:        req.FileName,
		FileNameSearch:  strings.ToLower(req.FileName),
		FileSizeBytes:   req.FileSizeBytes,
		StoragePath:     objectKey,
		DurationSeconds: req.DurationSeconds,
		UploadID:        uploadID,
		UploadStatus:    "pending",
		IsDeleted:       false,
	}

	if err := s.db.CreateVideo(ctx, video); err != nil {
		return nil, fmt.Errorf("failed to create video record: %w", err)
	}

	return &pb.InitiateMultipartUploadResponse{
		VideoId:               videoID,
		UploadId:              uploadID,
		RecommendedPartSizeMb: 10,
	}, nil
}

func (s *Service) GetPartUploadURLs(ctx context.Context, userID, orgID string, req *pb.GetPartUploadURLsRequest) (*pb.GetPartUploadURLsResponse, error) {
	video, err := s.db.GetVideo(ctx, req.VideoId)
	if err != nil {
		return nil, fmt.Errorf("video not found")
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	urls := make([]string, req.TotalParts)
	for i := 0; i < int(req.TotalParts); i++ {
		url, err := s.storage.GeneratePresignedPartURL(ctx, video.StoragePath, video.UploadID, int32(i+1), 1*time.Hour)
		if err != nil {
			return nil, fmt.Errorf("failed to generate url for part %d: %w", i+1, err)
		}
		urls[i] = url
	}

	video.TotalParts = req.TotalParts
	video.UploadStatus = "uploading"
	s.db.UpdateVideo(ctx, video)

	return &pb.GetPartUploadURLsResponse{
		PartUrls:  urls,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}, nil
}

func (s *Service) CompleteMultipartUpload(ctx context.Context, userID, orgID string, req *pb.CompleteMultipartUploadRequest) (*pb.CompleteMultipartUploadResponse, error) {
	video, err := s.db.GetVideo(ctx, req.VideoId)
	if err != nil {
		return nil, fmt.Errorf("video not found")
	}

	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	parts := make([]types.CompletedPart, len(req.Parts))
	for i, p := range req.Parts {
		parts[i] = types.CompletedPart{
			ETag:       aws.String(p.Etag),
			PartNumber: aws.Int32(p.PartNumber),
		}
	}

	if err := s.storage.CompleteMultipartUpload(ctx, video.StoragePath, video.UploadID, parts); err != nil {
		return nil, fmt.Errorf("failed to complete s3 upload: %w", err)
	}

	video.UploadStatus = "completed"
	now := time.Now()
	video.UploadedAt = &now
	s.db.UpdateVideo(ctx, video)

	// Генерация URL для просмотра (опционально)
	url, _ := s.storage.GeneratePresignedDownloadURL(ctx, video.StoragePath, 1*time.Hour)

	return &pb.CompleteMultipartUploadResponse{
		Message:  "Upload completed",
		VideoUrl: url,
	}, nil
}

func (s *Service) GetVideo(ctx context.Context, userID, orgID, videoID string) (*pb.Video, error) {
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

	return &pb.Video{
		VideoId:         video.VideoID,
		FileName:        video.FileName,
		FileSizeBytes:   video.FileSizeBytes,
		DurationSeconds: video.DurationSeconds,
		UploadStatus:    video.UploadStatus,
		UploadedAt:      uploadedAt,
	}, nil
}

func (s *Service) CreatePublicShareLink(ctx context.Context, userID, orgID string, req *pb.CreateShareLinkRequest) (*pb.CreateShareLinkResponse, error) {
	video, err := s.db.GetVideo(ctx, req.VideoId)
	if err != nil {
		return nil, err
	}
	if video.OrgID != orgID {
		return nil, fmt.Errorf("access denied")
	}

	var expiresAt int64
	if video.ShareExpiresAt != nil {
		expiresAt = video.ShareExpiresAt.Unix()
	}

	token := generateToken(32)
	video.PublicShareToken = token
	if req.ExpiresInHours > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
		video.ShareExpiresAt = &t
	} else {
		video.ShareExpiresAt = nil
	}

	if err := s.db.UpdateVideo(ctx, video); err != nil {
		return nil, err
	}

	return &pb.CreateShareLinkResponse{
		ShareUrl:  fmt.Sprintf("https://sellerproof.ru/share/%s", token),
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) GetPublicVideo(ctx context.Context, shareToken string) (*pb.GetPublicVideoResponse, error) {
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

	return &pb.GetPublicVideoResponse{
		FileName:    video.FileName,
		FileSize:    video.FileSizeBytes,
		DownloadUrl: url,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
	}, nil
}

func (s *Service) RevokeShareLink(ctx context.Context, userID, orgID, videoID string) error {
	// Implementation skipped for brevity
	return nil
}

func generateToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}
