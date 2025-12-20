package storage

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// StorageProvider определяет интерфейс для работы с объектным хранилищем (S3)
type StorageProvider interface {
	// Методы загрузки
	InitiateMultipartUpload(ctx context.Context, bucket, key string, contentType string) (string, error)
	GeneratePresignedPartURL(ctx context.Context, bucket, key, uploadID string, partNumber int32, lifetime time.Duration) (string, error)
	CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []types.CompletedPart) error

	// Методы скачивания и доступа
	GeneratePresignedDownloadURL(ctx context.Context, bucket, key string, lifetime time.Duration) (string, error)

	// Методы управления объектами
	CleanupObject(ctx context.Context, bucket, key string) error
	DeleteObject(ctx context.Context, bucket, key string) error
	CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error

	// Служебные методы
	GetObjectSize(ctx context.Context, bucket, key string) (int64, error)
	GetObjectHeader(ctx context.Context, bucket, key string) ([]byte, error)
}
