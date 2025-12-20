package storage

import (
	"context"
	"fmt"
	"io"

	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/lumiforge/sellerproof-backend/internal/config"
	app_errors "github.com/lumiforge/sellerproof-backend/internal/errors"
)

// Client обертка над S3 клиентом
type Client struct {
	s3Client      *s3.Client
	presignClient *s3.PresignClient
	endpoint      string
}

// CleanupObject deletes object from specified bucket (used for system cleanup)
func (c *Client) CleanupObject(ctx context.Context, bucket, key string) error {
	if key == "" || bucket == "" {
		return app_errors.ErrObjectKeyRequired
	}

	_, err := c.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	return err
}

// NewClient создает новый S3 клиент
func NewClient(ctx context.Context, cfg *config.Config) (*Client, error) {
	accessKey := cfg.AWSAccessKeyID
	secretKey := cfg.AWSSecretAccessKey
	endpoint := cfg.S3Endpoint
	region := cfg.SESRegion

	if accessKey == "" || secretKey == "" {
		return nil, app_errors.ErrAWSCredsOrBucketNamesNotSet
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return nil, app_errors.ErrFailedToLoadAWSConfig
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})
	presignClient := s3.NewPresignClient(client)

	return &Client{
		s3Client:      client,
		presignClient: presignClient,
		endpoint:      endpoint,
	}, nil
}

// InitiateMultipartUpload начинает загрузку
func (c *Client) InitiateMultipartUpload(ctx context.Context, bucket, key string, contentType string) (string, error) {
	input := &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		ContentType: aws.String(contentType),
	}

	resp, err := c.s3Client.CreateMultipartUpload(ctx, input)
	if err != nil {
		return "", err
	}

	return *resp.UploadId, nil
}

// GeneratePresignedPartURL генерирует URL для загрузки части
func (c *Client) GeneratePresignedPartURL(ctx context.Context, bucket, key, uploadID string, partNumber int32, lifetime time.Duration) (string, error) {
	input := &s3.UploadPartInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(partNumber),
	}

	req, err := c.presignClient.PresignUploadPart(ctx, input, func(opts *s3.PresignOptions) {
		opts.Expires = lifetime
	})
	if err != nil {
		return "", err
	}

	return req.URL, nil
}

// CompleteMultipartUpload завершает загрузку
func (c *Client) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []types.CompletedPart) error {
	input := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	}

	_, err := c.s3Client.CompleteMultipartUpload(ctx, input)
	return err
}

// GeneratePresignedDownloadURL генерирует URL для скачивания
func (c *Client) GeneratePresignedDownloadURL(ctx context.Context, bucket, key string, lifetime time.Duration) (string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	req, err := c.presignClient.PresignGetObject(ctx, input, func(opts *s3.PresignOptions) {
		opts.Expires = lifetime
	})
	return req.URL, err
}

// CopyObject copies object from one bucket to another
func (c *Client) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error {
	copySource := fmt.Sprintf("%s/%s", srcBucket, srcKey)

	_, err := c.s3Client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(dstBucket),
		CopySource: aws.String(copySource),
		Key:        aws.String(dstKey),
	})

	return err
}

// DeleteObject deletes object from specified bucket
func (c *Client) DeleteObject(ctx context.Context, bucket, key string) error {
	if key == "" {
		return app_errors.ErrObjectKeyRequired
	}

	_, err := c.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	return err
}

// GetObjectSize returns the size of the object in bytes
func (c *Client) GetObjectSize(ctx context.Context, bucket, key string) (int64, error) {
	output, err := c.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return 0, err
	}
	return *output.ContentLength, nil
}

func (c *Client) GetObjectHeader(ctx context.Context, bucket, key string) ([]byte, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Range:  aws.String("bytes=0-511"), // Читаем только первые 512 байт
	}

	resp, err := c.s3Client.GetObject(ctx, input)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
