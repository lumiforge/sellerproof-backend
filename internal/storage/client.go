package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/lumiforge/sellerproof-backend/internal/config"
)

// Client обертка над S3 клиентом
type Client struct {
	s3Client      *s3.Client
	presignClient *s3.PresignClient
	bucketName    string
}

// NewClient создает новый S3 клиент
func NewClient(ctx context.Context, cfg *config.Config) (*Client, error) {
	accessKey := cfg.AWSAccessKeyID
	secretKey := cfg.AWSSecretAccessKey
	bucketName := cfg.SPObjStoreBucketName
	endpoint := cfg.S3Endpoint
	region := "ru-central1"

	if accessKey == "" || secretKey == "" || bucketName == "" {
		return nil, fmt.Errorf("AWS credentials and bucket name must be set")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})
	presignClient := s3.NewPresignClient(client)

	return &Client{
		s3Client:      client,
		presignClient: presignClient,
		bucketName:    bucketName,
	}, nil
}

// InitiateMultipartUpload начинает загрузку
func (c *Client) InitiateMultipartUpload(ctx context.Context, key string, contentType string) (string, error) {
	input := &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(c.bucketName),
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
func (c *Client) GeneratePresignedPartURL(ctx context.Context, key, uploadID string, partNumber int32, lifetime time.Duration) (string, error) {
	input := &s3.UploadPartInput{
		Bucket:     aws.String(c.bucketName),
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
func (c *Client) CompleteMultipartUpload(ctx context.Context, key, uploadID string, parts []types.CompletedPart) error {
	input := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(c.bucketName),
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
func (c *Client) GeneratePresignedDownloadURL(ctx context.Context, key string, lifetime time.Duration) (string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(key),
	}

	req, err := c.presignClient.PresignGetObject(ctx, input, func(opts *s3.PresignOptions) {
		opts.Expires = lifetime
	})
	return req.URL, err
}
