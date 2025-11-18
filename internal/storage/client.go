package storage

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Client обертка над S3 клиентом
type Client struct {
	s3Client      *s3.Client
	presignClient *s3.PresignClient
	bucketName    string
}

// NewClient создает новый S3 клиент
func NewClient(ctx context.Context) (*Client, error) {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	bucketName := os.Getenv("SP_OBJSTORE_BUCKET_NAME")
	endpoint := "https://storage.yandexcloud.net"
	region := "ru-central1"

	if accessKey == "" || secretKey == "" || bucketName == "" {
		return nil, fmt.Errorf("AWS credentials and bucket name must be set")
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: endpoint}, nil
			})),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	client := s3.NewFromConfig(cfg)
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