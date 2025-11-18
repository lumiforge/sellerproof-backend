package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/lumiforge/sellerproof-backend/proto"
)

// InitiateMultipartUpload инициирует загрузку видео
func (s *Server) InitiateMultipartUpload(ctx context.Context, req *pb.InitiateMultipartUploadRequest) (*pb.InitiateMultipartUploadResponse, error) {
	claims, err := s.extractClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	resp, err := s.videoService.InitiateMultipartUpload(ctx, claims.UserID, claims.OrgID, req)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}

// GetPartUploadURLs возвращает ссылки для загрузки частей
func (s *Server) GetPartUploadURLs(ctx context.Context, req *pb.GetPartUploadURLsRequest) (*pb.GetPartUploadURLsResponse, error) {
	claims, err := s.extractClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	resp, err := s.videoService.GetPartUploadURLs(ctx, claims.UserID, claims.OrgID, req)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}

// CompleteMultipartUpload завершает загрузку видео
func (s *Server) CompleteMultipartUpload(ctx context.Context, req *pb.CompleteMultipartUploadRequest) (*pb.CompleteMultipartUploadResponse, error) {
	claims, err := s.extractClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	resp, err := s.videoService.CompleteMultipartUpload(ctx, claims.UserID, claims.OrgID, req)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}

// GetVideo возвращает информацию о видео
func (s *Server) GetVideo(ctx context.Context, req *pb.GetVideoRequest) (*pb.GetVideoResponse, error) {
	claims, err := s.extractClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	resp, err := s.videoService.GetVideo(ctx, claims.UserID, claims.OrgID, req.VideoId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.GetVideoResponse{
		Video: resp,
	}, nil
}

// SearchVideos ищет видео
func (s *Server) SearchVideos(ctx context.Context, req *pb.SearchVideosRequest) (*pb.SearchVideosResponse, error) {
	claims, err := s.extractClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	resp, err := s.videoService.SearchVideos(ctx, claims.UserID, claims.OrgID, claims.Role, req)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}

// GetPublicVideo возвращает публичную ссылку на видео (без аутентификации)
func (s *Server) GetPublicVideo(ctx context.Context, req *pb.GetPublicVideoRequest) (*pb.GetPublicVideoResponse, error) {
	if req.ShareToken == "" {
		return nil, status.Error(codes.InvalidArgument, "share token is required")
	}

	resp, err := s.videoService.GetPublicVideo(ctx, req.ShareToken)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}

// CreatePublicShareLink создает публичную ссылку для видео
func (s *Server) CreatePublicShareLink(ctx context.Context, req *pb.CreateShareLinkRequest) (*pb.CreateShareLinkResponse, error) {
	claims, err := s.extractClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	resp, err := s.videoService.CreatePublicShareLink(ctx, claims.UserID, claims.OrgID, claims.Role, req)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}

// RevokeShareLink отзывает публичную ссылку
func (s *Server) RevokeShareLink(ctx context.Context, req *pb.RevokeShareLinkRequest) (*pb.RevokeShareLinkResponse, error) {
	claims, err := s.extractClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	err = s.videoService.RevokeShareLink(ctx, claims.UserID, claims.OrgID, claims.Role, req.VideoId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.RevokeShareLinkResponse{Success: true}, nil
}
