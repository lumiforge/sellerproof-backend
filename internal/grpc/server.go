package grpc

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/lumiforge/sellerproof-backend/internal/auth"
	"github.com/lumiforge/sellerproof-backend/internal/email"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/storage"
	"github.com/lumiforge/sellerproof-backend/internal/video"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
	pb "github.com/lumiforge/sellerproof-backend/proto"
)

// Server реализует gRPC сервер
type Server struct {
	pb.UnimplementedAuthServiceServer
	pb.UnimplementedVideoServiceServer
	authService *auth.Service
	videoService *video.Service
	jwtManager  *jwt.JWTManager
}

// NewServer создает новый gRPC сервер
func NewServer(db ydb.Database, jwtManager *jwt.JWTManager, rbacManager *rbac.RBAC, emailClient *email.PostboxClient, storageClient *storage.Client) *Server {
	authService := auth.NewService(db, jwtManager, rbacManager, emailClient)
	videoService := video.NewService(db, storageClient, rbacManager)

	return &Server{
		authService: authService,
		videoService: videoService,
		jwtManager:  jwtManager,
	}
}

// Register реализует регистрацию пользователя
func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	authReq := &auth.RegisterRequest{
		Email:    req.Email,
		Password: req.Password,
		FullName: req.FullName,
	}

	resp, err := s.authService.Register(ctx, authReq)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.RegisterResponse{
		UserId:  resp.UserID,
		Message: resp.Message,
	}, nil
}

// VerifyEmail реализует верификацию email
func (s *Server) VerifyEmail(ctx context.Context, req *pb.VerifyEmailRequest) (*pb.VerifyEmailResponse, error) {
	if req.Email == "" || req.Code == "" {
		return nil, status.Error(codes.InvalidArgument, "email and code are required")
	}

	authReq := &auth.VerifyEmailRequest{
		Email: req.Email,
		Code:  req.Code,
	}

	resp, err := s.authService.VerifyEmail(ctx, authReq)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.VerifyEmailResponse{
		Message: resp.Message,
		Success: resp.Success,
	}, nil
}

// Login реализует вход пользователя
func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	authReq := &auth.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := s.authService.Login(ctx, authReq)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	userInfo := &pb.UserInfo{
		UserId:        resp.User.UserID,
		Email:         resp.User.Email,
		FullName:      resp.User.FullName,
		Role:          resp.User.Role,
		OrgId:         resp.User.OrgID,
		EmailVerified: resp.User.EmailVerified,
		CreatedAt:     resp.User.CreatedAt,
		UpdatedAt:     resp.User.UpdatedAt,
	}

	return &pb.LoginResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    resp.ExpiresAt,
		User:         userInfo,
	}, nil
}

// RefreshToken реализует обновление токена
func (s *Server) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	authReq := &auth.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := s.authService.RefreshToken(ctx, authReq)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.RefreshTokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    resp.ExpiresAt,
	}, nil
}

// Logout реализует выход пользователя
func (s *Server) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	authReq := &auth.LogoutRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := s.authService.Logout(ctx, authReq)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.LogoutResponse{
		Message: resp.Message,
	}, nil
}

// GetProfile реализует получение профиля пользователя
func (s *Server) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.GetProfileResponse, error) {
	// Извлечение токена из контекста
	claims, err := s.extractClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	resp, err := s.authService.GetProfile(ctx, claims.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	userInfo := &pb.UserInfo{
		UserId:        resp.User.UserID,
		Email:         resp.User.Email,
		FullName:      resp.User.FullName,
		Role:          resp.User.Role,
		OrgId:         resp.User.OrgID,
		EmailVerified: resp.User.EmailVerified,
		CreatedAt:     resp.User.CreatedAt,
		UpdatedAt:     resp.User.UpdatedAt,
	}

	return &pb.GetProfileResponse{
		User: userInfo,
	}, nil
}

// UpdateProfile реализует обновление профиля пользователя
func (s *Server) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.UpdateProfileResponse, error) {
	// Извлечение токена из контекста
	claims, err := s.extractClaimsFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	// Здесь должна быть логика обновления профиля
	// Для упрощения пропустим реализацию

	return &pb.UpdateProfileResponse{
		User: &pb.UserInfo{
			UserId:        claims.UserID,
			Email:         claims.Email,
			FullName:      req.FullName,
			Role:          claims.Role,
			OrgId:         claims.OrgID,
			EmailVerified: true, // Предполагаем, что email подтвержден
			CreatedAt:     0,    // Нужно получить из базы
			UpdatedAt:     0,    // Нужно получить из базы
		},
	}, nil
}

// AuthInterceptor представляет middleware для аутентификации gRPC запросов
func (s *Server) AuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Пропускаем публичные методы
	if info.FullMethod == "/auth.AuthService/Register" ||
		info.FullMethod == "/auth.AuthService/Login" ||
		info.FullMethod == "/auth.AuthService/RefreshToken" ||
		info.FullMethod == "/auth.AuthService/VerifyEmail" ||
		info.FullMethod == "/video.VideoService/GetPublicVideo" {
		return handler(ctx, req)
	}

	// Извлечение токена из метаданных
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	values := md["authorization"]
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "authorization token is not provided")
	}

	// Извлечение токена из header
	tokenString, err := jwt.ExtractTokenFromHeader(values[0])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	// Валидация токена
	claims, err := s.jwtManager.ValidateToken(tokenString)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	// Добавление claims в контекст
	newCtx := context.WithValue(ctx, "user_claims", claims)

	return handler(newCtx, req)
}

// extractClaimsFromContext извлекает claims из контекста
func (s *Server) extractClaimsFromContext(ctx context.Context) (*jwt.Claims, error) {
	claims, ok := ctx.Value("user_claims").(*jwt.Claims)
	if !ok {
		return nil, fmt.Errorf("user claims not found in context")
	}
	return claims, nil
}

// StartGRPCServer запускает gRPC сервер
func StartGRPCServer(server *Server, port string) error {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Создание сервера с interceptor
	s := grpc.NewServer(
		grpc.UnaryInterceptor(server.AuthInterceptor),
	)

	pb.RegisterAuthServiceServer(s, server)
	pb.RegisterVideoServiceServer(s, server)

	fmt.Printf("gRPC server listening on port %s\n", port)

	return s.Serve(lis)
}

// StartHTTPGateway запускает HTTP gateway для gRPC (опционально)
func StartHTTPGateway(server *Server, port string) error {
	// Здесь можно реализовать HTTP gateway используя grpc-gateway
	// Для упрощения пропустим
	return nil
}
