package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/lumiforge/sellerproof-backend/internal/email"
	"github.com/lumiforge/sellerproof-backend/internal/grpc"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/logger"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/storage"
	"github.com/lumiforge/sellerproof-backend/internal/telegram"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

func main() {
	ctx := context.Background()

	// Инициализация Telegram клиента
	tgClient := telegram.NewClient()

	// Инициализация логгера
	log := logger.New(tgClient)
	slog.SetDefault(log)

	// Инициализация YDB
	db, err := ydb.NewYDBClient(ctx)
	if err != nil {
		slog.Error("Failed to connect to YDB", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Инициализация JWT менеджера
	jwtManager := jwt.NewJWTManager()

	// Инициализация RBAC
	rbacManager := rbac.NewRBAC()

	// Инициализация email клиента
	emailClient := email.NewPostboxClient()

	// Инициализация S3 клиента
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		slog.Error("Failed to initialize storage client", "error", err)
		os.Exit(1)
	}

	// Инициализация gRPC сервера
	server := grpc.NewServer(db, jwtManager, rbacManager, emailClient, storageClient)

	// Запуск gRPC сервера
	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "50051"
	}

	slog.Info("Starting gRPC server", "port", port)
	if err := grpc.StartGRPCServer(server, port); err != nil {
		slog.Error("Failed to start gRPC server", "error", err)
		os.Exit(1)
	}
}
