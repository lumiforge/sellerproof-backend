package main

import (
	"context"
	"log"
	"os"

	"github.com/lumiforge/sellerproof-backend/internal/email"
	"github.com/lumiforge/sellerproof-backend/internal/grpc"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/storage"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

func main() {
	ctx := context.Background()

	// Инициализация YDB
	db, err := ydb.NewYDBClient(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to YDB: %v", err)
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
		log.Fatalf("Failed to initialize storage client: %v", err)
	}

	// Инициализация gRPC сервера
	server := grpc.NewServer(db, jwtManager, rbacManager, emailClient, storageClient)

	// Запуск gRPC сервера
	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "50051"
	}

	log.Printf("Starting gRPC server on port %s", port)
	if err := grpc.StartGRPCServer(server, port); err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
	}
}
