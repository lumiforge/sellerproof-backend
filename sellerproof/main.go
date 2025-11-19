package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/lumiforge/sellerproof-backend/internal/auth"
	"github.com/lumiforge/sellerproof-backend/internal/config"
	"github.com/lumiforge/sellerproof-backend/internal/email"
	httpserver "github.com/lumiforge/sellerproof-backend/internal/http"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/logger"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/storage"
	"github.com/lumiforge/sellerproof-backend/internal/telegram"
	"github.com/lumiforge/sellerproof-backend/internal/video"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

func EntryPoint() {
	ctx := context.Background()

	// Загрузка конфигурации
	cfg := config.Load()

	// Инициализация Telegram клиента
	tgClient := telegram.NewClient(cfg)

	// Инициализация логгера
	log := logger.New(tgClient)
	slog.SetDefault(log)

	// Инициализация YDB
	db, err := ydb.NewYDBClient(ctx, cfg)
	if err != nil {
		slog.Error("Failed to connect to YDB", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Инициализация JWT менеджера
	jwtManager := jwt.NewJWTManager(cfg)

	// Инициализация RBAC
	rbacManager := rbac.NewRBAC()

	// Инициализация email клиента
	emailClient := email.NewClient(cfg)

	// Инициализация S3 клиента
	storageClient, err := storage.NewClient(ctx, cfg)
	if err != nil {
		slog.Error("Failed to initialize storage client", "error", err)
		os.Exit(1)
	}

	// Инициализация сервисов
	authService := auth.NewService(db, jwtManager, rbacManager, emailClient)
	videoService := video.NewService(db, storageClient, rbacManager)

	// Инициализация HTTP сервера
	server := httpserver.NewServer(authService, videoService, jwtManager)

	// Настройка роутера
	router := httpserver.SetupRouter(server, jwtManager)

	// Запуск HTTP сервера
	port := cfg.HTTPPort

	slog.Info("Starting HTTP server", "port", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		slog.Error("Failed to start HTTP server", "error", err)
		os.Exit(1)
	}
}

func main() {
	EntryPoint()
}
