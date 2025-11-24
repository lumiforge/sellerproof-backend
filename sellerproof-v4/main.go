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

// @title			SellerProof API
// @version		1.0
// @description	API for SellerProof video management platform
// @termsOfService	http://swagger.io/terms/

// @contact.name	API Support
// @contact.url	http://www.swagger.io/support
// @contact.email	support@swagger.io

// @license.name	Apache 2.0
// @license.url	http://www.apache.org/licenses/LICENSE-2.0.html

// @host		localhost:8080
// @BasePath	/api/v1

// @securityDefinitions.apikey	BearerAuth
// @in							header
// @name						Authorization
// @description					Bearer token for authentication

var (
	router http.Handler
)

func init() {
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
		// Force output to stdout to ensure it appears in simple logs
		println("CRITICAL ERROR: Failed to connect to YDB: " + err.Error())
		os.Exit(1)
	}

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
	router = httpserver.SetupRouter(server, jwtManager)
}

func EntryPoint(w http.ResponseWriter, r *http.Request) {
	router.ServeHTTP(w, r)
}
