package bootstrap

import (
	"context"
	"log/slog"

	"net/http"

	"github.com/lumiforge/sellerproof-backend/internal/audit"
	"github.com/lumiforge/sellerproof-backend/internal/auth"
	"github.com/lumiforge/sellerproof-backend/internal/config"
	"github.com/lumiforge/sellerproof-backend/internal/email"
	app_errors "github.com/lumiforge/sellerproof-backend/internal/errors"
	httpserver "github.com/lumiforge/sellerproof-backend/internal/http"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/logger"
	"github.com/lumiforge/sellerproof-backend/internal/plan"
	"github.com/lumiforge/sellerproof-backend/internal/rbac"
	"github.com/lumiforge/sellerproof-backend/internal/storage"
	"github.com/lumiforge/sellerproof-backend/internal/telegram"
	"github.com/lumiforge/sellerproof-backend/internal/video"
	"github.com/lumiforge/sellerproof-backend/internal/ydb"
)

// Initialize настраивает все зависимости и возвращает готовый HTTP роутер
func Initialize(ctx context.Context) (http.Handler, error) {
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
		return nil, app_errors.ErrFailedToConnectYDB
	}

	// Инициализация JWT менеджера
	jwtManager := jwt.NewJWTManager(cfg)
	if jwtManager == nil {
		return nil, app_errors.ErrJWTSecretKeyNotConfigured
	}

	// Инициализация RBAC
	rbacManager := rbac.NewRBAC()

	// Инициализация email клиента
	emailClient := email.NewClient(cfg)

	// Инициализация S3 клиента
	storageClient, err := storage.NewClient(ctx, cfg)
	if err != nil {
		return nil, app_errors.ErrFailedToInitStorageClient
	}

	// Инициализация сервисов
	authService := auth.NewService(db, jwtManager, rbacManager, emailClient, cfg)
	videoService := video.NewService(db, storageClient, rbacManager, cfg)

	auditService := audit.NewService(db)
	planService := plan.NewService(db)

	// Инициализация HTTP сервера
	server := httpserver.NewServer(authService, videoService, jwtManager, auditService, planService)

	// Настройка роутера
	router := httpserver.SetupRouter(server, jwtManager)

	slog.Info("Application initialized successfully")
	return router, nil
}
