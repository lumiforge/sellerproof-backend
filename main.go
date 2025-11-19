package main

import (
	"context"
	"log/slog"
	"net/http"

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

// EntryPoint adapted for Yandex Cloud Function
func EntryPoint(ctx context.Context, request []byte) ([]byte, error) {
	// Load config
	cfg := config.Load()

	// Init Telegram Client
	tgClient := telegram.NewClient(cfg)

	// Init logger
	log := logger.New(tgClient)
	slog.SetDefault(log)

	// Init YDB
	db, err := ydb.NewYDBClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Init JWT Manager
	jwtManager := jwt.NewJWTManager(cfg)

	// Init RBAC
	rbacManager := rbac.NewRBAC()

	// Init email client
	emailClient := email.NewClient(cfg)

	// Init S3 client
	storageClient, err := storage.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Init services
	authService := auth.NewService(db, jwtManager, rbacManager, emailClient)
	videoService := video.NewService(db, storageClient, rbacManager)

	// Init HTTP server
	server := httpserver.NewServer(authService, videoService, jwtManager)

	// Setup router
	router := httpserver.SetupRouter(server, jwtManager)

	// TODO: parse request and response for Cloud Function integration
	// return 501 Not Implemented response by default
	return []byte(`{"statusCode":501,"body":"Not Implemented"}`), nil
}

func main() {
	// For local HTTP server launch
	// Use normal HTTP server run
	EntryPoint(context.Background(), nil)
}
