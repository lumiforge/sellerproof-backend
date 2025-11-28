package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"sync"

	"github.com/lumiforge/sellerproof-backend/internal/bootstrap"
	"github.com/lumiforge/sellerproof-backend/internal/config"
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
	apiHandler http.Handler
	initOnce   sync.Once
	initErr    error
)

// getHandler обеспечивает ленивую инициализацию приложения (Singleton)
func getHandler(ctx context.Context) (http.Handler, error) {
	initOnce.Do(func() {
		apiHandler, initErr = bootstrap.Initialize(ctx)
	})
	return apiHandler, initErr
}

// EntryPoint - точка входа для Yandex Cloud Functions (HttpTrigger)
func EntryPoint(w http.ResponseWriter, r *http.Request) {
	handler, err := getHandler(r.Context())
	if err != nil {
		slog.Error("Failed to initialize application", "error", err)
		http.Error(w, "Internal Server Error: Initialization failed", http.StatusInternalServerError)
		return
	}
	handler.ServeHTTP(w, r)
}

// main - точка входа для локального запуска
func main() {
	ctx := context.Background()

	// Инициализируем приложение
	handler, err := getHandler(ctx)
	if err != nil {
		log.Fatalf("CRITICAL: Failed to initialize application: %v", err)
	}

	// Загружаем конфиг только для получения порта (сам конфиг уже загружен внутри bootstrap)
	cfg := config.Load()
	port := cfg.HTTPPort
	if port == "" {
		port = "8080"
	}

	slog.Info("Starting server", "port", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
