package http

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/auth"
	"github.com/lumiforge/sellerproof-backend/internal/jwt"
	"github.com/lumiforge/sellerproof-backend/internal/logger"
)

// Context keys for storing values in request context
type contextKey string

const (
	UserClaimsKey contextKey = "user_claims"
	RequestIDKey  contextKey = "request_id"
)

// AuthMiddleware creates a middleware for JWT authentication
func AuthMiddleware(jwtManager *jwt.JWTManager, authService *auth.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for public endpoints
		if isPublicEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		// Extract token from "Bearer <token>" format
		tokenString, err := jwt.ExtractTokenFromHeader(authHeader)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Validate token
		claims, err := jwtManager.ValidateToken(tokenString)

		if err != nil {

			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if r.URL.Path != "/api/v1/auth/switch-organization" {
			// Check if user session is still valid in DB (handles revocation/ban instantly)
			if err := authService.ValidateActiveSession(r.Context(), claims.UserID, claims.OrgID); err != nil {
				http.Error(w, "Session invalidated: "+err.Error(), http.StatusUnauthorized)
				return
			}
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), UserClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Add request ID to context
		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)

		// Add request ID to response header
		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LoggingMiddleware logs requests and responses with structured logging
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Extract request ID from context
		requestID, _ := r.Context().Value(RequestIDKey).(string)

		// Create logger with request ID
		l := slog.With("request_id", requestID, "method", r.Method, "path", r.URL.Path)
		ctx := logger.WithContext(r.Context(), l)

		l.Info("Request started", "remote_addr", r.RemoteAddr, "user_agent", r.UserAgent())

		// Serve the request with updated context
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		duration := time.Since(start)
		l.Info("Request completed",
			"status_code", wrapped.statusCode,
			"duration_ms", duration.Milliseconds(),
			"response_size_bytes", wrapped.size,
		)
	})
}

// CORSMiddleware adds CORS headers
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Add Origins before production release
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ContentTypeMiddleware ensures JSON content type for API endpoints
func ContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isPublicEndpoint checks if the endpoint should be accessible without authentication
func isPublicEndpoint(path string) bool {
	publicPaths := []string{
		"/api/v1/auth/register",
		"/api/v1/auth/login",
		"/api/v1/auth/refresh",
		"/api/v1/auth/verify-email",
		"/api/v1/video/public",
		"/health",
		"/",
	}

	for _, publicPath := range publicPaths {
		if path == publicPath || (publicPath != "/" && strings.HasPrefix(path, publicPath+"/")) {
			return true
		}
	}

	return false
}

// responseWriter is a wrapper around http.ResponseWriter to capture status code and response size
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// GetUserClaims extracts user claims from request context
func GetUserClaims(r *http.Request) (*jwt.Claims, bool) {
	claims, ok := r.Context().Value(UserClaimsKey).(*jwt.Claims)
	return claims, ok
}

// GetRequestID extracts request ID from request context
func GetRequestID(r *http.Request) (string, bool) {
	requestID, ok := r.Context().Value(RequestIDKey).(string)
	return requestID, ok
}
