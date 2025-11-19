package http

import (
	"net/http"
	"strings"

	"github.com/lumiforge/sellerproof-backend/internal/jwt"
)

// SetupRouter creates and configures HTTP router
func SetupRouter(server *Server, jwtManager *jwt.JWTManager) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.HandleFunc("/health", server.Health)
	mux.HandleFunc("/", server.Health)

	// Auth routes (no auth required)
	mux.HandleFunc("/api/v1/auth/register", chainMiddleware(server.Register, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))
	mux.HandleFunc("/api/v1/auth/login", chainMiddleware(server.Login, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))
	mux.HandleFunc("/api/v1/auth/refresh", chainMiddleware(server.RefreshToken, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))
	mux.HandleFunc("/api/v1/auth/verify-email", chainMiddleware(server.VerifyEmail, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))

	// Protected auth routes
	mux.HandleFunc("/api/v1/auth/logout", chainMiddleware(server.Logout, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/auth/profile", chainMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			server.GetProfile(w, r)
		} else if r.Method == "PUT" {
			server.UpdateProfile(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))

	// Video routes
	// Public video routes (no auth required)
	mux.HandleFunc("/api/v1/video/public", chainMiddleware(server.GetPublicVideo, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))

	// Protected video routes
	mux.HandleFunc("/api/v1/video/upload/initiate", chainMiddleware(server.InitiateMultipartUpload, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/upload/urls", chainMiddleware(server.GetPartUploadURLs, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/upload/complete", chainMiddleware(server.CompleteMultipartUpload, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video", chainMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			server.GetVideo(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/search", chainMiddleware(server.SearchVideos, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/share", chainMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			server.CreatePublicShareLink(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/share/revoke", chainMiddleware(server.RevokeShareLink, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))

	return mux
}

// chainMiddleware applies multiple middleware to a handler function
func chainMiddleware(handler http.HandlerFunc, middleware ...func(http.Handler) http.Handler) http.HandlerFunc {
	h := http.Handler(handler)
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}
}

// methodMiddleware creates middleware that checks for specific HTTP method
func methodMiddleware(method string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// pathMiddleware creates middleware that checks URL path prefix
func pathMiddleware(prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, prefix) {
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
