package http

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/lumiforge/sellerproof-backend/internal/jwt"
)

// SetupRouter creates and configures HTTP router
func SetupRouter(server *Server, jwtManager *jwt.JWTManager) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.Handle("/very-secret-health-check", chainMiddleware(server.Health, methodMiddleware("GET")))

	// OpenAPI documentation endpoint (no auth required)
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		// Serve the generated OpenAPI specification
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Read the generated swagger.json file
		data, err := os.ReadFile("docs/swagger.json")
		if err != nil {
			http.Error(w, "OpenAPI documentation not found", http.StatusNotFound)
			return
		}

		// Validate it's valid JSON
		var jsonData interface{}
		if err := json.Unmarshal(data, &jsonData); err != nil {
			http.Error(w, "Invalid OpenAPI documentation", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(data)
	})

	// Auth routes (no auth required)
	mux.Handle("/api/v1/auth/register", chainMiddleware(server.Register, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))
	mux.HandleFunc("/api/v1/auth/login", chainMiddleware(server.Login, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))
	mux.HandleFunc("/api/v1/auth/refresh", chainMiddleware(server.RefreshToken, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))
	mux.HandleFunc("/api/v1/auth/verify-email", chainMiddleware(server.VerifyEmail, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))

	// Protected auth routes
	mux.HandleFunc("/api/v1/auth/logout", chainMiddleware(server.Logout, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/auth/profile", func(w http.ResponseWriter, r *http.Request) {
		// Apply basic middleware first
		CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Check method first before any auth or content-type validation
					if r.Method == "GET" {
						// For GET, apply auth middleware
						AuthMiddleware(jwtManager, http.HandlerFunc(server.GetProfile)).ServeHTTP(w, r)
					} else if r.Method == "PUT" {
						// For PUT, apply content-type and auth middleware
						ContentTypeMiddleware(AuthMiddleware(jwtManager, http.HandlerFunc(server.UpdateProfile))).ServeHTTP(w, r)
					} else {
						// Method not allowed
						http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
					}
				})).ServeHTTP(w, r)
			})).ServeHTTP(w, r)
		})).ServeHTTP(w, r)
	})

	// Organization routes
	mux.HandleFunc("/api/v1/auth/switch-organization", chainMiddleware(server.SwitchOrganization, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))

	mux.HandleFunc("/api/v1/organization/create", chainMiddleware(server.CreateOrganization, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))

	// Organization and Membership routes
	mux.HandleFunc("/api/v1/organization/invite", chainMiddleware(server.InviteUser, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/organization/invitations/accept", chainMiddleware(server.AcceptInvitation, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/organization/invitations", chainMiddleware(server.ListInvitations, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/organization/invitations/", func(w http.ResponseWriter, r *http.Request) {
		// Handle DELETE /api/v1/organization/invitations/{id}
		if r.Method == "DELETE" {
			// Extract invitation ID from path (simple parsing)
			path := r.URL.Path
			// Path format: /api/v1/organization/invitations/{id}
			parts := len(path) - len("/api/v1/organization/invitations/")
			if parts > 0 {
				// For now, reject DELETE as we need path parameter support
				// In a real implementation, you'd use a router that supports path params
				http.Error(w, "Method not implemented in this router", http.StatusNotImplemented)
			} else {
				http.Error(w, "Invalid path", http.StatusBadRequest)
			}
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/organization/members", chainMiddleware(server.ListMembers, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	// PUT /api/v1/organization/members/{user_id}/role
	mux.HandleFunc("PUT /api/v1/organization/members/{user_id}/role", chainMiddleware(server.UpdateMemberRole, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	// DELETE /api/v1/organization/members/{user_id}
	mux.HandleFunc("DELETE /api/v1/organization/members/{user_id}", chainMiddleware(server.RemoveMember, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))

	// Protected video routes
	mux.HandleFunc("/api/v1/video/upload/initiate", chainMiddleware(server.InitiateMultipartUpload, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/upload/urls", chainMiddleware(server.GetPartUploadURLs, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/upload/complete", chainMiddleware(server.CompleteMultipartUpload, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video", chainMiddleware(server.GetVideo, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/delete", chainMiddleware(server.DeleteVideo, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/search", chainMiddleware(server.SearchVideos, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/publish", chainMiddleware(server.PublishVideo, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))
	mux.HandleFunc("/api/v1/video/download", chainMiddleware(server.DownloadVideo, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, next)
	}))

	// Admin routes
	mux.HandleFunc("/api/v1/admin/audit-logs", chainMiddleware(server.GetAuditLogs, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, func(next http.Handler) http.Handler {
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
// func pathMiddleware(prefix string) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			if !strings.HasPrefix(r.URL.Path, prefix) {
// 				http.NotFound(w, r)
// 				return
// 			}
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }
