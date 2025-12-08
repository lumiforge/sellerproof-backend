package http

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/lumiforge/sellerproof-backend/internal/jwt"
)

// SetupRouter creates and configures HTTP router
func SetupRouter(server *Server, jwtManager *jwt.JWTManager) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.Handle("/very-secret-health-check", chainMiddleware(server.Health, methodMiddleware("GET")))

	// Public video endpoint (no auth required)
	mux.HandleFunc("/api/v1/video/public", chainMiddleware(server.GetPublicVideo, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware))

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
	mux.HandleFunc("/api/v1/auth/forgot-password", chainMiddleware(server.ForgotPassword, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))
	mux.HandleFunc("/api/v1/auth/reset-password", chainMiddleware(server.ResetPassword, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware))

	// Protected auth routes
	mux.HandleFunc("/api/v1/auth/logout", chainMiddleware(server.Logout, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/auth/organizations", chainMiddleware(server.GetUserOrganizations, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/auth/profile", func(w http.ResponseWriter, r *http.Request) {
		// Apply basic middleware first
		CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Check method first before any auth or content-type validation
					if r.Method == "GET" {
						// For GET, apply auth middleware
						AuthMiddleware(jwtManager, server.authService, http.HandlerFunc(server.GetProfile)).ServeHTTP(w, r)
					} else if r.Method == "PUT" {
						// For PUT, apply content-type and auth middleware
						ContentTypeMiddleware(AuthMiddleware(jwtManager, server.authService, http.HandlerFunc(server.UpdateProfile))).ServeHTTP(w, r)
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
		return AuthMiddleware(jwtManager, server.authService, next)
	}))

	mux.HandleFunc("/api/v1/organization/create", chainMiddleware(server.CreateOrganization, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))

	mux.HandleFunc("/api/v1/organization", chainMiddleware(server.DeleteOrganization, methodMiddleware("DELETE"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))

	mux.HandleFunc("/api/v1/organization/name", chainMiddleware(server.UpdateOrganizationName, methodMiddleware("PUT"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))

	// Organization and Membership routes
	mux.HandleFunc("/api/v1/organization/invite", chainMiddleware(server.InviteUser, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/organization/invitations/accept", chainMiddleware(server.AcceptInvitation, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/organization/invitations", chainMiddleware(server.ListInvitations, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))

	// DELETE /api/v1/organization/invitations/{id} - manual path parsing
	mux.HandleFunc("/api/v1/organization/invitations/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/v1/organization/invitations/")
		if path == "" || strings.Contains(path, "/") {
			server.writeError(w, http.StatusBadRequest, "Invalid path: invitation_id is required")
			return
		}

		// Store ID in context
		// TODO should not use built-in type string as key for value; define your own type to avoid collisions (SA1029)go-staticcheck
		ctx := context.WithValue(r.Context(), "path_id", path)
		r = r.WithContext(ctx)

		// Apply middlewares and handler
		handler := chainMiddleware(server.CancelInvitation, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, func(next http.Handler) http.Handler {
			return AuthMiddleware(jwtManager, server.authService, next)
		})
		handler(w, r)
	})

	mux.HandleFunc("/api/v1/organization/members", chainMiddleware(server.ListMembers, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))

	// PUT /api/v1/organization/members/{user_id}/role - manual path parsing
	mux.HandleFunc("/api/v1/organization/members/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/organization/members/")
		parts := strings.Split(path, "/")

		if len(parts) >= 2 && parts[1] == "role" && r.Method == "PUT" {
			// Store user_id in context
			ctx := context.WithValue(r.Context(), "path_user_id", parts[0])
			r = r.WithContext(ctx)

			handler := chainMiddleware(server.UpdateMemberRole, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
				return AuthMiddleware(jwtManager, server.authService, next)
			})
			handler(w, r)
			return
		} else if len(parts) >= 2 && parts[1] == "status" && r.Method == "PUT" {
			// Store user_id in context
			ctx := context.WithValue(r.Context(), "path_user_id", parts[0])
			r = r.WithContext(ctx)

			handler := chainMiddleware(server.UpdateMemberStatus, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
				return AuthMiddleware(jwtManager, server.authService, next)
			})
			handler(w, r)
			return
		} else if len(parts) == 1 && r.Method == "DELETE" {
			// Store user_id in context
			ctx := context.WithValue(r.Context(), "path_user_id", parts[0])
			r = r.WithContext(ctx)

			handler := chainMiddleware(server.RemoveMember, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, func(next http.Handler) http.Handler {
				return AuthMiddleware(jwtManager, server.authService, next)
			})
			handler(w, r)
			return
		}

		http.Error(w, "Not found", http.StatusNotFound)
	})

	/* REMOVED - replaced by manual routing above
	// PUT /api/v1/organization/members/{user_id}/role
	mux.HandleFunc("/api/v1/organization/members/{user_id}/role", chainMiddleware(server.UpdateMemberRole, methodMiddleware("PUT"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	// PUT /api/v1/organization/members/{user_id}/status
	mux.HandleFunc("/api/v1/organization/members/{user_id}/status", chainMiddleware(server.UpdateMemberStatus, methodMiddleware("PUT"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	// DELETE /api/v1/organization/members/{user_id}
	mux.HandleFunc("/api/v1/organization/members/{user_id}", chainMiddleware(server.RemoveMember, methodMiddleware("DELETE"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	*/

	// Protected video routes
	mux.HandleFunc("/api/v1/video/upload/initiate", chainMiddleware(server.InitiateMultipartUpload, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/video/upload/urls", chainMiddleware(server.GetPartUploadURLs, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/video/upload/complete", chainMiddleware(server.CompleteMultipartUpload, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/video", chainMiddleware(server.GetVideo, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))

	// DELETE /api/v1/video/{id} - manual path parsing
	mux.HandleFunc("/api/v1/video/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/api/v1/video/")
		if path == "" || strings.Contains(path, "/") {
			http.Error(w, "Invalid path", http.StatusNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), "path_id", path)
		r = r.WithContext(ctx)

		handler := chainMiddleware(server.DeleteVideo, CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, func(next http.Handler) http.Handler {
			return AuthMiddleware(jwtManager, server.authService, next)
		})
		handler(w, r)
	})
	mux.HandleFunc("/api/v1/video/search", chainMiddleware(server.SearchVideos, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/video/publish", chainMiddleware(server.PublishVideo, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/video/revoke", chainMiddleware(server.RevokeVideo, methodMiddleware("POST"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))
	mux.HandleFunc("/api/v1/video/download", chainMiddleware(server.DownloadVideo, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, ContentTypeMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
	}))

	// Admin routes
	mux.HandleFunc("/api/v1/admin/audit-logs", chainMiddleware(server.GetAuditLogs, methodMiddleware("GET"), CORSMiddleware, RequestIDMiddleware, LoggingMiddleware, func(next http.Handler) http.Handler {
		return AuthMiddleware(jwtManager, server.authService, next)
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
