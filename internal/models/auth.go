package models

// Auth Request/Response Models

// RegisterRequest represents a registration request
// @Description	Registration request with user details
type RegisterRequest struct {
	Email            string `json:"email" validate:"required,email"`
	Password         string `json:"password" validate:"required,min=8"`
	FullName         string `json:"full_name" validate:"required"`
	OrganizationName string `json:"organization_name"`
}

// RegisterResponse represents a registration response
// @Description	Registration response with user ID and message
type RegisterResponse struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

// VerifyEmailRequest represents an email verification request
// @Description	Email verification request with email and code
type VerifyEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required"`
}

// VerifyEmailResponse represents an email verification response
// @Description	Email verification response with success status
type VerifyEmailResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// LoginRequest represents a login request
// @Description	Login request with email and password
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse represents a login response
// @Description	Login response with tokens and user info
type LoginResponse struct {
	AccessToken   string              `json:"access_token"`
	RefreshToken  string              `json:"refresh_token"`
	ExpiresAt     int64               `json:"expires_at"`
	User          *UserInfo           `json:"user"`
	Organizations []*OrganizationInfo `json:"organizations"`
}

// RefreshTokenRequest represents a refresh token request
// @Description	Refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// RefreshTokenResponse represents a refresh token response
// @Description	Refresh token response with new tokens
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// LogoutRequest represents a logout request
// @Description	Logout request with refresh token
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// LogoutResponse represents a logout response
// @Description	Logout response with message
type LogoutResponse struct {
	Message string `json:"message"`
}

// GetProfileRequest represents a profile get request
// @Description	Get profile request
type GetProfileRequest struct {
	UserID string `json:"user_id"`
}

// GetProfileResponse represents a profile get response
// @Description	Get profile response with user info
type GetProfileResponse struct {
	User *UserInfo `json:"user"`
}

// UpdateProfileRequest represents a profile update request
// @Description	Profile update request with full name
type UpdateProfileRequest struct {
	FullName string `json:"full_name" validate:"required"`
}

// UserInfo represents user information
// @Description	User profile information
type UserInfo struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	FullName      string `json:"full_name"`
	Role          string `json:"role"`
	OrgID         string `json:"org_id"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
}

// OrganizationInfo represents information about user's organization
// @Description	Organization information for user
type OrganizationInfo struct {
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// SwitchOrganizationRequest represents a request to switch organization
// @Description	Switch organization request
type SwitchOrganizationRequest struct {
	OrgID string `json:"org_id"`
}

// SwitchOrganizationResponse represents a response for organization switching
// @Description	Switch organization response
type SwitchOrganizationResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"`
	OrgID       string `json:"org_id"`
}
