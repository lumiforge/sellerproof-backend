package ydb

import (
	"time"
)

// User представляет пользователя в системе
type User struct {
	UserID                string    `db:"user_id"`
	Email                 string    `db:"email"`
	PasswordHash          string    `db:"password_hash"`
	FullName              string    `db:"full_name"`
	EmailVerified         bool      `db:"email_verified"`
	VerificationCode      string    `db:"verification_code"`
	VerificationExpiresAt time.Time `db:"verification_expires_at"`
	CreatedAt             time.Time `db:"created_at"`
	UpdatedAt             time.Time `db:"updated_at"`
	IsActive              bool      `db:"is_active"`
}

// Organization представляет организацию
type Organization struct {
	OrgID     string            `db:"org_id"`
	Name      string            `db:"name"`
	OwnerID   string            `db:"owner_id"`
	Settings  map[string]string `db:"settings"`
	CreatedAt time.Time         `db:"created_at"`
	UpdatedAt time.Time         `db:"updated_at"`
}

// Membership представляет членство в организации
type Membership struct {
	MembershipID string    `db:"membership_id"`
	UserID       string    `db:"user_id"`
	OrgID        string    `db:"org_id"`
	Role         string    `db:"role"`
	Status       string    `db:"status"`
	InvitedBy    string    `db:"invited_by"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

// Plan представляет тарифный план
type Plan struct {
	PlanID          string            `db:"plan_id"`
	Name            string            `db:"name"`
	StorageLimitGB  int64             `db:"storage_limit_gb"`
	VideoCountLimit int64             `db:"video_count_limit"`
	PriceRub        float64           `db:"price_rub"`
	BillingCycle    string            `db:"billing_cycle"`
	Features        map[string]string `db:"features"`
	CreatedAt       time.Time         `db:"created_at"`
	UpdatedAt       time.Time         `db:"updated_at"`
}

// Subscription представляет подписку
type Subscription struct {
	SubscriptionID  string    `db:"subscription_id"`
	UserID          string    `db:"user_id"`
	OrgID           string    `db:"org_id"`
	PlanID          string    `db:"plan_id"`
	StorageLimitGB  int64     `db:"storage_limit_gb"`
	VideoCountLimit int64     `db:"video_count_limit"`
	IsActive        bool      `db:"is_active"`
	TrialEndsAt     time.Time `db:"trial_ends_at"`
	StartedAt       time.Time `db:"started_at"`
	ExpiresAt       time.Time `db:"expires_at"`
	BillingCycle    string    `db:"billing_cycle"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

// SubscriptionHistory представляет историю изменений подписок
type SubscriptionHistory struct {
	HistoryID       string    `db:"history_id"`
	SubscriptionID  string    `db:"subscription_id"`
	PlanID          string    `db:"plan_id"`
	StorageLimitGB  int64     `db:"storage_limit_gb"`
	VideoCountLimit int64     `db:"video_count_limit"`
	EventType       string    `db:"event_type"`
	ChangedAt       time.Time `db:"changed_at"`
}

// EmailLog представляет лог отправленного email
type EmailLog struct {
	EmailID          string    `db:"email_id"`
	UserID           string    `db:"user_id"`
	EmailType        string    `db:"email_type"`
	Recipient        string    `db:"recipient"`
	Status           string    `db:"status"`
	PostboxMessageID string    `db:"postbox_message_id"`
	SentAt           time.Time `db:"sent_at"`
	DeliveredAt      time.Time `db:"delivered_at"`
	ErrorMessage     string    `db:"error_message"`
}

// RefreshToken представляет refresh токен
type RefreshToken struct {
	TokenID   string    `db:"token_id"`
	UserID    string    `db:"user_id"`
	TokenHash string    `db:"token_hash"`
	ExpiresAt time.Time `db:"expires_at"`
	CreatedAt time.Time `db:"created_at"`
	IsRevoked bool      `db:"is_revoked"`
}
