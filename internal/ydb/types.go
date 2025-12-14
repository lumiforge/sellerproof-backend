package ydb

import (
	"time"
)

// User представляет пользователя в системе
type User struct {
	UserID                 string     `db:"user_id"`
	Email                  string     `db:"email"`
	PasswordHash           string     `db:"password_hash"`
	FullName               string     `db:"full_name"`
	EmailVerified          bool       `db:"email_verified"`
	VerificationCode       string     `db:"verification_code"`
	VerificationExpiresAt  time.Time  `db:"verification_expires_at"`
	VerificationAttempts   int32      `db:"verification_attempts"`
	PasswordResetCode      *string    `db:"password_reset_code"`
	PasswordResetExpiresAt *time.Time `db:"password_reset_expires_at"`
	CreatedAt              time.Time  `db:"created_at"`
	UpdatedAt              time.Time  `db:"updated_at"`
	IsActive               bool       `db:"is_active"`
	LastOrgID              *string    `db:"last_org_id"`
}

// Organization представляет организацию
type Organization struct {
	OrgID     string    `db:"org_id"`
	Name      string    `db:"name"`
	OwnerID   string    `db:"owner_id"`
	Settings  string    `db:"settings"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
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
	PlanID          string    `db:"plan_id"`
	Name            string    `db:"name"`
	StorageLimitMB  int64     `db:"storage_limit_mb"`
	VideoCountLimit int64     `db:"video_count_limit"`
	PriceRub        float64   `db:"price_rub"`
	BillingCycle    string    `db:"billing_cycle"`
	Features        string    `db:"features"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

// Subscription представляет подписку
type Subscription struct {
	SubscriptionID  string    `db:"subscription_id"`
	UserID          string    `db:"user_id"`
	OrgID           string    `db:"org_id"`
	PlanID          string    `db:"plan_id"`
	StorageLimitMB  int64     `db:"storage_limit_mb"`
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
	StorageLimitMB  int64     `db:"storage_limit_mb"`
	VideoCountLimit int64     `db:"video_count_limit"`
	EventType       string    `db:"event_type"`
	ChangedAt       time.Time `db:"changed_at"`
}

// EmailLog представляет лог отправленного email
type EmailLog struct {
	EmailID          string     `db:"email_id"`
	UserID           string     `db:"user_id"`
	EmailType        string     `db:"email_type"`
	Recipient        string     `db:"recipient"`
	Status           string     `db:"status"`
	PostboxMessageID string     `db:"postbox_message_id"`
	SentAt           time.Time  `db:"sent_at"`
	DeliveredAt      *time.Time `db:"delivered_at"`
	ErrorMessage     *string    `db:"error_message"`
}

// Invitation представляет приглашение пользователя в организацию
// "pending": Приглашение создано, но не принято.
// "accepted": Пользователь принял приглашение (в этот момент создается Membership со статусом "active").
// "expired": Истек срок действия ссылки.
// "cancelled": Приглашение отозвано администратором.
type Invitation struct {
	InvitationID string     `db:"invitation_id"`
	OrgID        string     `db:"org_id"`
	Email        string     `db:"email"`
	Role         string     `db:"role"`
	InviteCode   string     `db:"invite_code"`
	InvitedBy    string     `db:"invited_by"`
	Status       string     `db:"status"` // "pending", "accepted", "expired", "cancelled"
	ExpiresAt    time.Time  `db:"expires_at"`
	CreatedAt    time.Time  `db:"created_at"`
	AcceptedAt   *time.Time `db:"accepted_at"`
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

// Video представляет видео файл
type Video struct {
	VideoID          string     `db:"video_id"`
	OrgID            string     `db:"org_id"`
	UploadedBy       string     `db:"uploaded_by"`
	AuthorName       string     `db:"author_name"`
	Title            string     `db:"title"`
	FileName         string     `db:"file_name"`
	FileNameSearch   string     `db:"file_name_search"`
	FileSizeBytes    int64      `db:"file_size_bytes"`
	StoragePath      string     `db:"storage_path"`
	DurationSeconds  int32      `db:"duration_seconds"`
	UploadID         string     `db:"upload_id"`
	UploadStatus     string     `db:"upload_status"`
	IsDeleted        bool       `db:"is_deleted"`
	DeletedAt        *time.Time `db:"deleted_at"`
	CreatedAt        time.Time  `db:"created_at"`
	PartsUploaded    *int32     `db:"parts_uploaded"`
	TotalParts       *int32     `db:"total_parts"`
	PublicShareToken *string    `db:"public_share_token"`
	ShareExpiresAt   *time.Time `db:"share_expires_at"`
	UploadedAt       *time.Time `db:"uploaded_at"`
	PublicURL        *string    `db:"public_url"`
	PublishStatus    string     `db:"publish_status"`
	PublishedAt      *time.Time `db:"published_at"`
	UploadExpiresAt  *time.Time `db:"upload_expires_at"`
}

// TrashVideo представляет видео в корзине
type TrashVideo struct {
	VideoID         string    `db:"video_id"`
	OrgID           string    `db:"org_id"`
	UploadedBy      string    `db:"uploaded_by"`
	Title           string    `db:"title"`
	FileName        string    `db:"file_name"`
	FileNameSearch  string    `db:"file_name_search"`
	FileSizeBytes   int64     `db:"file_size_bytes"`
	StoragePath     string    `db:"storage_path"`
	DurationSeconds int32     `db:"duration_seconds"`
	UploadID        string    `db:"upload_id"`
	UploadStatus    string    `db:"upload_status"`
	PartsUploaded   *int32    `db:"parts_uploaded"`
	TotalParts      *int32    `db:"total_parts"`
	CreatedAt       time.Time `db:"created_at"`
	UploadedAt      time.Time `db:"uploaded_at"`
	DeletedAt       time.Time `db:"deleted_at"`
	PublishStatus   string    `db:"publish_status"`
}

// PublicVideoShare представляет публичный шаринг видео
type PublicVideoShare struct {
	ShareID        string     `db:"share_id"`
	VideoID        string     `db:"video_id"`
	PublicToken    string     `db:"public_token"`
	CreatedAt      time.Time  `db:"created_at"`
	CreatedBy      string     `db:"created_by"`
	Revoked        bool       `db:"revoked"`
	RevokedAt      *time.Time `db:"revoked_at"`
	AccessCount    uint64     `db:"access_count"`
	LastAccessedAt *time.Time `db:"last_accessed_at"`
}
