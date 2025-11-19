package ydb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lumiforge/sellerproof-backend/internal/config"
)

// YDBClient реализация интерфейса Database
type YDBClient struct {
	db *sql.DB
}

// NewYDBClient создает новый клиент YDB
func NewYDBClient(ctx context.Context, cfg *config.Config) (*YDBClient, error) {
	endpoint := cfg.SPYDBEndpoint
	database := cfg.SPYDBDatabasePath

	if endpoint == "" || database == "" {
		return nil, fmt.Errorf("YDB endpoint and database path must be set")
	}

	// Временно используем SQLite для демонстрации
	// В реальном проекте здесь будет подключение к YDB
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Создаем таблицы
	client := &YDBClient{db: db}
	err = client.createTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return client, nil
}

// createTables создает таблицы в базе данных
func (c *YDBClient) createTables(ctx context.Context) error {
	// Таблица пользователей
	_, err := c.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			user_id TEXT PRIMARY KEY,
			email TEXT UNIQUE,
			password_hash TEXT,
			full_name TEXT,
			email_verified BOOLEAN DEFAULT FALSE,
			verification_code TEXT,
			verification_expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_active BOOLEAN DEFAULT TRUE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Таблица организаций
	_, err = c.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS organizations (
			org_id TEXT PRIMARY KEY,
			name TEXT,
			owner_id TEXT,
			settings TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create organizations table: %w", err)
	}

	// Таблица членства
	_, err = c.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS memberships (
			membership_id TEXT PRIMARY KEY,
			user_id TEXT,
			org_id TEXT,
			role TEXT,
			status TEXT,
			invited_by TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create memberships table: %w", err)
	}

	// Таблица refresh токенов
	_, err = c.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS refresh_tokens (
			token_id TEXT PRIMARY KEY,
			user_id TEXT,
			token_hash TEXT,
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_revoked BOOLEAN DEFAULT FALSE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create refresh_tokens table: %w", err)
	}

	// Таблица email логов
	_, err = c.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS email_logs (
			email_id TEXT PRIMARY KEY,
			user_id TEXT,
			email_type TEXT,
			recipient TEXT,
			status TEXT,
			postbox_message_id TEXT,
			sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			delivered_at DATETIME,
			error_message TEXT
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create email_logs table: %w", err)
	}

	// Таблица тарифных планов
	_, err = c.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS plans (
			plan_id TEXT PRIMARY KEY,
			name TEXT,
			storage_limit_gb INTEGER,
			video_count_limit INTEGER,
			price_rub REAL,
			billing_cycle TEXT,
			features TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create plans table: %w", err)
	}

	// Вставляем базовые тарифные планы
	_, err = c.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO plans (plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features) VALUES
		('free', 'Free', 1, 10, 0, 'monthly', '{"sharing": false, "search": true}'),
		('pro', 'Pro', 100, 1000, 990, 'monthly', '{"sharing": true, "search": true, "analytics": true}'),
		('enterprise', 'Enterprise', 0, 0, 4990, 'monthly', '{"sharing": true, "search": true, "analytics": true, "api_access": true, "priority_support": true}')
	`)
	if err != nil {
		return fmt.Errorf("failed to insert plans: %w", err)
	}

	// Таблица подписок
	_, err = c.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS subscriptions (
			subscription_id TEXT PRIMARY KEY,
			user_id TEXT,
			org_id TEXT,
			plan_id TEXT,
			storage_limit_gb INTEGER,
			video_count_limit INTEGER,
			is_active BOOLEAN DEFAULT TRUE,
			trial_ends_at DATETIME,
			started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME,
			billing_cycle TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create subscriptions table: %w", err)
	}

	// Таблица видео
	_, err = c.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS videos (
			video_id TEXT PRIMARY KEY,
			org_id TEXT,
			uploaded_by TEXT,
			file_name TEXT,
			file_name_search TEXT,
			file_size_bytes INTEGER,
			storage_path TEXT,
			duration_seconds INTEGER,
			upload_id TEXT,
			upload_status TEXT,
			parts_uploaded INTEGER,
			total_parts INTEGER,
			public_share_token TEXT,
			share_expires_at DATETIME,
			uploaded_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_deleted BOOLEAN DEFAULT FALSE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create videos table: %w", err)
	}

	return nil
}

// Close закрывает соединение с базой данных
func (c *YDBClient) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// Initialize создает таблицы в базе данных
func (c *YDBClient) Initialize(ctx context.Context) error {
	// Таблицы уже создаются в createTables
	return nil
}

// CreateUser создает нового пользователя
func (c *YDBClient) CreateUser(ctx context.Context, user *User) error {
	query := `
		INSERT INTO users (
			user_id, email, password_hash, full_name, email_verified,
			verification_code, verification_expires_at, created_at, updated_at, is_active
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}

	_, err := c.db.ExecContext(ctx, query,
		user.UserID, user.Email, user.PasswordHash, user.FullName,
		user.EmailVerified, user.VerificationCode, user.VerificationExpiresAt,
		user.CreatedAt, user.UpdatedAt, user.IsActive,
	)

	return err
}

// GetUserByID получает пользователя по ID
func (c *YDBClient) GetUserByID(ctx context.Context, userID string) (*User, error) {
	query := `
		SELECT user_id, email, password_hash, full_name, email_verified,
			   verification_code, verification_expires_at, created_at, updated_at, is_active
		FROM users
		WHERE user_id = ?
	`

	var user User
	err := c.db.QueryRowContext(ctx, query, userID).Scan(
		&user.UserID, &user.Email, &user.PasswordHash, &user.FullName,
		&user.EmailVerified, &user.VerificationCode, &user.VerificationExpiresAt,
		&user.CreatedAt, &user.UpdatedAt, &user.IsActive,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByEmail получает пользователя по email
func (c *YDBClient) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT user_id, email, password_hash, full_name, email_verified,
			   verification_code, verification_expires_at, created_at, updated_at, is_active
		FROM users
		WHERE email = ?
	`

	var user User
	err := c.db.QueryRowContext(ctx, query, email).Scan(
		&user.UserID, &user.Email, &user.PasswordHash, &user.FullName,
		&user.EmailVerified, &user.VerificationCode, &user.VerificationExpiresAt,
		&user.CreatedAt, &user.UpdatedAt, &user.IsActive,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// UpdateUser обновляет данные пользователя
func (c *YDBClient) UpdateUser(ctx context.Context, user *User) error {
	query := `
		UPDATE users SET 
			email = ?, full_name = ?, email_verified = ?,
			verification_code = ?, verification_expires_at = ?, updated_at = ?, is_active = ?
		WHERE user_id = ?
	`

	user.UpdatedAt = time.Now()

	_, err := c.db.ExecContext(ctx, query,
		user.Email, user.FullName, user.EmailVerified,
		user.VerificationCode, user.VerificationExpiresAt, user.UpdatedAt, user.IsActive, user.UserID,
	)

	return err
}

// CreateOrganization создает новую организацию
func (c *YDBClient) CreateOrganization(ctx context.Context, org *Organization) error {
	query := `
		INSERT INTO organizations (org_id, name, owner_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`

	now := time.Now()
	if org.CreatedAt.IsZero() {
		org.CreatedAt = now
	}
	if org.UpdatedAt.IsZero() {
		org.UpdatedAt = now
	}

	_, err := c.db.ExecContext(ctx, query,
		org.OrgID, org.Name, org.OwnerID, org.CreatedAt, org.UpdatedAt,
	)

	return err
}

// CreateMembership создает членство в организации
func (c *YDBClient) CreateMembership(ctx context.Context, membership *Membership) error {
	query := `
		INSERT INTO memberships (
			membership_id, user_id, org_id, role, status, invited_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	if membership.CreatedAt.IsZero() {
		membership.CreatedAt = now
	}
	if membership.UpdatedAt.IsZero() {
		membership.UpdatedAt = now
	}

	_, err := c.db.ExecContext(ctx, query,
		membership.MembershipID, membership.UserID, membership.OrgID,
		membership.Role, membership.Status, membership.InvitedBy,
		membership.CreatedAt, membership.UpdatedAt,
	)

	return err
}

// GetMembership получает членство по пользователю и организации
func (c *YDBClient) GetMembership(ctx context.Context, userID, orgID string) (*Membership, error) {
	query := `
		SELECT membership_id, user_id, org_id, role, status, invited_by, created_at, updated_at
		FROM memberships
		WHERE user_id = ? AND org_id = ?
	`

	var membership Membership
	err := c.db.QueryRowContext(ctx, query, userID, orgID).Scan(
		&membership.MembershipID, &membership.UserID, &membership.OrgID,
		&membership.Role, &membership.Status, &membership.InvitedBy,
		&membership.CreatedAt, &membership.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &membership, nil
}

// CreateRefreshToken создает новый refresh токен
func (c *YDBClient) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (token_id, user_id, token_hash, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	now := time.Now()
	if token.CreatedAt.IsZero() {
		token.CreatedAt = now
	}

	_, err := c.db.ExecContext(ctx, query,
		token.TokenID, token.UserID, token.TokenHash, token.ExpiresAt, token.CreatedAt,
	)

	return err
}

// GetRefreshToken получает refresh токен по хешу
func (c *YDBClient) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	query := `
		SELECT token_id, user_id, token_hash, expires_at, created_at, is_revoked
		FROM refresh_tokens
		WHERE token_hash = ?
	`

	var token RefreshToken
	err := c.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.TokenID, &token.UserID, &token.TokenHash,
		&token.ExpiresAt, &token.CreatedAt, &token.IsRevoked,
	)

	if err != nil {
		return nil, err
	}

	return &token, nil
}

// RevokeRefreshToken отзывает refresh токен
func (c *YDBClient) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE refresh_tokens SET is_revoked = TRUE WHERE token_hash = ?
	`

	_, err := c.db.ExecContext(ctx, query, tokenHash)
	return err
}

// CreateEmailLog создает запись в логе email
func (c *YDBClient) CreateEmailLog(ctx context.Context, log *EmailLog) error {
	query := `
		INSERT INTO email_logs (
			email_id, user_id, email_type, recipient, status, postbox_message_id, sent_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	if log.SentAt.IsZero() {
		log.SentAt = now
	}

	_, err := c.db.ExecContext(ctx, query,
		log.EmailID, log.UserID, log.EmailType, log.Recipient,
		log.Status, log.PostboxMessageID, log.SentAt,
	)

	return err
}

// GetPlanByID получает тарифный план по ID
func (c *YDBClient) GetPlanByID(ctx context.Context, planID string) (*Plan, error) {
	query := `
		SELECT plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at
		FROM plans
		WHERE plan_id = ?
	`

	var plan Plan
	err := c.db.QueryRowContext(ctx, query, planID).Scan(
		&plan.PlanID, &plan.Name, &plan.StorageLimitGB, &plan.VideoCountLimit,
		&plan.PriceRub, &plan.BillingCycle, &plan.Features,
		&plan.CreatedAt, &plan.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &plan, nil
}

// CreateSubscription создает новую подписку
func (c *YDBClient) CreateSubscription(ctx context.Context, subscription *Subscription) error {
	query := `
		INSERT INTO subscriptions (
			subscription_id, user_id, org_id, plan_id, storage_limit_gb, video_count_limit,
			is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	if subscription.CreatedAt.IsZero() {
		subscription.CreatedAt = now
	}
	if subscription.UpdatedAt.IsZero() {
		subscription.UpdatedAt = now
	}

	_, err := c.db.ExecContext(ctx, query,
		subscription.SubscriptionID, subscription.UserID, subscription.OrgID, subscription.PlanID,
		subscription.StorageLimitGB, subscription.VideoCountLimit, subscription.IsActive,
		subscription.TrialEndsAt, subscription.StartedAt, subscription.ExpiresAt,
		subscription.BillingCycle, subscription.CreatedAt, subscription.UpdatedAt,
	)

	return err
}

// GetSubscriptionByUser получает активную подписку пользователя
func (c *YDBClient) GetSubscriptionByUser(ctx context.Context, userID string) (*Subscription, error) {
	query := `
		SELECT subscription_id, user_id, org_id, plan_id, storage_limit_gb, video_count_limit,
			   is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		FROM subscriptions
		WHERE user_id = ? AND is_active = TRUE
		ORDER BY created_at DESC
		LIMIT 1
	`

	var subscription Subscription
	err := c.db.QueryRowContext(ctx, query, userID).Scan(
		&subscription.SubscriptionID, &subscription.UserID, &subscription.OrgID,
		&subscription.PlanID, &subscription.StorageLimitGB, &subscription.VideoCountLimit,
		&subscription.IsActive, &subscription.TrialEndsAt, &subscription.StartedAt,
		&subscription.ExpiresAt, &subscription.BillingCycle,
		&subscription.CreatedAt, &subscription.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &subscription, nil
}

// Остальные методы реализуются по аналогии...
func (c *YDBClient) DeleteUser(ctx context.Context, userID string) error {
	// Реализация...
	return nil
}

func (c *YDBClient) GetOrganizationByID(ctx context.Context, orgID string) (*Organization, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) GetOrganizationsByOwner(ctx context.Context, ownerID string) ([]*Organization, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) UpdateOrganization(ctx context.Context, org *Organization) error {
	// Реализация...
	return nil
}

func (c *YDBClient) GetMembershipsByUser(ctx context.Context, userID string) ([]*Membership, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) GetMembershipsByOrg(ctx context.Context, orgID string) ([]*Membership, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) UpdateMembership(ctx context.Context, membership *Membership) error {
	// Реализация...
	return nil
}

func (c *YDBClient) DeleteMembership(ctx context.Context, membershipID string) error {
	// Реализация...
	return nil
}

func (c *YDBClient) GetAllPlans(ctx context.Context) ([]*Plan, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) GetSubscriptionByID(ctx context.Context, subscriptionID string) (*Subscription, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) GetSubscriptionByOrg(ctx context.Context, orgID string) (*Subscription, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) UpdateSubscription(ctx context.Context, subscription *Subscription) error {
	// Реализация...
	return nil
}

func (c *YDBClient) CreateSubscriptionHistory(ctx context.Context, history *SubscriptionHistory) error {
	// Реализация...
	return nil
}

func (c *YDBClient) GetSubscriptionHistory(ctx context.Context, subscriptionID string) ([]*SubscriptionHistory, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) GetEmailLogsByUser(ctx context.Context, userID string) ([]*EmailLog, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) UpdateEmailLog(ctx context.Context, log *EmailLog) error {
	// Реализация...
	return nil
}

func (c *YDBClient) GetRefreshTokensByUser(ctx context.Context, userID string) ([]*RefreshToken, error) {
	// Реализация...
	return nil, nil
}

func (c *YDBClient) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	// Реализация...
	return nil
}

func (c *YDBClient) CleanupExpiredTokens(ctx context.Context) error {
	// Реализация...
	return nil
}

// CreateVideo создает запись о видео
func (c *YDBClient) CreateVideo(ctx context.Context, video *Video) error {
	query := `
		INSERT INTO videos (
			video_id, org_id, uploaded_by, file_name, file_name_search, file_size_bytes,
			storage_path, duration_seconds, upload_id, upload_status, created_at, is_deleted
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := c.db.ExecContext(ctx, query,
		video.VideoID, video.OrgID, video.UploadedBy, video.FileName, video.FileNameSearch,
		video.FileSizeBytes, video.StoragePath, video.DurationSeconds, video.UploadID,
		video.UploadStatus, time.Now(), video.IsDeleted,
	)
	return err
}

// GetVideo получает видео по ID
func (c *YDBClient) GetVideo(ctx context.Context, videoID string) (*Video, error) {
	query := `
		SELECT video_id, org_id, uploaded_by, file_name, file_size_bytes, storage_path,
		       duration_seconds, upload_id, upload_status, total_parts, public_share_token, share_expires_at, uploaded_at
		FROM videos WHERE video_id = ?
	`
	var v Video
	err := c.db.QueryRowContext(ctx, query, videoID).Scan(
		&v.VideoID, &v.OrgID, &v.UploadedBy, &v.FileName, &v.FileSizeBytes, &v.StoragePath,
		&v.DurationSeconds, &v.UploadID, &v.UploadStatus, &v.TotalParts, &v.PublicShareToken, &v.ShareExpiresAt, &v.UploadedAt,
	)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// UpdateVideo обновляет запись о видео
func (c *YDBClient) UpdateVideo(ctx context.Context, video *Video) error {
	query := `
		UPDATE videos SET
			upload_status = ?, parts_uploaded = ?, total_parts = ?,
			public_share_token = ?, share_expires_at = ?, uploaded_at = ?
		WHERE video_id = ?
	`
	_, err := c.db.ExecContext(ctx, query,
		video.UploadStatus, video.PartsUploaded, video.TotalParts,
		video.PublicShareToken, video.ShareExpiresAt, video.UploadedAt, video.VideoID,
	)
	return err
}

// GetStorageUsage возвращает использованный объем хранилища
func (c *YDBClient) GetStorageUsage(ctx context.Context, orgID string) (int64, error) {
	query := `
		SELECT COALESCE(SUM(file_size_bytes), 0)
		FROM videos
		WHERE org_id = ? AND is_deleted = FALSE AND upload_status != 'failed'
	`
	var usage int64
	err := c.db.QueryRowContext(ctx, query, orgID).Scan(&usage)
	if err != nil {
		return 0, err
	}
	return usage, nil
}

// GetVideoByShareToken получает видео по токену
func (c *YDBClient) GetVideoByShareToken(ctx context.Context, token string) (*Video, error) {
	query := `
		SELECT video_id, org_id, file_name, file_size_bytes, storage_path, share_expires_at
		FROM videos
		WHERE public_share_token = ? AND is_deleted = FALSE
	`
	var v Video
	err := c.db.QueryRowContext(ctx, query, token).Scan(
		&v.VideoID, &v.OrgID, &v.FileName, &v.FileSizeBytes, &v.StoragePath, &v.ShareExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// SearchVideos ищет видео с пагинацией
func (c *YDBClient) SearchVideos(ctx context.Context, orgID, userID, query string, limit, offset int) ([]*Video, int64, error) {
	baseQuery := `FROM videos WHERE org_id = ? AND is_deleted = FALSE`
	args := []interface{}{orgID}

	if userID != "" {
		baseQuery += ` AND uploaded_by = ?`
		args = append(args, userID)
	}

	if query != "" {
		baseQuery += ` AND file_name_search LIKE ?`
		args = append(args, "%"+strings.ToLower(query)+"%")
	}

	// Count total
	countQuery := `SELECT COUNT(*) ` + baseQuery
	var total int64
	err := c.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get data
	dataQuery := `SELECT video_id, org_id, uploaded_by, file_name, file_size_bytes, storage_path, duration_seconds, upload_status, uploaded_at ` + baseQuery + ` ORDER BY uploaded_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := c.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var videos []*Video
	for rows.Next() {
		var v Video
		if err := rows.Scan(&v.VideoID, &v.OrgID, &v.UploadedBy, &v.FileName, &v.FileSizeBytes, &v.StoragePath, &v.DurationSeconds, &v.UploadStatus, &v.UploadedAt); err != nil {
			return nil, 0, err
		}
		videos = append(videos, &v)
	}

	return videos, total, nil
}
