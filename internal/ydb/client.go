package ydb

import (
	"context"
	"fmt"
	"log"

	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lumiforge/sellerproof-backend/internal/config"
	"github.com/lumiforge/sellerproof-backend/internal/models"
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/table"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/result/named"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/types"
	yc "github.com/ydb-platform/ydb-go-yc"
)

// YDBClient реализация интерфейса Database
type YDBClient struct {
	driver       *ydb.Driver
	databasePath string
	config       *config.Config
}

// NewYDBClient создает новый клиент YDB
func NewYDBClient(ctx context.Context, cfg *config.Config) (*YDBClient, error) {
	endpoint := cfg.SPYDBEndpoint
	database := cfg.SPYDBDatabasePath

	if endpoint == "" || database == "" {
		return nil, fmt.Errorf("YDB credentials not provided. Please set SP_YDB_ENDPOINT and SP_YDB_DATABASE_PATH environment variables")
	}

	driver, err := ydb.Open(ctx, endpoint,
		ydb.WithDatabase(database),
		yc.WithMetadataCredentials(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to YDB: %w", err)
	}

	log.Println("Successfully connected to YDB")

	client := &YDBClient{
		driver:       driver,
		databasePath: database,
		config:       cfg,
	}

	// Создаём таблицы только если флаг установлен
	if cfg.SPYDBAutoCreateTables > 0 {
		log.Println("SP_YDB_AUTO_CREATE_TABLES is enabled, checking and creating tables...")
		err = client.createTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create tables: %w", err)
		}
	}

	return client, nil
}

// Close закрывает соединение с базой данных
func (c *YDBClient) Close() error {
	if c.driver != nil {
		return c.driver.Close(context.Background())
	}
	return nil
}

// Initialize создает таблицы в базе данных
func (c *YDBClient) Initialize(ctx context.Context) error {
	// Таблицы уже создаются в createTables
	return nil
}

// createTables создает таблицы в базе данных
func (c *YDBClient) createTables(ctx context.Context) error {
	log.Println("Starting table creation...")
	// Таблица пользователей
	log.Println("Creating table: users")
	if exists, err := c.tableExists(ctx, "users"); err != nil {
		return fmt.Errorf("failed to check users table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE users (
				user_id Text NOT NULL,
				email Text NOT NULL,
				password_hash Text NOT NULL,
				full_name Text NOT NULL,
				email_verified Bool DEFAULT false,
				verification_code Text NOT NULL,
				verification_expires_at Timestamp NOT NULL,
				created_at Timestamp NOT NULL,
				updated_at Timestamp NOT NULL,
				is_active Bool DEFAULT true,
				PRIMARY KEY (user_id),
				INDEX email_idx GLOBAL UNIQUE ON (email) COVER (password_hash, full_name, email_verified, is_active)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create users table: %w", err)
		}
	} else {
		log.Println("Table users already exists, skipping creation")
	}

	// Небольшая задержка между созданием таблиц для избежания лимита schema operations
	time.Sleep(500 * time.Millisecond)

	// Таблица организаций
	log.Println("Creating table: organizations")
	if exists, err := c.tableExists(ctx, "organizations"); err != nil {
		return fmt.Errorf("failed to check organizations table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE organizations (
				org_id Text NOT NULL,
				name Text NOT NULL,
				owner_id Text NOT NULL,
				settings Json NOT NULL,
				created_at Timestamp NOT NULL,
				updated_at Timestamp NOT NULL,
				PRIMARY KEY (org_id),
				INDEX owner_idx GLOBAL ON (owner_id)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create organizations table: %w", err)
		}
	} else {
		log.Println("Table organizations already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица членства
	log.Println("Creating table: memberships")
	if exists, err := c.tableExists(ctx, "memberships"); err != nil {
		return fmt.Errorf("failed to check memberships table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE memberships (
				membership_id Text NOT NULL,
				user_id Text NOT NULL,
				org_id Text NOT NULL,
				role Text NOT NULL,
				status Text NOT NULL,
				invited_by Text NOT NULL,
				created_at Timestamp NOT NULL,
				updated_at Timestamp NOT NULL,
				PRIMARY KEY (membership_id),
				INDEX user_idx GLOBAL ON (user_id),
				INDEX org_idx GLOBAL ON (org_id),
				INDEX user_org_idx GLOBAL ON (user_id, org_id)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create memberships table: %w", err)
		}
	} else {
		log.Println("Table memberships already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица refresh токенов
	log.Println("Creating table: refresh_tokens")
	if exists, err := c.tableExists(ctx, "refresh_tokens"); err != nil {
		return fmt.Errorf("failed to check refresh_tokens table existence: %w", err)
	} else if !exists {

		query := `
			CREATE TABLE refresh_tokens (
				token_id Text NOT NULL,
				user_id Text NOT NULL,
				token_hash Text NOT NULL,
				expires_at Timestamp NOT NULL,
				created_at Timestamp NOT NULL,
				is_revoked Bool DEFAULT false,
				PRIMARY KEY (token_id),
				INDEX user_idx GLOBAL ON (user_id),
				INDEX token_hash_idx GLOBAL ON (token_hash)
			)
		`

		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create refresh_tokens table: %w", err)
		}
	} else {
		log.Println("Table refresh_tokens already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица email логов
	log.Println("Creating table: email_logs")
	if exists, err := c.tableExists(ctx, "email_logs"); err != nil {
		return fmt.Errorf("failed to check email_logs table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE email_logs (
				email_id Text NOT NULL,
				user_id Text NOT NULL,
				email_type Text NOT NULL,
				recipient Text NOT NULL,
				status Text NOT NULL,
				postbox_message_id Text NOT NULL,
				sent_at Timestamp NOT NULL,
				delivered_at Timestamp NOT NULL,
				error_message Text NOT NULL,
				PRIMARY KEY (email_id),
				INDEX user_idx GLOBAL ON (user_id)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create email_logs table: %w", err)
		}
	} else {
		log.Println("Table email_logs already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица тарифных планов
	log.Println("Creating table: plans")
	if exists, err := c.tableExists(ctx, "plans"); err != nil {
		return fmt.Errorf("failed to check plans table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE plans (
				plan_id Text NOT NULL,
				name Text NOT NULL,
				storage_limit_mb Int64 NOT NULL,
				video_count_limit Int64 NOT NULL,
				price_rub Double NOT NULL,
				billing_cycle Text NOT NULL,
				features Json NOT NULL,
				created_at Timestamp NOT NULL,
				updated_at Timestamp NOT NULL,
				PRIMARY KEY (plan_id)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create plans table: %w", err)
		}

		// Вставляем базовые тарифные планы только после создания таблицы
		plansQuery := fmt.Sprintf(`
			REPLACE INTO plans (plan_id, name, storage_limit_mb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at)
			VALUES
			('free', 'Free', %d, %d, %.2f, 'monthly', '{"sharing": false, "search": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp()),
			('pro', 'Pro', %d, %d, %.2f, 'monthly', '{"sharing": true, "search": true, "analytics": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp()),
			('enterprise', 'Enterprise', %d, %d, %.2f, 'monthly', '{"sharing": true, "search": true, "analytics": true, "api_access": true, "priority_support": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp())
		`,
			c.config.StorageLimitFree, c.config.VideoCountLimitFree, c.config.PriceRubFree,
			c.config.StorageLimitPro, c.config.VideoCountLimitPro, c.config.PriceRubPro,
			c.config.StorageLimitEnterprise, c.config.VideoCountLimitEnterprise, c.config.PriceRubEnterprise,
		)
		if err := c.executeQuery(ctx, plansQuery); err != nil {
			return fmt.Errorf("failed to insert plans: %w", err)
		}
	} else {
		log.Println("Table plans already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица подписок
	log.Println("Creating table: subscriptions")
	if exists, err := c.tableExists(ctx, "subscriptions"); err != nil {
		return fmt.Errorf("failed to check subscriptions table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE subscriptions (
				subscription_id Text NOT NULL,
				user_id Text NOT NULL,
				org_id Text NOT NULL,
				plan_id Text NOT NULL,
				storage_limit_mb Int64 NOT NULL,
				video_count_limit Int64 NOT NULL,
				is_active Bool DEFAULT true,
				trial_ends_at Timestamp NOT NULL,
				started_at Timestamp NOT NULL,
				expires_at Timestamp NOT NULL,
				billing_cycle Text NOT NULL,
				created_at Timestamp NOT NULL,
				updated_at Timestamp NOT NULL,
				PRIMARY KEY (subscription_id),
				INDEX user_idx GLOBAL ON (user_id),
				INDEX org_idx GLOBAL ON (org_id)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create subscriptions table: %w", err)
		}
	} else {
		log.Println("Table subscriptions already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица видео
	log.Println("Creating table: videos")
	if exists, err := c.tableExists(ctx, "videos"); err != nil {
		return fmt.Errorf("failed to check videos table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE videos (
				video_id Text NOT NULL,
				org_id Text NOT NULL,
				uploaded_by Text NOT NULL,
				file_name Text NOT NULL,
				file_name_search Text NOT NULL,
				file_size_bytes Int64 NOT NULL,
				storage_path Text NOT NULL,
				duration_seconds Int32 NOT NULL,
				upload_id Text NOT NULL,
				upload_status Text NOT NULL,
				parts_uploaded Optional<Int32>,
				total_parts Optional<Int32>,
				public_share_token Optional<Text>,
				share_expires_at Optional<Timestamp>,
				uploaded_at Optional<Timestamp>,
				created_at Timestamp NOT NULL,
				is_deleted Bool DEFAULT false,
				PRIMARY KEY (video_id),
				INDEX org_idx GLOBAL ON (org_id),
				INDEX org_user_idx GLOBAL ON (org_id, uploaded_by),
				INDEX org_deleted_idx GLOBAL ON (org_id, is_deleted),
				INDEX share_token_idx GLOBAL ON (public_share_token)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create videos table: %w", err)
		}
	} else {
		log.Println("Table videos already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица истории подписок
	log.Println("Creating table: subscription_history")
	if exists, err := c.tableExists(ctx, "subscription_history"); err != nil {
		return fmt.Errorf("failed to check subscription_history table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE subscription_history (
				history_id Text NOT NULL,
				subscription_id Text NOT NULL,
				plan_id Text NOT NULL,
				storage_limit_mb Int64 NOT NULL,
				video_count_limit Int64 NOT NULL,
				event_type Text NOT NULL,
				changed_at Timestamp NOT NULL,
				PRIMARY KEY (history_id),
				INDEX subscription_idx GLOBAL ON (subscription_id)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create subscription_history table: %w", err)
		}
	} else {
		log.Println("Table subscription_history already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица приглашений
	log.Println("Creating table: invitations")
	if exists, err := c.tableExists(ctx, "invitations"); err != nil {
		return fmt.Errorf("failed to check invitations table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE invitations (
				invitation_id Text NOT NULL,
				org_id Text NOT NULL,
				email Text NOT NULL,
				role Text NOT NULL,
				invite_code Text NOT NULL,
				invited_by Text NOT NULL,
				status Text NOT NULL,
				expires_at Timestamp NOT NULL,
				created_at Timestamp NOT NULL,
				accepted_at Timestamp,
				PRIMARY KEY (invitation_id),
				INDEX org_idx GLOBAL ON (org_id),
				INDEX email_idx GLOBAL ON (email),
				INDEX code_idx GLOBAL UNIQUE ON (invite_code)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create invitations table: %w", err)
		}
	} else {
		log.Println("Table invitations already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица логов аудита
	log.Println("Creating table: audit_logs")
	if exists, err := c.tableExists(ctx, "audit_logs"); err != nil {
		return fmt.Errorf("failed to check audit_logs table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE audit_logs (
				id Text NOT NULL,
				timestamp Timestamp NOT NULL,
				user_id Text NOT NULL,
				org_id Text NOT NULL,
				action_type Text NOT NULL,
				action_result Text NOT NULL,
				ip_address Text NOT NULL,
				user_agent Text,
				details Json,
				PRIMARY KEY (id),
				INDEX timestamp_idx GLOBAL ON (timestamp),
				INDEX user_id_idx GLOBAL ON (user_id),
				INDEX org_id_idx GLOBAL ON (org_id),
				INDEX action_type_idx GLOBAL ON (action_type),
				INDEX composite_idx GLOBAL ON (org_id, timestamp DESC)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create audit_logs table: %w", err)
		}
	} else {
		log.Println("Table audit_logs already exists, skipping creation")
	}

	return nil
}

// tableExists checks if a table exists in the database
func (c *YDBClient) tableExists(ctx context.Context, tableName string) (bool, error) {
	fullPath := path.Join(c.databasePath, tableName)
	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, err := session.DescribeTable(ctx, fullPath)
		return err
	})

	if err != nil {
		// If error contains "not found" or similar, table doesn't exist
		// YDB returns SchemeError with "Path not found" usually
		// Also check for code 400070 which is SCHEME_ERROR
		msg := err.Error()
		if strings.Contains(msg, "not found") ||
			strings.Contains(msg, "does not exist") ||
			strings.Contains(msg, "Path not found") ||
			strings.Contains(msg, "code = 400070") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// executeSchemeQuery выполняет DDL запрос
func (c *YDBClient) executeSchemeQuery(ctx context.Context, query string) error {
	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		return session.ExecuteSchemeQuery(ctx, query)
	})
}

// executeQuery выполняет запрос без параметров
func (c *YDBClient) executeQuery(ctx context.Context, query string) error {
	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query, table.NewQueryParameters())
		return err
	})
}

// CreateUser создает нового пользователя
func (c *YDBClient) CreateUser(ctx context.Context, user *User) error {
	query := `
		DECLARE $user_id AS Text;
		DECLARE $email AS Text;
		DECLARE $password_hash AS Text;
		DECLARE $full_name AS Text;
		DECLARE $email_verified AS Bool;
		DECLARE $verification_code AS Text;
		DECLARE $verification_expires_at AS Timestamp;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;
		DECLARE $is_active AS Bool;

		REPLACE INTO users (
			user_id, email, password_hash, full_name, email_verified,
			verification_code, verification_expires_at, created_at, updated_at, is_active
		) VALUES ($user_id, $email, $password_hash, $full_name, $email_verified, $verification_code, $verification_expires_at, $created_at, $updated_at, $is_active)
	`

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(user.UserID)),
				table.ValueParam("$email", types.TextValue(user.Email)),
				table.ValueParam("$password_hash", types.TextValue(user.PasswordHash)),
				table.ValueParam("$full_name", types.TextValue(user.FullName)),
				table.ValueParam("$email_verified", types.BoolValue(user.EmailVerified)),
				table.ValueParam("$verification_code", types.TextValue(user.VerificationCode)),
				table.ValueParam("$verification_expires_at", types.TimestampValueFromTime(user.VerificationExpiresAt)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(user.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(user.UpdatedAt)),
				table.ValueParam("$is_active", types.BoolValue(user.IsActive)),
			),
		)
		return err
	})
}

// GetUserByID получает пользователя по ID
func (c *YDBClient) GetUserByID(ctx context.Context, userID string) (*User, error) {
	query := `
		DECLARE $user_id AS Text;
		SELECT user_id, email, password_hash, full_name, email_verified,
			   verification_code, verification_expires_at, created_at, updated_at, is_active
		FROM users
		WHERE user_id = $user_id
	`

	var user User
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(userID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			err := res.ScanNamed(
				named.Required("user_id", &user.UserID),
				named.Required("email", &user.Email),
				named.Required("password_hash", &user.PasswordHash),
				named.Required("full_name", &user.FullName),
				named.Required("email_verified", &user.EmailVerified),
				named.Required("verification_code", &user.VerificationCode),
				named.Required("verification_expires_at", &user.VerificationExpiresAt),
				named.Required("created_at", &user.CreatedAt),
				named.Required("updated_at", &user.UpdatedAt),
				named.Required("is_active", &user.IsActive),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("user not found")
	}

	return &user, nil
}

// GetUserByEmail получает пользователя по email
func (c *YDBClient) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		DECLARE $email AS Text;
		SELECT user_id, email, password_hash, full_name, email_verified,
			   verification_code, verification_expires_at, created_at, updated_at, is_active
		FROM users
		WHERE email = $email
	`

	var user User
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$email", types.TextValue(email)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			err := res.ScanNamed(
				named.Required("user_id", &user.UserID),
				named.Required("email", &user.Email),
				named.Required("password_hash", &user.PasswordHash),
				named.Required("full_name", &user.FullName),
				named.Required("email_verified", &user.EmailVerified),
				named.Required("verification_code", &user.VerificationCode),
				named.Required("verification_expires_at", &user.VerificationExpiresAt),
				named.Required("created_at", &user.CreatedAt),
				named.Required("updated_at", &user.UpdatedAt),
				named.Required("is_active", &user.IsActive),
			)

			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("user not found")
	}

	return &user, nil
}

// UpdateUser обновляет данные пользователя
func (c *YDBClient) UpdateUser(ctx context.Context, user *User) error {
	query := `
		DECLARE $user_id AS Text;
		DECLARE $email AS Text;
		DECLARE $password_hash AS Text;
		DECLARE $full_name AS Text;
		DECLARE $email_verified AS Bool;
		DECLARE $verification_code AS Text;
		DECLARE $verification_expires_at AS Timestamp;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;
		DECLARE $is_active AS Bool;

		REPLACE INTO users (
			user_id, email, password_hash, full_name, email_verified,
			verification_code, verification_expires_at, created_at, updated_at, is_active
		) VALUES ($user_id, $email, $password_hash, $full_name, $email_verified, $verification_code, $verification_expires_at, $created_at, $updated_at, $is_active)
	`

	user.UpdatedAt = time.Now()

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(user.UserID)),
				table.ValueParam("$email", types.TextValue(user.Email)),
				table.ValueParam("$password_hash", types.TextValue(user.PasswordHash)),
				table.ValueParam("$full_name", types.TextValue(user.FullName)),
				table.ValueParam("$email_verified", types.BoolValue(user.EmailVerified)),
				table.ValueParam("$verification_code", types.TextValue(user.VerificationCode)),
				table.ValueParam("$verification_expires_at", types.TimestampValueFromTime(user.VerificationExpiresAt)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(user.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(user.UpdatedAt)),
				table.ValueParam("$is_active", types.BoolValue(user.IsActive)),
			),
		)
		return err
	})
}

// CreateOrganization создает новую организацию
func (c *YDBClient) CreateOrganization(ctx context.Context, org *Organization) error {
	query := `
		DECLARE $org_id AS Text;
		DECLARE $name AS Text;
		DECLARE $owner_id AS Text;
		DECLARE $settings AS Json;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO organizations (org_id, name, owner_id,settings, created_at, updated_at)
		VALUES ($org_id, $name, $owner_id, $settings, $created_at, $updated_at)
	`

	now := time.Now()
	if org.CreatedAt.IsZero() {
		org.CreatedAt = now
	}
	if org.UpdatedAt.IsZero() {
		org.UpdatedAt = now
	}

	// Settings is already a JSON string, use it directly or default to empty object
	var settingsJSON string
	if org.Settings != "" {
		settingsJSON = org.Settings
	} else {
		settingsJSON = "{}"
	}

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(org.OrgID)),
				table.ValueParam("$name", types.TextValue(org.Name)),
				table.ValueParam("$owner_id", types.TextValue(org.OwnerID)),
				table.ValueParam("$settings", types.JSONValue(settingsJSON)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(org.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(org.UpdatedAt)),
			),
		)
		return err
	})
}

// CreateMembership создает членство в организации
func (c *YDBClient) CreateMembership(ctx context.Context, membership *Membership) error {
	query := `
		DECLARE $membership_id AS Text;
		DECLARE $user_id AS Text;
		DECLARE $org_id AS Text;
		DECLARE $role AS Text;
		DECLARE $status AS Text;
		DECLARE $invited_by AS Text;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO memberships (
			membership_id, user_id, org_id, role, status, invited_by, created_at, updated_at
		) VALUES ($membership_id, $user_id, $org_id, $role, $status, $invited_by, $created_at, $updated_at)
	`

	now := time.Now()
	if membership.CreatedAt.IsZero() {
		membership.CreatedAt = now
	}
	if membership.UpdatedAt.IsZero() {
		membership.UpdatedAt = now
	}

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$membership_id", types.TextValue(membership.MembershipID)),
				table.ValueParam("$user_id", types.TextValue(membership.UserID)),
				table.ValueParam("$org_id", types.TextValue(membership.OrgID)),
				table.ValueParam("$role", types.TextValue(membership.Role)),
				table.ValueParam("$status", types.TextValue(membership.Status)),
				table.ValueParam("$invited_by", types.TextValue(membership.InvitedBy)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(membership.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(membership.UpdatedAt)),
			),
		)
		return err
	})
}

// GetMembership получает членство по пользователю и организации
func (c *YDBClient) GetMembership(ctx context.Context, userID, orgID string) (*Membership, error) {
	query := `
		DECLARE $user_id AS Text;
		DECLARE $org_id AS Text;
		SELECT membership_id, user_id, org_id, role, status, invited_by, created_at, updated_at
		FROM memberships
		WHERE user_id = $user_id AND org_id = $org_id
	`

	var membership Membership
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(userID)),
				table.ValueParam("$org_id", types.TextValue(orgID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			err := res.ScanNamed(
				named.Required("membership_id", &membership.MembershipID),
				named.Required("user_id", &membership.UserID),
				named.Required("org_id", &membership.OrgID),
				named.Optional("role", &membership.Role),
				named.Optional("status", &membership.Status),
				named.Optional("invited_by", &membership.InvitedBy),
				named.Required("created_at", &membership.CreatedAt),
				named.Required("updated_at", &membership.UpdatedAt),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("membership not found")
	}

	return &membership, nil
}

// CreateRefreshToken создает новый refresh токен
func (c *YDBClient) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	query := `
		DECLARE $token_id AS Text;
		DECLARE $user_id AS Text;
		DECLARE $token_hash AS Text;
		DECLARE $expires_at AS Timestamp;
		DECLARE $created_at AS Timestamp;

		REPLACE INTO refresh_tokens (token_id, user_id, token_hash, expires_at, created_at)
		VALUES ($token_id, $user_id, $token_hash, $expires_at, $created_at)
	`

	now := time.Now()
	if token.CreatedAt.IsZero() {
		token.CreatedAt = now
	}

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$token_id", types.TextValue(token.TokenID)),
				table.ValueParam("$user_id", types.TextValue(token.UserID)),
				table.ValueParam("$token_hash", types.TextValue(token.TokenHash)),
				table.ValueParam("$expires_at", types.TimestampValueFromTime(token.ExpiresAt)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(token.CreatedAt)),
			),
		)
		return err
	})
}

// GetRefreshToken получает refresh токен по хешу
func (c *YDBClient) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	query := `
		DECLARE $token_hash AS Text;
		SELECT token_id, user_id, token_hash, expires_at, created_at, is_revoked
		FROM refresh_tokens
		WHERE token_hash = $token_hash
	`

	var token RefreshToken
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$token_hash", types.TextValue(tokenHash)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			err := res.ScanNamed(
				named.Required("token_id", &token.TokenID),
				named.Required("user_id", &token.UserID),
				named.Required("token_hash", &token.TokenHash),
				named.Required("expires_at", &token.ExpiresAt),
				named.Required("created_at", &token.CreatedAt),
				named.Required("is_revoked", &token.IsRevoked),
			)

			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("refresh token not found")
	}

	return &token, nil
}

// RevokeRefreshToken отзывает refresh токен
func (c *YDBClient) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	// Сначала проверяем, существует ли токен
	token, err := c.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("refresh token not found")
	}

	// Проверяем, не истек ли токен
	if time.Now().After(token.ExpiresAt) {
		return fmt.Errorf("refresh token expired")
	}

	// Если токен существует и не истек, отзываем его
	query := `
		DECLARE $token_hash AS Text;
		UPDATE refresh_tokens SET is_revoked = true WHERE token_hash = $token_hash
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$token_hash", types.TextValue(tokenHash)),
			),
		)
		return err
	})
}

// CreateEmailLog создает запись в логе email
func (c *YDBClient) CreateEmailLog(ctx context.Context, log *EmailLog) error {
	query := `
		DECLARE $email_id AS Text;
		DECLARE $user_id AS Text;
		DECLARE $email_type AS Text;
		DECLARE $recipient AS Text;
		DECLARE $status AS Text;
		DECLARE $postbox_message_id AS Text;
		DECLARE $sent_at AS Timestamp;

		REPLACE INTO email_logs (
			email_id, user_id, email_type, recipient, status, postbox_message_id, sent_at
		) VALUES ($email_id, $user_id, $email_type, $recipient, $status, $postbox_message_id, $sent_at)
	`

	now := time.Now()
	if log.SentAt.IsZero() {
		log.SentAt = now
	}

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$email_id", types.TextValue(log.EmailID)),
				table.ValueParam("$user_id", types.TextValue(log.UserID)),
				table.ValueParam("$email_type", types.TextValue(log.EmailType)),
				table.ValueParam("$recipient", types.TextValue(log.Recipient)),
				table.ValueParam("$status", types.TextValue(log.Status)),
				table.ValueParam("$postbox_message_id", types.TextValue(log.PostboxMessageID)),
				table.ValueParam("$sent_at", types.TimestampValueFromTime(log.SentAt)),
			),
		)
		return err
	})
}

// GetPlanByID получает тарифный план по ID
func (c *YDBClient) GetPlanByID(ctx context.Context, planID string) (*Plan, error) {
	query := `
		DECLARE $plan_id AS Text;
		SELECT plan_id, name, storage_limit_mb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at
		FROM plans
		WHERE plan_id = $plan_id
	`

	var plan Plan
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$plan_id", types.TextValue(planID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			err := res.ScanNamed(
				named.Required("plan_id", &plan.PlanID),
				named.Required("name", &plan.Name),
				named.Required("storage_limit_mb", &plan.StorageLimitMB),
				named.Required("video_count_limit", &plan.VideoCountLimit),
				named.Required("price_rub", &plan.PriceRub),
				named.Required("billing_cycle", &plan.BillingCycle),
				named.Required("features", &plan.Features),
				named.Required("created_at", &plan.CreatedAt),
				named.Required("updated_at", &plan.UpdatedAt),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("plan not found")
	}

	return &plan, nil
}

// CreateSubscription создает новую подписку
func (c *YDBClient) CreateSubscription(ctx context.Context, subscription *Subscription) error {
	query := `
		DECLARE $subscription_id AS Text;
		DECLARE $user_id AS Text;
		DECLARE $org_id AS Text;
		DECLARE $plan_id AS Text;
		DECLARE $storage_limit_mb AS Int64;
		DECLARE $video_count_limit AS Int64;
		DECLARE $is_active AS Bool;
		DECLARE $trial_ends_at AS Timestamp;
		DECLARE $started_at AS Timestamp;
		DECLARE $expires_at AS Timestamp;
		DECLARE $billing_cycle AS Text;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO subscriptions (
			subscription_id, user_id, org_id, plan_id, storage_limit_mb, video_count_limit,
			is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		) VALUES ($subscription_id, $user_id, $org_id, $plan_id, $storage_limit_mb, $video_count_limit, $is_active, $trial_ends_at, $started_at, $expires_at, $billing_cycle, $created_at, $updated_at)
	`

	now := time.Now()
	if subscription.CreatedAt.IsZero() {
		subscription.CreatedAt = now
	}
	if subscription.UpdatedAt.IsZero() {
		subscription.UpdatedAt = now
	}

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$subscription_id", types.TextValue(subscription.SubscriptionID)),
				table.ValueParam("$user_id", types.TextValue(subscription.UserID)),
				table.ValueParam("$org_id", types.TextValue(subscription.OrgID)),
				table.ValueParam("$plan_id", types.TextValue(subscription.PlanID)),
				table.ValueParam("$storage_limit_mb", types.Int64Value(subscription.StorageLimitMB)),
				table.ValueParam("$video_count_limit", types.Int64Value(subscription.VideoCountLimit)),
				table.ValueParam("$is_active", types.BoolValue(subscription.IsActive)),
				table.ValueParam("$trial_ends_at", types.TimestampValueFromTime(subscription.TrialEndsAt)),
				table.ValueParam("$started_at", types.TimestampValueFromTime(subscription.StartedAt)),
				table.ValueParam("$expires_at", types.TimestampValueFromTime(subscription.ExpiresAt)),
				table.ValueParam("$billing_cycle", types.TextValue(subscription.BillingCycle)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(subscription.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(subscription.UpdatedAt)),
			),
		)
		return err
	})
}

// GetSubscriptionByUser получает активную подписку пользователя
func (c *YDBClient) GetSubscriptionByUser(ctx context.Context, userID string) (*Subscription, error) {
	query := `
		DECLARE $user_id AS Text;
		SELECT subscription_id, user_id, org_id, plan_id, storage_limit_mb, video_count_limit,
			   is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		FROM subscriptions
		WHERE user_id = $user_id AND is_active = true
		ORDER BY created_at DESC
		LIMIT 1
	`

	var subscription Subscription
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {

		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(userID)),
			),
		)
		if err != nil {

			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			err := res.ScanNamed(
				named.Required("subscription_id", &subscription.SubscriptionID),
				named.Required("user_id", &subscription.UserID),
				named.Required("org_id", &subscription.OrgID),
				named.Required("plan_id", &subscription.PlanID),
				named.Required("storage_limit_mb", &subscription.StorageLimitMB),
				named.Required("video_count_limit", &subscription.VideoCountLimit),
				named.Required("trial_ends_at", &subscription.TrialEndsAt),
				named.Required("started_at", &subscription.StartedAt),
				named.Required("expires_at", &subscription.ExpiresAt),
				named.Required("billing_cycle", &subscription.BillingCycle),
				named.Required("created_at", &subscription.CreatedAt),
				named.Required("updated_at", &subscription.UpdatedAt),
			)

			if err != nil {

				return fmt.Errorf("scan failed: %w", err)
			}

		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("subscription not found")
	}

	return &subscription, nil
}

// CreateVideo создает запись о видео
func (c *YDBClient) CreateVideo(ctx context.Context, video *Video) error {
	query := `
		DECLARE $video_id AS Text;
		DECLARE $org_id AS Text;
		DECLARE $uploaded_by AS Text;
		DECLARE $file_name AS Text;
		DECLARE $file_name_search AS Text;
		DECLARE $file_size_bytes AS Int64;
		DECLARE $storage_path AS Text;
		DECLARE $duration_seconds AS Int32;
		DECLARE $upload_id AS Text;
		DECLARE $upload_status AS Text;
		DECLARE $parts_uploaded AS Optional<Int32>;
		DECLARE $total_parts AS Optional<Int32>;
		DECLARE $public_share_token AS Optional<Text>;
		DECLARE $share_expires_at AS Optional<Timestamp>;
		DECLARE $uploaded_at AS Optional<Timestamp>;
		DECLARE $created_at AS Timestamp;
		DECLARE $is_deleted AS Bool;

		REPLACE INTO videos (
			video_id, org_id, uploaded_by, file_name, file_name_search, file_size_bytes,
			storage_path, duration_seconds, upload_id, upload_status, parts_uploaded, total_parts,
			public_share_token, share_expires_at, uploaded_at, created_at, is_deleted
		) VALUES ($video_id, $org_id, $uploaded_by, $file_name, $file_name_search, $file_size_bytes, $storage_path, $duration_seconds, $upload_id, $upload_status, $parts_uploaded, $total_parts, $public_share_token, $share_expires_at, $uploaded_at, $created_at, $is_deleted)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$video_id", types.TextValue(video.VideoID)),
				table.ValueParam("$org_id", types.TextValue(video.OrgID)),
				table.ValueParam("$uploaded_by", types.TextValue(video.UploadedBy)),
				table.ValueParam("$file_name", types.TextValue(video.FileName)),
				table.ValueParam("$file_name_search", types.TextValue(strings.ToLower(video.FileName))),
				table.ValueParam("$file_size_bytes", types.Int64Value(video.FileSizeBytes)),
				table.ValueParam("$storage_path", types.TextValue(video.StoragePath)),
				table.ValueParam("$duration_seconds", types.Int32Value(video.DurationSeconds)),
				table.ValueParam("$upload_id", types.TextValue(video.UploadID)),
				table.ValueParam("$upload_status", types.TextValue(video.UploadStatus)),
				func() table.ParameterOption {
					if video.PartsUploaded == nil {
						return table.ValueParam("$parts_uploaded", types.NullValue(types.TypeInt32))
					}
					return table.ValueParam("$parts_uploaded", types.OptionalValue(types.Int32Value(*video.PartsUploaded)))
				}(),
				func() table.ParameterOption {
					if video.TotalParts == nil {
						return table.ValueParam("$total_parts", types.NullValue(types.TypeInt32))
					}
					return table.ValueParam("$total_parts", types.OptionalValue(types.Int32Value(*video.TotalParts)))
				}(),
				func() table.ParameterOption {
					if video.PublicShareToken == nil {
						return table.ValueParam("$public_share_token", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$public_share_token", types.OptionalValue(types.TextValue(*video.PublicShareToken)))
				}(),
				func() table.ParameterOption {
					if video.ShareExpiresAt == nil {
						return table.ValueParam("$share_expires_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$share_expires_at", types.OptionalValue(types.TimestampValueFromTime(*video.ShareExpiresAt)))
				}(),
				func() table.ParameterOption {
					if video.UploadedAt == nil {
						return table.ValueParam("$uploaded_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$uploaded_at", types.OptionalValue(types.TimestampValueFromTime(*video.UploadedAt)))
				}(),
				table.ValueParam("$created_at", types.TimestampValueFromTime(time.Now())),
				table.ValueParam("$is_deleted", types.BoolValue(video.IsDeleted)),
			),
		)
		return err
	})
}

// GetVideo получает видео по ID
func (c *YDBClient) GetVideo(ctx context.Context, videoID string) (*Video, error) {
	query := `
		DECLARE $video_id AS Text;
		SELECT video_id, org_id, uploaded_by, file_name, file_name_search, file_size_bytes, storage_path,
		       duration_seconds, upload_id, upload_status, parts_uploaded, total_parts, public_share_token, share_expires_at, uploaded_at, created_at, is_deleted
		FROM videos WHERE video_id = $video_id
	`

	var v Video
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$video_id", types.TextValue(videoID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			// Временные переменные для nullable полей
			var partsUploaded *int32
			var totalParts *int32
			var publicShareToken *string
			var shareExpiresAt *time.Time
			var uploadedAt *time.Time

			err := res.ScanNamed(
				named.Required("video_id", &v.VideoID),
				named.Required("org_id", &v.OrgID),
				named.Required("uploaded_by", &v.UploadedBy),
				named.Required("file_name", &v.FileName),
				named.Required("file_name_search", &v.FileNameSearch),
				named.Required("file_size_bytes", &v.FileSizeBytes),
				named.Required("storage_path", &v.StoragePath),
				named.Required("duration_seconds", &v.DurationSeconds),
				named.Required("upload_id", &v.UploadID),
				named.Required("upload_status", &v.UploadStatus),
				named.Optional("parts_uploaded", &partsUploaded),
				named.Optional("total_parts", &totalParts),
				named.Optional("public_share_token", &publicShareToken),
				named.Optional("share_expires_at", &shareExpiresAt),
				named.Optional("uploaded_at", &uploadedAt),
				named.Required("created_at", &v.CreatedAt),
				named.Required("is_deleted", &v.IsDeleted),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Присваиваем значения nullable полей
			v.PartsUploaded = partsUploaded
			v.TotalParts = totalParts
			v.PublicShareToken = publicShareToken
			v.ShareExpiresAt = shareExpiresAt
			v.UploadedAt = uploadedAt
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("video not found")
	}

	return &v, nil
}

// UpdateVideo обновляет запись о видео
func (c *YDBClient) UpdateVideo(ctx context.Context, video *Video) error {
	query := `
		DECLARE $video_id AS Text;
		DECLARE $org_id AS Text;
		DECLARE $uploaded_by AS Text;
		DECLARE $file_name AS Text;
		DECLARE $file_name_search AS Text;
		DECLARE $file_size_bytes AS Int64;
		DECLARE $storage_path AS Text;
		DECLARE $duration_seconds AS Int32;
		DECLARE $upload_id AS Text;
		DECLARE $upload_status AS Text;
		DECLARE $parts_uploaded AS Optional<Int32>;
		DECLARE $total_parts AS Optional<Int32>;
		DECLARE $public_share_token AS Optional<Text>;
		DECLARE $share_expires_at AS Optional<Timestamp>;
		DECLARE $uploaded_at AS Optional<Timestamp>;
		DECLARE $created_at AS Timestamp;
		DECLARE $is_deleted AS Bool;

		REPLACE INTO videos (
			video_id, org_id, uploaded_by, file_name, file_name_search, file_size_bytes,
			storage_path, duration_seconds, upload_id, upload_status, parts_uploaded, total_parts,
			public_share_token, share_expires_at, uploaded_at, created_at, is_deleted
		) VALUES ($video_id, $org_id, $uploaded_by, $file_name, $file_name_search, $file_size_bytes, $storage_path, $duration_seconds, $upload_id, $upload_status, $parts_uploaded, $total_parts, $public_share_token, $share_expires_at, $uploaded_at, $created_at, $is_deleted)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$video_id", types.TextValue(video.VideoID)),
				table.ValueParam("$org_id", types.TextValue(video.OrgID)),
				table.ValueParam("$uploaded_by", types.TextValue(video.UploadedBy)),
				table.ValueParam("$file_name", types.TextValue(video.FileName)),
				table.ValueParam("$file_name_search", types.TextValue(strings.ToLower(video.FileName))),
				table.ValueParam("$file_size_bytes", types.Int64Value(video.FileSizeBytes)),
				table.ValueParam("$storage_path", types.TextValue(video.StoragePath)),
				table.ValueParam("$duration_seconds", types.Int32Value(video.DurationSeconds)),
				table.ValueParam("$upload_id", types.TextValue(video.UploadID)),
				table.ValueParam("$upload_status", types.TextValue(video.UploadStatus)),
				func() table.ParameterOption {
					if video.PartsUploaded == nil {
						return table.ValueParam("$parts_uploaded", types.NullValue(types.TypeInt32))
					}
					return table.ValueParam("$parts_uploaded", types.OptionalValue(types.Int32Value(*video.PartsUploaded)))
				}(),
				func() table.ParameterOption {
					if video.TotalParts == nil {
						return table.ValueParam("$total_parts", types.NullValue(types.TypeInt32))
					}
					return table.ValueParam("$total_parts", types.OptionalValue(types.Int32Value(*video.TotalParts)))
				}(),
				func() table.ParameterOption {
					if video.PublicShareToken == nil {
						return table.ValueParam("$public_share_token", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$public_share_token", types.OptionalValue(types.TextValue(*video.PublicShareToken)))
				}(),
				func() table.ParameterOption {
					if video.ShareExpiresAt == nil {
						return table.ValueParam("$share_expires_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$share_expires_at", types.OptionalValue(types.TimestampValueFromTime(*video.ShareExpiresAt)))
				}(),
				func() table.ParameterOption {
					if video.UploadedAt == nil {
						return table.ValueParam("$uploaded_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$uploaded_at", types.OptionalValue(types.TimestampValueFromTime(*video.UploadedAt)))
				}(),
				table.ValueParam("$created_at", types.TimestampValueFromTime(time.Now())),
				table.ValueParam("$is_deleted", types.BoolValue(video.IsDeleted)),
			),
		)
		return err
	})
}

// GetStorageUsage возвращает использованный объем хранилища
func (c *YDBClient) GetStorageUsage(ctx context.Context, orgID string) (int64, error) {
	query := `
		DECLARE $org_id AS Text;
		SELECT COALESCE(SUM(file_size_bytes), 0)
		FROM videos
		WHERE org_id = $org_id AND is_deleted = false AND upload_status != 'failed'
	`

	var usage int64

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(orgID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			err := res.ScanNamed(
				named.Required("column0", &usage),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return 0, err
	}
	return usage, nil
}

// GetVideoByShareToken получает видео по токену
func (c *YDBClient) GetVideoByShareToken(ctx context.Context, token string) (*Video, error) {
	query := `
		DECLARE $token AS Text;
		SELECT video_id, org_id, uploaded_by, file_name, file_name_search, file_size_bytes, storage_path,
		       duration_seconds, upload_id, upload_status, parts_uploaded, total_parts, public_share_token, share_expires_at, uploaded_at, created_at, is_deleted
		FROM videos
		WHERE public_share_token = $token AND is_deleted = false
	`

	var v Video
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$token", types.TextValue(token)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			// Временные переменные для nullable полей
			var partsUploaded *int32
			var totalParts *int32
			var publicShareToken *string
			var shareExpiresAt *time.Time
			var uploadedAt *time.Time

			err := res.ScanNamed(
				named.Required("video_id", &v.VideoID),
				named.Required("org_id", &v.OrgID),
				named.Required("uploaded_by", &v.UploadedBy),
				named.Required("file_name", &v.FileName),
				named.Required("file_name_search", &v.FileNameSearch),
				named.Required("file_size_bytes", &v.FileSizeBytes),
				named.Required("storage_path", &v.StoragePath),
				named.Required("duration_seconds", &v.DurationSeconds),
				named.Required("upload_id", &v.UploadID),
				named.Required("upload_status", &v.UploadStatus),
				named.Optional("parts_uploaded", &partsUploaded),
				named.Optional("total_parts", &totalParts),
				named.Optional("public_share_token", &publicShareToken),
				named.Optional("share_expires_at", &shareExpiresAt),
				named.Optional("uploaded_at", &uploadedAt),
				named.Required("created_at", &v.CreatedAt),
				named.Required("is_deleted", &v.IsDeleted),
			)

			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Присваиваем значения nullable полей
			v.PartsUploaded = partsUploaded
			v.TotalParts = totalParts
			v.PublicShareToken = publicShareToken
			v.ShareExpiresAt = shareExpiresAt
			v.UploadedAt = uploadedAt
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("video not found")
	}

	return &v, nil
}

// SearchVideos ищет видео с пагинацией
func (c *YDBClient) SearchVideos(ctx context.Context, orgID, userID, query string, limit, offset int) ([]*Video, int64, error) {
	var countQuery, dataQuery string
	var countParams, dataParams *table.QueryParameters

	// Базовая часть WHERE clause
	whereClause := `WHERE org_id = $org_id AND is_deleted = false`

	// Определяем, какие параметры нужны
	hasUserFilter := userID != ""
	hasQueryFilter := query != ""

	// Добавляем условия в WHERE
	if hasUserFilter {
		whereClause += ` AND uploaded_by = $user_id`
	}
	if hasQueryFilter {
		whereClause += ` AND file_name_search LIKE $query`
	}

	// ===== COUNT QUERY =====
	// Объявляем только те параметры, которые используем
	declares := `DECLARE $org_id AS Text;`
	if hasUserFilter {
		declares += `
		DECLARE $user_id AS Text;`
	}
	if hasQueryFilter {
		declares += `
		DECLARE $query AS Text;`
	}

	countQuery = declares + `
	SELECT COUNT(*) FROM videos ` + whereClause

	// Параметры для подсчета
	countParamsBuilder := []table.ParameterOption{
		table.ValueParam("$org_id", types.TextValue(orgID)),
	}
	if hasUserFilter {
		countParamsBuilder = append(countParamsBuilder, table.ValueParam("$user_id", types.TextValue(userID)))
	}
	if hasQueryFilter {
		countParamsBuilder = append(countParamsBuilder, table.ValueParam("$query", types.TextValue("%"+strings.ToLower(query)+"%")))
	}
	countParams = table.NewQueryParameters(countParamsBuilder...)

	var total uint64

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), countQuery, countParams)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			err := res.ScanNamed(
				named.Required("column0", &total),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, 0, err
	}

	// ===== DATA QUERY =====
	declares = `DECLARE $org_id AS Text;`
	if hasUserFilter {
		declares += `
		DECLARE $user_id AS Text;`
	}
	if hasQueryFilter {
		declares += `
		DECLARE $query AS Text;`
	}
	declares += `
	DECLARE $limit AS Uint64;
	DECLARE $offset AS Uint64;`

	dataQuery = declares + `
	SELECT video_id, org_id, uploaded_by, file_name, file_name_search, file_size_bytes, 
	       storage_path, duration_seconds, upload_id, upload_status, parts_uploaded, total_parts, 
	       public_share_token, share_expires_at, uploaded_at, created_at, is_deleted
	FROM videos ` + whereClause + `
	ORDER BY uploaded_at DESC 
	LIMIT $limit OFFSET $offset`

	// Параметры для получения данных
	dataParamsBuilder := []table.ParameterOption{
		table.ValueParam("$org_id", types.TextValue(orgID)),
	}
	if hasUserFilter {
		dataParamsBuilder = append(dataParamsBuilder, table.ValueParam("$user_id", types.TextValue(userID)))
	}
	if hasQueryFilter {
		dataParamsBuilder = append(dataParamsBuilder, table.ValueParam("$query", types.TextValue("%"+strings.ToLower(query)+"%")))
	}
	dataParamsBuilder = append(dataParamsBuilder,
		table.ValueParam("$limit", types.Uint64Value(uint64(limit))),
		table.ValueParam("$offset", types.Uint64Value(uint64(offset))),
	)
	dataParams = table.NewQueryParameters(dataParamsBuilder...)

	var videos []*Video

	err = c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), dataQuery, dataParams)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var v Video
				var partsUploaded *int32
				var totalParts *int32
				var publicShareToken *string
				var shareExpiresAt *time.Time
				var uploadedAt *time.Time

				if err := res.ScanNamed(
					named.Required("video_id", &v.VideoID),
					named.Required("org_id", &v.OrgID),
					named.Required("uploaded_by", &v.UploadedBy),
					named.Required("file_name", &v.FileName),
					named.Required("file_name_search", &v.FileNameSearch),
					named.Required("file_size_bytes", &v.FileSizeBytes),
					named.Required("storage_path", &v.StoragePath),
					named.Required("duration_seconds", &v.DurationSeconds),
					named.Required("upload_id", &v.UploadID),
					named.Required("upload_status", &v.UploadStatus),
					named.Optional("parts_uploaded", &partsUploaded),
					named.Optional("total_parts", &totalParts),
					named.Optional("public_share_token", &publicShareToken),
					named.Optional("share_expires_at", &shareExpiresAt),
					named.Optional("uploaded_at", &uploadedAt),
					named.Required("created_at", &v.CreatedAt),
					named.Required("is_deleted", &v.IsDeleted),
				); err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}

				v.PartsUploaded = partsUploaded
				v.TotalParts = totalParts
				v.PublicShareToken = publicShareToken
				v.ShareExpiresAt = shareExpiresAt
				v.UploadedAt = uploadedAt

				videos = append(videos, &v)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, 0, err
	}

	return videos, int64(total), nil
}

// Реализация оставшихся методов интерфейса

func (c *YDBClient) DeleteUser(ctx context.Context, userID string) error {
	query := `DELETE FROM users WHERE user_id = $user_id`
	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(userID)),
			),
		)
		return err
	})
}

func (c *YDBClient) GetOrganizationByID(ctx context.Context, orgID string) (*Organization, error) {
	query := `
		DECLARE $org_id AS Text;
		SELECT org_id, name, owner_id, settings, created_at, updated_at
		FROM organizations
		WHERE org_id = $org_id
	`

	var org Organization
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(orgID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			err := res.ScanNamed(
				named.Required("org_id", &org.OrgID),
				named.Required("name", &org.Name),
				named.Required("owner_id", &org.OwnerID),
				named.Required("settings", &org.Settings),
				named.Required("created_at", &org.CreatedAt),
				named.Required("updated_at", &org.UpdatedAt),
			)

			if err != nil {
				log.Println("Error in loop ", err)
				return fmt.Errorf("scan failed: %w", err)
			}
		}

		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("organization not found")
	}
	log.Println("Organization found ", org.OrgID, org.Name)
	return &org, nil
}

func (c *YDBClient) GetOrganizationsByOwner(ctx context.Context, ownerID string) ([]*Organization, error) {
	query := `
		DECLARE $owner_id AS Text;
		SELECT org_id, name, owner_id, settings, created_at, updated_at
		FROM organizations
		WHERE owner_id = $owner_id
	`

	var orgs []*Organization

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$owner_id", types.TextValue(ownerID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var org Organization
				if err := res.ScanNamed(
					named.Required("org_id", &org.OrgID),
					named.Required("name", &org.Name),
					named.Required("owner_id", &org.OwnerID),
					named.Required("settings", &org.Settings),
					named.Required("created_at", &org.CreatedAt),
					named.Required("updated_at", &org.UpdatedAt),
				); err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}
				orgs = append(orgs, &org)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}

	return orgs, nil
}

func (c *YDBClient) UpdateOrganization(ctx context.Context, org *Organization) error {
	query := `
		DECLARE $org_id AS Text;
		DECLARE $name AS Text;
		DECLARE $owner_id AS Text;
		DECLARE $settings AS Json;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO organizations (org_id, name, owner_id, settings, created_at, updated_at)
		VALUES ($org_id, $name, $owner_id, $settings, $created_at, $updated_at)
	`

	org.UpdatedAt = time.Now()

	// Settings is already a JSON string, use it directly or default to empty object
	var settingsJSON string
	if org.Settings != "" {
		settingsJSON = org.Settings
	} else {
		settingsJSON = "{}"
	}

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(org.OrgID)),
				table.ValueParam("$name", types.TextValue(org.Name)),
				table.ValueParam("$owner_id", types.TextValue(org.OwnerID)),
				table.ValueParam("$settings", types.JSONValue(settingsJSON)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(org.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(org.UpdatedAt)),
			),
		)
		return err
	})
}

func (c *YDBClient) GetMembershipsByUser(ctx context.Context, userID string) ([]*Membership, error) {

	query := `
        DECLARE $user_id AS Text;
        SELECT membership_id, user_id, org_id, role, status, invited_by, created_at, updated_at
        FROM memberships
        WHERE user_id = $user_id
    `

	var memberships []*Membership

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(userID)),
			),
		)
		if err != nil {

			return err
		}
		defer res.Close()

		resultSetCount := 0
		rowCount := 0
		for res.NextResultSet(ctx) {
			resultSetCount++
			for res.NextRow() {
				rowCount++
				var membership Membership
				if err := res.ScanNamed(
					named.Required("membership_id", &membership.MembershipID),
					named.Required("user_id", &membership.UserID),
					named.Required("org_id", &membership.OrgID),
					named.Required("role", &membership.Role),
					named.Required("status", &membership.Status),
					named.Required("invited_by", &membership.InvitedBy),
					named.Required("created_at", &membership.CreatedAt),
					named.Required("updated_at", &membership.UpdatedAt),
				); err != nil {

					return fmt.Errorf("scan failed: %w", err)
				}

				memberships = append(memberships, &membership)
			}
		}

		return res.Err()
	})

	if err != nil {

		return nil, err
	}

	return memberships, nil
}

func (c *YDBClient) GetMembershipsByOrg(ctx context.Context, orgID string) ([]*Membership, error) {
	query := `
		DECLARE $org_id AS Text;
		SELECT membership_id, user_id, org_id, role, status, invited_by, created_at, updated_at
		FROM memberships
		WHERE org_id = $org_id
	`

	var memberships []*Membership

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(orgID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var membership Membership
				if err := res.ScanNamed(
					named.Required("membership_id", &membership.MembershipID),
					named.Required("user_id", &membership.UserID),
					named.Required("org_id", &membership.OrgID),
					named.Required("role", &membership.Role),
					named.Required("status", &membership.Status),
					named.Required("invited_by", &membership.InvitedBy),
					named.Required("created_at", &membership.CreatedAt),
					named.Required("updated_at", &membership.UpdatedAt),
				); err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}
				memberships = append(memberships, &membership)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}

	return memberships, nil
}

func (c *YDBClient) UpdateMembership(ctx context.Context, membership *Membership) error {
	query := `
		DECLARE $membership_id AS Text;
		DECLARE $user_id AS Text;
		DECLARE $org_id AS Text;
		DECLARE $role AS Text;
		DECLARE $status AS Text;
		DECLARE $invited_by AS Text;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO memberships (
			membership_id, user_id, org_id, role, status, invited_by, created_at, updated_at
		) VALUES ($membership_id, $user_id, $org_id, $role, $status, $invited_by, $created_at, $updated_at)
	`

	membership.UpdatedAt = time.Now()

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$membership_id", types.TextValue(membership.MembershipID)),
				table.ValueParam("$user_id", types.TextValue(membership.UserID)),
				table.ValueParam("$org_id", types.TextValue(membership.OrgID)),
				table.ValueParam("$role", types.TextValue(membership.Role)),
				table.ValueParam("$status", types.TextValue(membership.Status)),
				table.ValueParam("$invited_by", types.TextValue(membership.InvitedBy)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(membership.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(membership.UpdatedAt)),
			),
		)
		return err
	})
}

func (c *YDBClient) DeleteMembership(ctx context.Context, membershipID string) error {
	query := `
		DECLARE $membership_id AS Text;
		DELETE FROM memberships WHERE membership_id = $membership_id
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$membership_id", types.TextValue(membershipID)),
			),
		)
		return err
	})
}

func (c *YDBClient) GetAllPlans(ctx context.Context) ([]*Plan, error) {
	query := `
		SELECT plan_id, name, storage_limit_mb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at
		FROM plans
	`

	var plans []*Plan

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query, table.NewQueryParameters())
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var plan Plan
				if err := res.ScanNamed(
					named.Required("plan_id", &plan.PlanID),
					named.Required("name", &plan.Name),
					named.Required("storage_limit_mb", &plan.StorageLimitMB),
					named.Required("video_count_limit", &plan.VideoCountLimit),
					named.Required("price_rub", &plan.PriceRub),
					named.Required("billing_cycle", &plan.BillingCycle),
					named.Required("features", &plan.Features),
					named.Required("created_at", &plan.CreatedAt),
					named.Required("updated_at", &plan.UpdatedAt),
				); err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}
				plans = append(plans, &plan)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}

	return plans, nil
}

func (c *YDBClient) GetSubscriptionByID(ctx context.Context, subscriptionID string) (*Subscription, error) {
	query := `
		DECLARE $subscription_id AS Text;
		SELECT subscription_id, user_id, org_id, plan_id, storage_limit_mb, video_count_limit,
			   is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		FROM subscriptions
		WHERE subscription_id = $subscription_id
	`

	var subscription Subscription
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$subscription_id", types.TextValue(subscriptionID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			err := res.ScanNamed(
				named.Required("subscription_id", &subscription.SubscriptionID),
				named.Required("user_id", &subscription.UserID),
				named.Required("org_id", &subscription.OrgID),
				named.Required("plan_id", &subscription.PlanID),
				named.Required("storage_limit_mb", &subscription.StorageLimitMB),
				named.Required("video_count_limit", &subscription.VideoCountLimit),
				named.Required("is_active", &subscription.IsActive),
				named.Required("trial_ends_at", &subscription.TrialEndsAt),
				named.Required("started_at", &subscription.StartedAt),
				named.Required("expires_at", &subscription.ExpiresAt),
				named.Required("billing_cycle", &subscription.BillingCycle),
				named.Required("created_at", &subscription.CreatedAt),
				named.Required("updated_at", &subscription.UpdatedAt),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("subscription not found")
	}

	return &subscription, nil
}

func (c *YDBClient) GetSubscriptionByOrg(ctx context.Context, orgID string) (*Subscription, error) {
	query := `
		DECLARE $org_id AS Text;
		SELECT subscription_id, user_id, org_id, plan_id, storage_limit_mb, video_count_limit,
			   is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		FROM subscriptions
		WHERE org_id = $org_id AND is_active = true
		ORDER BY created_at DESC
		LIMIT 1
	`

	var subscription Subscription
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(orgID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			err := res.ScanNamed(
				named.Required("subscription_id", &subscription.SubscriptionID),
				named.Required("user_id", &subscription.UserID),
				named.Required("org_id", &subscription.OrgID),
				named.Required("plan_id", &subscription.PlanID),
				named.Required("storage_limit_mb", &subscription.StorageLimitMB),
				named.Required("video_count_limit", &subscription.VideoCountLimit),
				named.Required("is_active", &subscription.IsActive),
				named.Required("trial_ends_at", &subscription.TrialEndsAt),
				named.Required("started_at", &subscription.StartedAt),
				named.Required("expires_at", &subscription.ExpiresAt),
				named.Required("billing_cycle", &subscription.BillingCycle),
				named.Required("created_at", &subscription.CreatedAt),
				named.Required("updated_at", &subscription.UpdatedAt),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("subscription not found")
	}

	return &subscription, nil
}

func (c *YDBClient) UpdateSubscription(ctx context.Context, subscription *Subscription) error {
	query := `
		DECLARE $subscription_id AS Text;
		DECLARE $user_id AS Text;
		DECLARE $org_id AS Text;
		DECLARE $plan_id AS Text;
		DECLARE $storage_limit_mb AS Int64;
		DECLARE $video_count_limit AS Int64;
		DECLARE $is_active AS Bool;
		DECLARE $trial_ends_at AS Timestamp;
		DECLARE $started_at AS Timestamp;
		DECLARE $expires_at AS Timestamp;
		DECLARE $billing_cycle AS Text;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO subscriptions (
			subscription_id, user_id, org_id, plan_id, storage_limit_mb, video_count_limit,
			is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		) VALUES ($subscription_id, $user_id, $org_id, $plan_id, $storage_limit_mb, $video_count_limit, $is_active, $trial_ends_at, $started_at, $expires_at, $billing_cycle, $created_at, $updated_at)
	`

	subscription.UpdatedAt = time.Now()

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$subscription_id", types.TextValue(subscription.SubscriptionID)),
				table.ValueParam("$user_id", types.TextValue(subscription.UserID)),
				table.ValueParam("$org_id", types.TextValue(subscription.OrgID)),
				table.ValueParam("$plan_id", types.TextValue(subscription.PlanID)),
				table.ValueParam("$storage_limit_mb", types.Int64Value(subscription.StorageLimitMB)),
				table.ValueParam("$video_count_limit", types.Int64Value(subscription.VideoCountLimit)),
				table.ValueParam("$is_active", types.BoolValue(subscription.IsActive)),
				table.ValueParam("$trial_ends_at", types.TimestampValueFromTime(subscription.TrialEndsAt)),
				table.ValueParam("$started_at", types.TimestampValueFromTime(subscription.StartedAt)),
				table.ValueParam("$expires_at", types.TimestampValueFromTime(subscription.ExpiresAt)),
				table.ValueParam("$billing_cycle", types.TextValue(subscription.BillingCycle)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(subscription.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(subscription.UpdatedAt)),
			),
		)
		return err
	})
}

func (c *YDBClient) CreateSubscriptionHistory(ctx context.Context, history *SubscriptionHistory) error {
	historyID := uuid.New().String()
	query := `
		DECLARE $history_id AS Text;
		DECLARE $subscription_id AS Text;
		DECLARE $plan_id AS Text;
		DECLARE $storage_limit_mb AS Int64;
		DECLARE $video_count_limit AS Int64;
		DECLARE $event_type AS Text;
		DECLARE $changed_at AS Timestamp;

		REPLACE INTO subscription_history (
			history_id, subscription_id, plan_id, storage_limit_mb, video_count_limit, event_type, changed_at
		) VALUES ($history_id, $subscription_id, $plan_id, $storage_limit_mb, $video_count_limit, $event_type, $changed_at)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$history_id", types.TextValue(historyID)),
				table.ValueParam("$subscription_id", types.TextValue(history.SubscriptionID)),
				table.ValueParam("$plan_id", types.TextValue(history.PlanID)),
				table.ValueParam("$storage_limit_mb", types.Int64Value(history.StorageLimitMB)),
				table.ValueParam("$video_count_limit", types.Int64Value(history.VideoCountLimit)),
				table.ValueParam("$event_type", types.TextValue(history.EventType)),
				table.ValueParam("$changed_at", types.TimestampValueFromTime(history.ChangedAt)),
			),
		)
		return err
	})
}

func (c *YDBClient) GetSubscriptionHistory(ctx context.Context, subscriptionID string) ([]*SubscriptionHistory, error) {
	query := `
		DECLARE $subscription_id AS Text;
		SELECT history_id, subscription_id, plan_id, storage_limit_mb, video_count_limit, event_type, changed_at
		FROM subscription_history
		WHERE subscription_id = $subscription_id
		ORDER BY changed_at DESC
	`

	var histories []*SubscriptionHistory

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$subscription_id", types.TextValue(subscriptionID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var history SubscriptionHistory
				if err := res.ScanNamed(
					named.Required("history_id", &history.HistoryID),
					named.Required("subscription_id", &history.SubscriptionID),
					named.Required("plan_id", &history.PlanID),
					named.Required("storage_limit_mb", &history.StorageLimitMB),
					named.Required("video_count_limit", &history.VideoCountLimit),
					named.Required("event_type", &history.EventType),
					named.Required("changed_at", &history.ChangedAt),
				); err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}
				histories = append(histories, &history)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}

	return histories, nil
}

func (c *YDBClient) GetEmailLogsByUser(ctx context.Context, userID string) ([]*EmailLog, error) {
	query := `
		DECLARE $user_id AS Text;
		SELECT email_id, user_id, email_type, recipient, status, postbox_message_id, sent_at, delivered_at, error_message
		FROM email_logs
		WHERE user_id = $user_id
		ORDER BY sent_at DESC
	`

	var logs []*EmailLog

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(userID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var log EmailLog
				if err := res.ScanNamed(
					named.Required("email_id", &log.EmailID),
					named.Required("user_id", &log.UserID),
					named.Required("email_type", &log.EmailType),
					named.Required("recipient", &log.Recipient),
					named.Required("status", &log.Status),
					named.Required("postbox_message_id", &log.PostboxMessageID),
					named.Required("sent_at", &log.SentAt),
					named.Required("delivered_at", &log.DeliveredAt),
					named.Required("error_message", &log.ErrorMessage),
				); err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}
				logs = append(logs, &log)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}

	return logs, nil
}

func (c *YDBClient) UpdateEmailLog(ctx context.Context, log *EmailLog) error {
	query := `
		DECLARE $email_id AS Text;
		DECLARE $user_id AS Text;
		DECLARE $email_type AS Text;
		DECLARE $recipient AS Text;
		DECLARE $status AS Text;
		DECLARE $postbox_message_id AS Text;
		DECLARE $sent_at AS Timestamp;
		DECLARE $delivered_at AS Timestamp;
		DECLARE $error_message AS Text;

		REPLACE INTO email_logs (
			email_id, user_id, email_type, recipient, status, postbox_message_id, sent_at, delivered_at, error_message
		) VALUES ($email_id, $user_id, $email_type, $recipient, $status, $postbox_message_id, $sent_at, $delivered_at, $error_message)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$email_id", types.TextValue(log.EmailID)),
				table.ValueParam("$user_id", types.TextValue(log.UserID)),
				table.ValueParam("$email_type", types.TextValue(log.EmailType)),
				table.ValueParam("$recipient", types.TextValue(log.Recipient)),
				table.ValueParam("$status", types.TextValue(log.Status)),
				table.ValueParam("$postbox_message_id", types.TextValue(log.PostboxMessageID)),
				table.ValueParam("$sent_at", types.TimestampValueFromTime(log.SentAt)),
				table.ValueParam("$delivered_at", types.TimestampValueFromTime(log.DeliveredAt)),
				table.ValueParam("$error_message", types.TextValue(log.ErrorMessage)),
			),
		)
		return err
	})
}

func (c *YDBClient) GetRefreshTokensByUser(ctx context.Context, userID string) ([]*RefreshToken, error) {
	query := `
		DECLARE $user_id AS Text;
		SELECT token_id, user_id, token_hash, expires_at, created_at, is_revoked
		FROM refresh_tokens
		WHERE user_id = $user_id
		ORDER BY created_at DESC
	`

	var tokens []*RefreshToken

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(userID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var token RefreshToken
				if err := res.ScanNamed(
					named.Required("token_id", &token.TokenID),
					named.Required("user_id", &token.UserID),
					named.Required("token_hash", &token.TokenHash),
					named.Required("expires_at", &token.ExpiresAt),
					named.Required("created_at", &token.CreatedAt),
					named.Required("is_revoked", &token.IsRevoked),
				); err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}
				tokens = append(tokens, &token)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func (c *YDBClient) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	query := `
		DECLARE $user_id AS Text;
		UPDATE refresh_tokens SET is_revoked = true WHERE user_id = $user_id
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(userID)),
			),
		)
		return err
	})
}

func (c *YDBClient) CleanupExpiredTokens(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < CurrentUtcTimestamp()`
	return c.executeQuery(ctx, query)
}

// CreateInvitation создает новое приглашение
func (c *YDBClient) CreateInvitation(ctx context.Context, invitation *Invitation) error {
	if invitation.InvitationID == "" {
		invitation.InvitationID = uuid.New().String()
	}

	query := `
		DECLARE $invitation_id AS Text;
		DECLARE $org_id AS Text;
		DECLARE $email AS Text;
		DECLARE $role AS Text;
		DECLARE $invite_code AS Text;
		DECLARE $invited_by AS Text;
		DECLARE $status AS Text;
		DECLARE $expires_at AS Timestamp;
		DECLARE $created_at AS Timestamp;

		INSERT INTO invitations (invitation_id, org_id, email, role, invite_code, invited_by, status, expires_at, created_at)
		VALUES ($invitation_id, $org_id, $email, $role, $invite_code, $invited_by, $status, $expires_at, $created_at)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$invitation_id", types.TextValue(invitation.InvitationID)),
				table.ValueParam("$org_id", types.TextValue(invitation.OrgID)),
				table.ValueParam("$email", types.TextValue(invitation.Email)),
				table.ValueParam("$role", types.TextValue(invitation.Role)),
				table.ValueParam("$invite_code", types.TextValue(invitation.InviteCode)),
				table.ValueParam("$invited_by", types.TextValue(invitation.InvitedBy)),
				table.ValueParam("$status", types.TextValue(invitation.Status)),
				table.ValueParam("$expires_at", types.TimestampValueFromTime(invitation.ExpiresAt)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(invitation.CreatedAt)),
			),
		)
		return err
	})
}

// GetInvitationByCode получает приглашение по коду
func (c *YDBClient) GetInvitationByCode(ctx context.Context, code string) (*Invitation, error) {
	query := `
		DECLARE $invite_code AS Text;
		SELECT invitation_id, org_id, email, role, invite_code, invited_by, status, expires_at, created_at, accepted_at
		FROM invitations
		WHERE invite_code = $invite_code
	`

	var invitation *Invitation
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$invite_code", types.TextValue(code)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			invitation = &Invitation{}
			err := res.ScanNamed(
				named.Required("invitation_id", &invitation.InvitationID),
				named.Required("org_id", &invitation.OrgID),
				named.Required("email", &invitation.Email),
				named.Required("role", &invitation.Role),
				named.Required("invite_code", &invitation.InviteCode),
				named.Required("invited_by", &invitation.InvitedBy),
				named.Required("status", &invitation.Status),
				named.Required("expires_at", &invitation.ExpiresAt),
				named.Required("created_at", &invitation.CreatedAt),
				named.Optional("accepted_at", &invitation.AcceptedAt),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("invitation not found")
	}

	return invitation, nil
}

// GetInvitationsByOrg получает все приглашения организации
func (c *YDBClient) GetInvitationsByOrg(ctx context.Context, orgID string) ([]*Invitation, error) {
	query := `
		DECLARE $org_id AS Text;
		SELECT invitation_id, org_id, email, role, invite_code, invited_by, status, expires_at, created_at, accepted_at
		FROM invitations
		WHERE org_id = $org_id
		ORDER BY created_at DESC
	`

	var invitations []*Invitation

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(orgID)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				invitation := &Invitation{}
				err := res.ScanNamed(
					named.Required("invitation_id", &invitation.InvitationID),
					named.Required("org_id", &invitation.OrgID),
					named.Required("email", &invitation.Email),
					named.Required("role", &invitation.Role),
					named.Required("invite_code", &invitation.InviteCode),
					named.Required("invited_by", &invitation.InvitedBy),
					named.Required("status", &invitation.Status),
					named.Required("expires_at", &invitation.ExpiresAt),
					named.Required("created_at", &invitation.CreatedAt),
					named.Optional("accepted_at", &invitation.AcceptedAt),
				)
				if err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}
				invitations = append(invitations, invitation)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}

	return invitations, nil
}

// UpdateInvitationStatus обновляет статус приглашения
func (c *YDBClient) UpdateInvitationStatus(ctx context.Context, invitationID, status string) error {
	query := `
		DECLARE $invitation_id AS Text;
		DECLARE $status AS Text;
		UPDATE invitations SET status = $status WHERE invitation_id = $invitation_id
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$invitation_id", types.TextValue(invitationID)),
				table.ValueParam("$status", types.TextValue(status)),
			),
		)
		return err
	})
}

// UpdateInvitationStatusWithAcceptTime обновляет статус и время принятия приглашения
func (c *YDBClient) UpdateInvitationStatusWithAcceptTime(ctx context.Context, invitationID, status string, acceptedAt time.Time) error {
	query := `
		DECLARE $invitation_id AS Text;
		DECLARE $status AS Text;
		DECLARE $accepted_at AS Timestamp;
		UPDATE invitations SET status = $status, accepted_at = $accepted_at WHERE invitation_id = $invitation_id
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$invitation_id", types.TextValue(invitationID)),
				table.ValueParam("$status", types.TextValue(status)),
				table.ValueParam("$accepted_at", types.TimestampValueFromTime(acceptedAt)),
			),
		)
		return err
	})
}

// DeleteInvitation удаляет приглашение
func (c *YDBClient) DeleteInvitation(ctx context.Context, invitationID string) error {
	query := `
		DECLARE $invitation_id AS Text;
		DELETE FROM invitations WHERE invitation_id = $invitation_id
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$invitation_id", types.TextValue(invitationID)),
			),
		)
		return err
	})
}

// GetInvitationByEmail получает приглашение по email и организации
func (c *YDBClient) GetInvitationByEmail(ctx context.Context, orgID, email string) (*Invitation, error) {
	query := `
		DECLARE $org_id AS Text;
		DECLARE $email AS Text;
		SELECT invitation_id, org_id, email, role, invite_code, invited_by, status, expires_at, created_at, accepted_at
		FROM invitations
		WHERE org_id = $org_id AND email = $email AND status = "pending"
	`

	var invitation *Invitation
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(orgID)),
				table.ValueParam("$email", types.TextValue(email)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			invitation = &Invitation{}
			err := res.ScanNamed(
				named.Required("invitation_id", &invitation.InvitationID),
				named.Required("org_id", &invitation.OrgID),
				named.Required("email", &invitation.Email),
				named.Required("role", &invitation.Role),
				named.Required("invite_code", &invitation.InviteCode),
				named.Required("invited_by", &invitation.InvitedBy),
				named.Required("status", &invitation.Status),
				named.Required("expires_at", &invitation.ExpiresAt),
				named.Required("created_at", &invitation.CreatedAt),
				named.Optional("accepted_at", &invitation.AcceptedAt),
			)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("invitation not found")
	}

	return invitation, nil
}

// InsertAuditLog сохраняет запись аудита
func (c *YDBClient) InsertAuditLog(ctx context.Context, auditLog *models.AuditLog) error {
	query := `
DECLARE $id AS Text;
DECLARE $timestamp AS Timestamp;
DECLARE $user_id AS Text;
DECLARE $org_id AS Text;
DECLARE $action_type AS Text;
DECLARE $action_result AS Text;
DECLARE $ip_address AS Text;
DECLARE $user_agent AS Text;
DECLARE $details AS Json;

INSERT INTO audit_logs (id, timestamp, user_id, org_id, action_type, action_result, ip_address, user_agent, details)
VALUES ($id, $timestamp, $user_id, $org_id, $action_type, $action_result, $ip_address, $user_agent, $details)
`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$id", types.TextValue(auditLog.ID)),
				table.ValueParam("$timestamp", types.TimestampValueFromTime(auditLog.Timestamp)),
				table.ValueParam("$user_id", types.TextValue(auditLog.UserID)),
				table.ValueParam("$org_id", types.TextValue(auditLog.OrgID)),
				table.ValueParam("$action_type", types.TextValue(auditLog.ActionType)),
				table.ValueParam("$action_result", types.TextValue(auditLog.ActionResult)),
				table.ValueParam("$ip_address", types.TextValue(auditLog.IPAddress)),
				table.ValueParam("$user_agent", types.TextValue(auditLog.UserAgent)),
				table.ValueParam("$details", types.JSONValue(string(auditLog.Details))),
			),
		)
		return err
	})
}

// GetAuditLogs получает логи аудита с фильтрацией и пагинацией

// GetAuditLogs получает логи аудита с фильтрацией и пагинацией
func (c *YDBClient) GetAuditLogs(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.AuditLog, int64, error) {
whereConditions := []string{}

if userID, ok := filters["user_id"].(string); ok && userID != "" {
whereConditions = append(whereConditions, fmt.Sprintf("user_id = '%s'", strings.ReplaceAll(userID, "'", "''")))
}

if orgID, ok := filters["org_id"].(string); ok && orgID != "" {
whereConditions = append(whereConditions, fmt.Sprintf("org_id = '%s'", strings.ReplaceAll(orgID, "'", "''")))
}

if actionType, ok := filters["action_type"].(string); ok && actionType != "" {
whereConditions = append(whereConditions, fmt.Sprintf("action_type = '%s'", strings.ReplaceAll(actionType, "'", "''")))
}

if result, ok := filters["result"].(string); ok && result != "" {
whereConditions = append(whereConditions, fmt.Sprintf("action_result = '%s'", strings.ReplaceAll(result, "'", "''")))
}

if from, ok := filters["from"].(string); ok && from != "" {
fromTime, err := time.Parse("2006-01-02", from)
if err == nil {
whereConditions = append(whereConditions, fmt.Sprintf("timestamp >= CAST('%s' AS Timestamp)", fromTime.UTC().Format(time.RFC3339)))
}
}

if to, ok := filters["to"].(string); ok && to != "" {
toTime, err := time.Parse("2006-01-02", to)
if err == nil {
toTime = toTime.AddDate(0, 0, 1)
whereConditions = append(whereConditions, fmt.Sprintf("timestamp < CAST('%s' AS Timestamp)", toTime.UTC().Format(time.RFC3339)))
}
}

whereClause := ""
if len(whereConditions) > 0 {
whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
}

var total int64
var logs []*models.AuditLog

err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
// Get total count
countQuery := fmt.Sprintf("SELECT COUNT(*) as total FROM audit_logs %s", whereClause)
_, res, err := session.Execute(ctx, table.DefaultTxControl(), countQuery, table.NewQueryParameters())
if err != nil {
return err
}
defer res.Close()

for res.NextRow() {
if err := res.ScanNamed(named.Required("total", &total)); err != nil {
return err
}
}
if err := res.Err(); err != nil {
return err
}

// Get logs with pagination
logsQuery := fmt.Sprintf(`
SELECT id, timestamp, user_id, org_id, action_type, action_result, ip_address, user_agent, details
FROM audit_logs
%s
ORDER BY timestamp DESC
LIMIT %d OFFSET %d
`, whereClause, limit, offset)

_, res, err = session.Execute(ctx, table.DefaultTxControl(), logsQuery, table.NewQueryParameters())
if err != nil {
return err
}
defer res.Close()

logs = make([]*models.AuditLog, 0)
for res.NextRow() {
var log models.AuditLog
var details string
if err := res.ScanNamed(
named.Required("id", &log.ID),
named.Required("timestamp", &log.Timestamp),
named.Required("user_id", &log.UserID),
named.Required("org_id", &log.OrgID),
named.Required("action_type", &log.ActionType),
named.Required("action_result", &log.ActionResult),
named.Required("ip_address", &log.IPAddress),
named.Optional("user_agent", &log.UserAgent),
named.Optional("details", &details),
); err != nil {
return err
}
if details != "" {
log.Details = []byte(details)
} else {
log.Details = []byte("{}")
}
logs = append(logs, &log)
}
return res.Err()
})

if err != nil {
return nil, 0, err
}

return logs, total, nil
}
