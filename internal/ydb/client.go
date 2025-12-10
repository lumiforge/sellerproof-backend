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
	app_errors "github.com/lumiforge/sellerproof-backend/internal/errors"
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
				verification_attempts Int32 DEFAULT 0,
				password_reset_code Text,
				password_reset_expires_at Timestamp,
				created_at Timestamp NOT NULL,
				updated_at Timestamp NOT NULL,
				is_active Bool DEFAULT true,
				last_org_id Text,
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
				delivered_at Optional<Timestamp>,
				error_message Optional<Text>,
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
				title Text NOT NULL,
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
				deleted_at Optional<Timestamp>,
				public_url Optional<Text>,
				publish_status Text DEFAULT 'private',
				published_at Optional<Timestamp>,
				upload_expires_at Optional<Timestamp>,
				PRIMARY KEY (video_id),
				INDEX org_idx GLOBAL ON (org_id),
				INDEX org_user_idx GLOBAL ON (org_id, uploaded_by),
				INDEX org_deleted_idx GLOBAL ON (org_id, is_deleted),
				INDEX share_token_idx GLOBAL ON (public_share_token),
				INDEX publish_status_idx GLOBAL ON (publish_status),
				INDEX org_filename_idx GLOBAL ON (org_id, file_name_search)
			)
			WITH (
				TTL = Interval("PT0S") ON upload_expires_at
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
				INDEX composite_idx GLOBAL ON (org_id, timestamp)
				)
				`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create audit_logs table: %w", err)
		}
	} else {
		log.Println("Table audit_logs already exists, skipping creation")
	}

	time.Sleep(500 * time.Millisecond)

	// Таблица публичных шарингов видео
	log.Println("Creating table: public_video_shares")
	if exists, err := c.tableExists(ctx, "public_video_shares"); err != nil {
		return fmt.Errorf("failed to check public_video_shares table existence: %w", err)
	} else if !exists {
		query := `
			CREATE TABLE public_video_shares (
				share_id Text NOT NULL,
				video_id Text NOT NULL,
				public_token Text NOT NULL,
				created_at Timestamp NOT NULL,
				created_by Text NOT NULL,
				revoked Bool DEFAULT false,
				revoked_at Timestamp,
				access_count Uint64 DEFAULT 0,
				last_accessed_at Timestamp,
				PRIMARY KEY (share_id),
				INDEX public_token_idx GLOBAL UNIQUE ON (public_token),
				INDEX video_id_idx GLOBAL ON (video_id),
				INDEX revoked_idx GLOBAL ON (revoked)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create public_video_shares table: %w", err)
		}
	} else {
		log.Println("Table public_video_shares already exists, skipping creation")
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
		DECLARE $verification_attempts AS Int32;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;
		DECLARE $is_active AS Bool;
		DECLARE $last_org_id AS Optional<Text>;

		REPLACE INTO users (
			user_id, email, password_hash, full_name, email_verified,
			verification_code, verification_expires_at, verification_attempts,
			created_at, updated_at, is_active, last_org_id
		) VALUES (
			$user_id, $email, $password_hash, $full_name, $email_verified,
			$verification_code, $verification_expires_at, $verification_attempts,
			$created_at, $updated_at, $is_active, $last_org_id
		)
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
				table.ValueParam("$verification_attempts", types.Int32Value(user.VerificationAttempts)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(user.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(user.UpdatedAt)),
				table.ValueParam("$is_active", types.BoolValue(user.IsActive)),
				func() table.ParameterOption {
					if user.LastOrgID == nil {
						return table.ValueParam("$last_org_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$last_org_id", types.OptionalValue(types.TextValue(*user.LastOrgID)))
				}(),
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
			   verification_code, verification_expires_at, verification_attempts,
			   created_at, updated_at, is_active, last_org_id,
			   password_reset_code, password_reset_expires_at
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
				named.Required("verification_attempts", &user.VerificationAttempts),
				named.Required("created_at", &user.CreatedAt),
				named.Required("updated_at", &user.UpdatedAt),
				named.Required("is_active", &user.IsActive),
				named.Optional("last_org_id", &user.LastOrgID),
				named.Optional("password_reset_code", &user.PasswordResetCode),
				named.Optional("password_reset_expires_at", &user.PasswordResetExpiresAt),
			)
			if err != nil {
				return app_errors.ErrScanFailed
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
			   verification_code, verification_expires_at, verification_attempts,
			   created_at, updated_at, is_active, last_org_id,
			   password_reset_code, password_reset_expires_at
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
				named.Required("verification_attempts", &user.VerificationAttempts),
				named.Required("created_at", &user.CreatedAt),
				named.Required("updated_at", &user.UpdatedAt),
				named.Required("is_active", &user.IsActive),
				named.Optional("last_org_id", &user.LastOrgID),
				named.Optional("password_reset_code", &user.PasswordResetCode),
				named.Optional("password_reset_expires_at", &user.PasswordResetExpiresAt),
			)

			if err != nil {
				return app_errors.ErrScanFailed
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

// TODO Potentially Race Condition / Lost Update
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
		DECLARE $verification_attempts AS Int32;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;
		DECLARE $is_active AS Bool;
		DECLARE $last_org_id AS Optional<Text>;

		REPLACE INTO users (
			user_id, email, password_hash, full_name, email_verified,
			verification_code, verification_expires_at, verification_attempts,
			created_at, updated_at, is_active, last_org_id
		) VALUES (
			$user_id, $email, $password_hash, $full_name, $email_verified,
			$verification_code, $verification_expires_at, $verification_attempts,
			$created_at, $updated_at, $is_active, $last_org_id
		)
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
				table.ValueParam("$verification_attempts", types.Int32Value(user.VerificationAttempts)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(user.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(user.UpdatedAt)),
				table.ValueParam("$is_active", types.BoolValue(user.IsActive)),
				func() table.ParameterOption {
					if user.LastOrgID == nil {
						return table.ValueParam("$last_org_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$last_org_id", types.OptionalValue(types.TextValue(*user.LastOrgID)))
				}(),
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
			log.Println("About to scan membership data")

			err := res.ScanNamed(
				named.Required("membership_id", &membership.MembershipID),
				named.Required("user_id", &membership.UserID),
				named.Required("org_id", &membership.OrgID),
				named.Required("role", &membership.Role),
				named.Required("status", &membership.Status),
				named.Required("invited_by", &membership.InvitedBy),
				named.Required("created_at", &membership.CreatedAt),
				named.Required("updated_at", &membership.UpdatedAt),
			)

			log.Println("ScanNamed error:", err)

			if err != nil {
				log.Println("Scan failed with error:", err)
				return fmt.Errorf("scan failed: %w", err)
			}
			log.Println("Successfully scanned membership:", membership.MembershipID)
		}

		log.Println("res.Err():", res.Err()) // ✅ Проверим res.Err()
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
				return app_errors.ErrScanFailed
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
				return app_errors.ErrScanFailed
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
		WHERE user_id = $user_id AND is_active = true AND expires_at > CurrentUtcTimestamp()
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
		DECLARE $title AS Text;
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
		DECLARE $deleted_at AS Optional<Timestamp>;
		DECLARE $public_url AS Optional<Text>;
		DECLARE $publish_status AS Text;
		DECLARE $published_at AS Optional<Timestamp>;
		DECLARE $upload_expires_at AS Optional<Timestamp>;

		REPLACE INTO videos (
			video_id, org_id, uploaded_by, title, file_name, file_name_search, file_size_bytes,
			storage_path, duration_seconds, upload_id, upload_status, parts_uploaded, total_parts,
			public_share_token, share_expires_at, uploaded_at, created_at, is_deleted, deleted_at,
			public_url, publish_status, published_at, upload_expires_at
		) VALUES ($video_id, $org_id, $uploaded_by, $title, $file_name, $file_name_search, $file_size_bytes, $storage_path, $duration_seconds, $upload_id, $upload_status, $parts_uploaded, $total_parts, $public_share_token, $share_expires_at, $uploaded_at, $created_at, $is_deleted, $deleted_at, $public_url, $publish_status, $published_at, $upload_expires_at)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$video_id", types.TextValue(video.VideoID)),
				table.ValueParam("$org_id", types.TextValue(video.OrgID)),
				table.ValueParam("$uploaded_by", types.TextValue(video.UploadedBy)),
				table.ValueParam("$title", types.TextValue(video.Title)),
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
				func() table.ParameterOption {
					if video.DeletedAt == nil {
						return table.ValueParam("$deleted_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$deleted_at", types.OptionalValue(types.TimestampValueFromTime(*video.DeletedAt)))
				}(),
				func() table.ParameterOption {
					if video.PublicURL == nil {
						return table.ValueParam("$public_url", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$public_url", types.OptionalValue(types.TextValue(*video.PublicURL)))
				}(),
				table.ValueParam("$publish_status", types.TextValue(video.PublishStatus)),
				func() table.ParameterOption {
					if video.PublishedAt == nil {
						return table.ValueParam("$published_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$published_at", types.OptionalValue(types.TimestampValueFromTime(*video.PublishedAt)))
				}(),
				func() table.ParameterOption {
					if video.UploadExpiresAt == nil {
						return table.ValueParam("$upload_expires_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$upload_expires_at", types.OptionalValue(types.TimestampValueFromTime(*video.UploadExpiresAt)))
				}(),
			),
		)
		return err
	})
}

// GetVideo получает видео по ID
func (c *YDBClient) GetVideo(ctx context.Context, videoID string) (*Video, error) {
	query := `
		DECLARE $video_id AS Text;
		SELECT video_id, org_id, uploaded_by, title, file_name, file_name_search, file_size_bytes, storage_path,
		       duration_seconds, upload_id, upload_status, parts_uploaded, total_parts, public_share_token, share_expires_at, uploaded_at, created_at, is_deleted, deleted_at,
		       public_url, publish_status, published_at, upload_expires_at
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
			var uploadExpiresAt *time.Time
			var isDeleted *bool
			var deletedAt *time.Time
			var publishStatus *string

			err := res.Scan(
				&v.VideoID,
				&v.OrgID,
				&v.UploadedBy,
				&v.Title,
				&v.FileName,
				&v.FileNameSearch,
				&v.FileSizeBytes,
				&v.StoragePath,
				&v.DurationSeconds,
				&v.UploadID,
				&v.UploadStatus,
				&partsUploaded,
				&totalParts,
				&publicShareToken,
				&shareExpiresAt,
				&uploadedAt,
				&v.CreatedAt,
				&isDeleted,
				&deletedAt,
				&v.PublicURL,
				&publishStatus,
				&v.PublishedAt,
				&uploadExpiresAt,
			)
			if err != nil {
				return app_errors.ErrScanFailed
			}

			// Присваиваем значения nullable полей
			v.PartsUploaded = partsUploaded
			v.TotalParts = totalParts
			v.PublicShareToken = publicShareToken
			v.ShareExpiresAt = shareExpiresAt
			v.UploadedAt = uploadedAt
			v.UploadExpiresAt = uploadExpiresAt
			if isDeleted != nil {
				v.IsDeleted = *isDeleted
			}
			v.DeletedAt = deletedAt
			if publishStatus != nil {
				v.PublishStatus = *publishStatus
			}
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

// GetVideoByID получает видео по ID с проверкой организации
func (c *YDBClient) GetVideoByID(ctx context.Context, videoID, orgID string) (*Video, error) {
	query := `
		DECLARE $video_id AS Text;
		DECLARE $org_id AS Text;
		SELECT video_id, org_id, uploaded_by, title, file_name, file_name_search, file_size_bytes, storage_path,
		       duration_seconds, upload_id, upload_status, parts_uploaded, total_parts, public_share_token, share_expires_at, uploaded_at, created_at, is_deleted,
		       public_url, publish_status, published_at, upload_expires_at
		FROM videos
		WHERE video_id = $video_id AND org_id = $org_id
	`

	var v Video
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$video_id", types.TextValue(videoID)),
				table.ValueParam("$org_id", types.TextValue(orgID)),
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
			var uploadExpiresAt *time.Time
			var isDeleted *bool
			var publishStatus *string

			err := res.Scan(
				&v.VideoID,
				&v.OrgID,
				&v.UploadedBy,
				&v.Title,
				&v.FileName,
				&v.FileNameSearch,
				&v.FileSizeBytes,
				&v.StoragePath,
				&v.DurationSeconds,
				&v.UploadID,
				&v.UploadStatus,
				&partsUploaded,
				&totalParts,
				&publicShareToken,
				&shareExpiresAt,
				&uploadedAt,
				&v.CreatedAt,
				&isDeleted,
				&v.PublicURL,
				&publishStatus,
				&v.PublishedAt,
				&uploadExpiresAt,
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
			v.UploadExpiresAt = uploadExpiresAt
			if isDeleted != nil {
				v.IsDeleted = *isDeleted
			}
			if publishStatus != nil {
				v.PublishStatus = *publishStatus
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, app_errors.ErrVideoNotFound
	}
	return &v, nil
}

// UpdateVideo обновляет запись о видео
func (c *YDBClient) UpdateVideo(ctx context.Context, video *Video) error {
	query := `
		DECLARE $video_id AS Text;
		DECLARE $org_id AS Text;
		DECLARE $uploaded_by AS Text;
		DECLARE $title AS Text;
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
		DECLARE $deleted_at AS Optional<Timestamp>;
		DECLARE $public_url AS Optional<Text>;
		DECLARE $publish_status AS Text;
		DECLARE $published_at AS Optional<Timestamp>;
		DECLARE $upload_expires_at AS Optional<Timestamp>;

		REPLACE INTO videos (
			video_id, org_id, uploaded_by, title, file_name, file_name_search, file_size_bytes,
			storage_path, duration_seconds, upload_id, upload_status, parts_uploaded, total_parts,
			public_share_token, share_expires_at, uploaded_at, created_at, is_deleted, deleted_at,
			public_url, publish_status, published_at, upload_expires_at
		) VALUES ($video_id, $org_id, $uploaded_by, $title, $file_name, $file_name_search, $file_size_bytes, $storage_path, $duration_seconds, $upload_id, $upload_status, $parts_uploaded, $total_parts, $public_share_token, $share_expires_at, $uploaded_at, $created_at, $is_deleted, $deleted_at, $public_url, $publish_status, $published_at, $upload_expires_at)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$video_id", types.TextValue(video.VideoID)),
				table.ValueParam("$org_id", types.TextValue(video.OrgID)),
				table.ValueParam("$uploaded_by", types.TextValue(video.UploadedBy)),
				table.ValueParam("$title", types.TextValue(video.Title)),
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
				table.ValueParam("$created_at", types.TimestampValueFromTime(video.CreatedAt)),
				table.ValueParam("$is_deleted", types.BoolValue(video.IsDeleted)),
				func() table.ParameterOption {
					if video.DeletedAt == nil {
						return table.ValueParam("$deleted_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$deleted_at", types.OptionalValue(types.TimestampValueFromTime(*video.DeletedAt)))
				}(),
				func() table.ParameterOption {
					if video.PublicURL == nil {
						return table.ValueParam("$public_url", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$public_url", types.OptionalValue(types.TextValue(*video.PublicURL)))
				}(),
				table.ValueParam("$publish_status", types.TextValue(video.PublishStatus)),
				func() table.ParameterOption {
					if video.PublishedAt == nil {
						return table.ValueParam("$published_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$published_at", types.OptionalValue(types.TimestampValueFromTime(*video.PublishedAt)))
				}(),
				func() table.ParameterOption {
					if video.UploadExpiresAt == nil {
						return table.ValueParam("$upload_expires_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$upload_expires_at", types.OptionalValue(types.TimestampValueFromTime(*video.UploadExpiresAt)))
				}(),
			),
		)
		return err
	})
}

// GetStorageUsage возвращает использованный объем хранилища
func (c *YDBClient) GetStorageUsage(ctx context.Context, ownerID string) (int64, int64, error) {
	query := `
		DECLARE $owner_id AS Text;

		SELECT
			COALESCE(SUM(v.file_size_bytes + CASE WHEN v.publish_status = 'published' THEN v.file_size_bytes ELSE 0 END), 0) as size,
			COUNT(*) as count
		FROM videos AS v
		INNER JOIN organizations AS o ON v.org_id = o.org_id
		WHERE o.owner_id = $owner_id AND v.is_deleted = false AND v.upload_status != 'failed'
	`

	var usage int64
	var count uint64

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

		if res.NextResultSet(ctx) && res.NextRow() {
			err := res.ScanNamed(
				named.Required("size", &usage),
				named.Required("count", &count),
			)
			if err != nil {
				return app_errors.ErrScanFailed
			}
		}
		return res.Err()
	})

	if err != nil {
		return 0, 0, err
	}
	return usage, int64(count), nil
}

// PublishVideoTx выполняет публикацию видео в одной транзакции:
// 1. Создает запись public_video_shares
// 2. Обновляет статус и URL в таблице videos
func (c *YDBClient) PublishVideoTx(ctx context.Context, share *PublicVideoShare, videoID, publicURL, status string) error {
	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		// Декларации
		declarations := `
			DECLARE $share_id AS Text;
			DECLARE $video_id AS Text;
			DECLARE $public_token AS Text;
			DECLARE $created_at AS Timestamp;
			DECLARE $created_by AS Text;
			DECLARE $revoked AS Bool;
			DECLARE $access_count AS Uint64;
			DECLARE $last_accessed_at AS Optional<Timestamp>;

			DECLARE $vid_id AS Text;
			DECLARE $vid_status AS Text;
			DECLARE $vid_public_url AS Text;
			DECLARE $vid_published_at AS Timestamp;
		`

		// Запросы
		statements := `
			-- 1. Создаем шаринг
			REPLACE INTO public_video_shares (
				share_id, video_id, public_token, created_at, created_by, revoked, access_count, last_accessed_at
			) VALUES ($share_id, $video_id, $public_token, $created_at, $created_by, $revoked, $access_count, $last_accessed_at);

			-- 2. Обновляем видео
			UPDATE videos
			SET publish_status = $vid_status,
				public_url = $vid_public_url,
				published_at = $vid_published_at
			WHERE video_id = $vid_id;
		`

		finalQuery := declarations + "\n" + statements
		now := time.Now()

		// Параметры
		params := table.NewQueryParameters(
			// Params for Share
			table.ValueParam("$share_id", types.TextValue(share.ShareID)),
			table.ValueParam("$video_id", types.TextValue(share.VideoID)),
			table.ValueParam("$public_token", types.TextValue(share.PublicToken)),
			table.ValueParam("$created_at", types.TimestampValueFromTime(share.CreatedAt)),
			table.ValueParam("$created_by", types.TextValue(share.CreatedBy)),
			table.ValueParam("$revoked", types.BoolValue(share.Revoked)),
			table.ValueParam("$access_count", types.Uint64Value(share.AccessCount)),
			table.ValueParam("$last_accessed_at", types.NullValue(types.TypeTimestamp)), // Изначально null

			// Params for Video Update
			table.ValueParam("$vid_id", types.TextValue(videoID)),
			table.ValueParam("$vid_status", types.TextValue(status)),
			table.ValueParam("$vid_public_url", types.TextValue(publicURL)),
			table.ValueParam("$vid_published_at", types.TimestampValueFromTime(now)),
		)

		_, _, err := session.Execute(
			ctx,
			table.TxControl(table.BeginTx(table.WithSerializableReadWrite()), table.CommitTx()),
			finalQuery,
			params,
		)
		return err
	})
}

// GetVideoByShareToken получает видео по токену
func (c *YDBClient) GetVideoByShareToken(ctx context.Context, token string) (*Video, error) {
	query := `
		DECLARE $token AS Text;
		SELECT video_id, org_id, uploaded_by, title, file_name, file_name_search, file_size_bytes, storage_path,
		       duration_seconds, upload_id, upload_status, parts_uploaded, total_parts, public_share_token, share_expires_at, uploaded_at, created_at, is_deleted,
		       public_url, publish_status, published_at, upload_expires_at
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
			var uploadExpiresAt *time.Time
			var isDeleted *bool
			var publishStatus *string

			err := res.Scan(
				&v.VideoID,
				&v.OrgID,
				&v.UploadedBy,
				&v.Title,
				&v.FileName,
				&v.FileNameSearch,
				&v.FileSizeBytes,
				&v.StoragePath,
				&v.DurationSeconds,
				&v.UploadID,
				&v.UploadStatus,
				&partsUploaded,
				&totalParts,
				&publicShareToken,
				&shareExpiresAt,
				&uploadedAt,
				&v.CreatedAt,
				&isDeleted,
				&v.PublicURL,
				&publishStatus,
				&v.PublishedAt,
				&uploadExpiresAt,
			)

			if err != nil {
				return app_errors.ErrScanFailed
			}
			// Присваиваем значения nullable полей
			v.PartsUploaded = partsUploaded
			v.TotalParts = totalParts
			v.PublicShareToken = publicShareToken
			v.ShareExpiresAt = shareExpiresAt
			v.UploadedAt = uploadedAt
			v.UploadExpiresAt = uploadExpiresAt
			if isDeleted != nil {
				v.IsDeleted = *isDeleted
			}
			if publishStatus != nil {
				v.PublishStatus = *publishStatus
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, app_errors.ErrVideoNotFound
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
		// Экранируем спецсимволы для LIKE, чтобы предотвратить инъекцию логики поиска
		safeQuery := strings.ToLower(query)
		safeQuery = strings.ReplaceAll(safeQuery, "\\", "\\\\") // Сначала экранируем сам экранирующий символ
		safeQuery = strings.ReplaceAll(safeQuery, "%", "\\%")   // Экранируем процент
		safeQuery = strings.ReplaceAll(safeQuery, "_", "\\_")   // Экранируем подчеркивание
		countParamsBuilder = append(countParamsBuilder, table.ValueParam("$query", types.TextValue(safeQuery+"%")))
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
				return app_errors.ErrScanFailed
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
	SELECT video_id, org_id, uploaded_by, title, file_name, file_name_search, file_size_bytes,
	       storage_path, duration_seconds, upload_id, upload_status, parts_uploaded, total_parts,
	       public_share_token, share_expires_at, uploaded_at, created_at, is_deleted,
	       public_url, publish_status, published_at, upload_expires_at
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
		// Повторяем экранирование для второго запроса
		safeQuery := strings.ToLower(query)
		safeQuery = strings.ReplaceAll(safeQuery, "\\", "\\\\")
		safeQuery = strings.ReplaceAll(safeQuery, "%", "\\%")
		safeQuery = strings.ReplaceAll(safeQuery, "_", "\\_")
		dataParamsBuilder = append(dataParamsBuilder, table.ValueParam("$query", types.TextValue(safeQuery+"%")))
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
				var uploadExpiresAt *time.Time
				var isDeleted *bool
				var publishStatus *string

				if err := res.Scan(
					&v.VideoID,
					&v.OrgID,
					&v.UploadedBy,
					&v.Title,
					&v.FileName,
					&v.FileNameSearch,
					&v.FileSizeBytes,
					&v.StoragePath,
					&v.DurationSeconds,
					&v.UploadID,
					&v.UploadStatus,
					&partsUploaded,
					&totalParts,
					&publicShareToken,
					&shareExpiresAt,
					&uploadedAt,
					&v.CreatedAt,
					&isDeleted,
					&v.PublicURL,
					&publishStatus,
					&v.PublishedAt,
					&uploadExpiresAt); err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}

				v.PartsUploaded = partsUploaded
				v.TotalParts = totalParts
				v.PublicShareToken = publicShareToken
				v.ShareExpiresAt = shareExpiresAt
				v.UploadedAt = uploadedAt
				v.UploadExpiresAt = uploadExpiresAt
				if isDeleted != nil {
					v.IsDeleted = *isDeleted
				}
				if publishStatus != nil {
					v.PublishStatus = *publishStatus
				}

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
        ORDER BY created_at ASC
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
					named.Optional("delivered_at", &log.DeliveredAt),
					named.Optional("error_message", &log.ErrorMessage),
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
				func() table.ParameterOption {
					if log.DeliveredAt == nil {
						return table.ValueParam("$delivered_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$delivered_at", types.OptionalValue(types.TimestampValueFromTime(*log.DeliveredAt)))
				}(),
				func() table.ParameterOption {
					if log.ErrorMessage == nil {
						return table.ValueParam("$error_message", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$error_message", types.OptionalValue(types.TextValue(*log.ErrorMessage)))
				}(),
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
				return app_errors.ErrScanFailed
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

// UpdateUserPasswordResetInfo обновляет код сброса пароля
func (c *YDBClient) UpdateUserPasswordResetInfo(ctx context.Context, userID string, code string, expiresAt time.Time) error {
	query := `
		DECLARE $user_id AS Text;
		DECLARE $code AS Text;
		DECLARE $expires_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		UPDATE users
		SET password_reset_code = $code,
			password_reset_expires_at = $expires_at,
			updated_at = $updated_at
		WHERE user_id = $user_id
	`
	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(userID)),
				table.ValueParam("$code", types.TextValue(code)),
				table.ValueParam("$expires_at", types.TimestampValueFromTime(expiresAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(time.Now())),
			),
		)
		return err
	})
}

// UpdateUserPassword обновляет пароль пользователя и сбрасывает код восстановления
func (c *YDBClient) UpdateUserPassword(ctx context.Context, userID string, passwordHash string) error {
	// 1. Сначала получаем полную запись пользователя
	user, err := c.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to fetch user for password update: %w", err)
	}

	// 2. Модифицируем необходимые поля в объекте
	user.PasswordHash = passwordHash
	user.PasswordResetCode = nil
	user.PasswordResetExpiresAt = nil
	user.UpdatedAt = time.Now()

	// 3. Используем REPLACE INTO для полной замены строки
	query := `
		DECLARE $user_id AS Text;
		DECLARE $email AS Text;
		DECLARE $password_hash AS Text;
		DECLARE $full_name AS Text;
		DECLARE $email_verified AS Bool;
		DECLARE $verification_code AS Text;
		DECLARE $verification_expires_at AS Timestamp;
		DECLARE $verification_attempts AS Int32;
        DECLARE $password_reset_code AS Optional<Text>;
        DECLARE $password_reset_expires_at AS Optional<Timestamp>;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;
		DECLARE $is_active AS Bool;
		DECLARE $last_org_id AS Optional<Text>;

		REPLACE INTO users (
			user_id, email, password_hash, full_name, email_verified,
			verification_code, verification_expires_at, verification_attempts,
            password_reset_code, password_reset_expires_at,
			created_at, updated_at, is_active, last_org_id
		) VALUES (
			$user_id, $email, $password_hash, $full_name, $email_verified,
			$verification_code, $verification_expires_at, $verification_attempts,
            $password_reset_code, $password_reset_expires_at,
			$created_at, $updated_at, $is_active, $last_org_id
		)
	`
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
				table.ValueParam("$verification_attempts", types.Int32Value(user.VerificationAttempts)),
				table.ValueParam("$password_reset_code", types.NullValue(types.TypeText)),
				table.ValueParam("$password_reset_expires_at", types.NullValue(types.TypeTimestamp)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(user.CreatedAt)),
				table.ValueParam("$updated_at", types.TimestampValueFromTime(user.UpdatedAt)),
				table.ValueParam("$is_active", types.BoolValue(user.IsActive)),
				func() table.ParameterOption {
					if user.LastOrgID == nil {
						return table.ValueParam("$last_org_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$last_org_id", types.OptionalValue(types.TextValue(*user.LastOrgID)))
				}(),
			),
		)
		return err
	})
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

// CreatePublicVideoShare creates a new public video share record
func (c *YDBClient) CreatePublicVideoShare(ctx context.Context, share *PublicVideoShare) error {
	query := `
		DECLARE $share_id AS Text;
		DECLARE $video_id AS Text;
		DECLARE $public_token AS Text;
		DECLARE $created_at AS Timestamp;
		DECLARE $created_by AS Text;
		DECLARE $revoked AS Bool;
		DECLARE $access_count AS Uint64;
		DECLARE $last_accessed_at AS Optional<Timestamp>;

		REPLACE INTO public_video_shares (
			share_id, video_id, public_token, created_at, created_by, revoked, access_count, last_accessed_at
		) VALUES ($share_id, $video_id, $public_token, $created_at, $created_by, $revoked, $access_count, $last_accessed_at)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$share_id", types.TextValue(share.ShareID)),
				table.ValueParam("$video_id", types.TextValue(share.VideoID)),
				table.ValueParam("$public_token", types.TextValue(share.PublicToken)),
				table.ValueParam("$created_at", types.TimestampValueFromTime(share.CreatedAt)),
				table.ValueParam("$created_by", types.TextValue(share.CreatedBy)),
				table.ValueParam("$revoked", types.BoolValue(share.Revoked)),
				table.ValueParam("$access_count", types.Uint64Value(share.AccessCount)),
				func() table.ParameterOption {
					if share.LastAccessedAt == nil {
						return table.ValueParam("$last_accessed_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$last_accessed_at", types.OptionalValue(types.TimestampValueFromTime(*share.LastAccessedAt)))
				}(),
			),
		)
		return err
	})
}

// GetPublicVideoShareByToken gets public video share by token
func (c *YDBClient) GetPublicVideoShareByToken(ctx context.Context, token string) (*PublicVideoShare, error) {
	query := `
		DECLARE $public_token AS Text;
		SELECT share_id, video_id, public_token, created_at, created_by, revoked, revoked_at, access_count, last_accessed_at
		FROM public_video_shares
		WHERE public_token = $public_token
	`

	var share PublicVideoShare
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$public_token", types.TextValue(token)),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			found = true
			var lastAccessedAt *time.Time
			err := res.ScanNamed(
				named.Required("share_id", &share.ShareID),
				named.Required("video_id", &share.VideoID),
				named.Required("public_token", &share.PublicToken),
				named.Required("created_at", &share.CreatedAt),
				named.Required("created_by", &share.CreatedBy),
				named.Required("revoked", &share.Revoked),
				named.Optional("revoked_at", &share.RevokedAt),
				named.Required("access_count", &share.AccessCount),
				named.Optional("last_accessed_at", &lastAccessedAt),
			)
			if err != nil {
				return app_errors.ErrScanFailed
			}
			share.LastAccessedAt = lastAccessedAt
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("public video share not found")
	}

	return &share, nil
}

// GetActivePublicVideoShare gets the active (not revoked) public share for a video
func (c *YDBClient) GetActivePublicVideoShare(ctx context.Context, videoID string) (*PublicVideoShare, error) {
	query := `
		DECLARE $video_id AS Text;
		SELECT share_id, video_id, public_token, created_at, created_by, revoked, revoked_at, access_count, last_accessed_at
		FROM public_video_shares
		WHERE video_id = $video_id AND revoked = false
		LIMIT 1
	`

	var share PublicVideoShare
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
			var lastAccessedAt *time.Time
			err := res.ScanNamed(
				named.Required("share_id", &share.ShareID),
				named.Required("video_id", &share.VideoID),
				named.Required("public_token", &share.PublicToken),
				named.Required("created_at", &share.CreatedAt),
				named.Required("created_by", &share.CreatedBy),
				named.Required("revoked", &share.Revoked),
				named.Optional("revoked_at", &share.RevokedAt),
				named.Required("access_count", &share.AccessCount),
				named.Optional("last_accessed_at", &lastAccessedAt),
			)
			if err != nil {
				return app_errors.ErrScanFailed
			}
			share.LastAccessedAt = lastAccessedAt
		}
		return res.Err()
	})

	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("active public share not found")
	}

	return &share, nil
}

// RevokePublicVideoShare revokes public access to a video
func (c *YDBClient) RevokePublicVideoShare(ctx context.Context, videoID, userID string) error {
	query := `
		DECLARE $video_id AS Text;
		DECLARE $user_id AS Text;
		DECLARE $revoked_at AS Timestamp;

		UPDATE public_video_shares
		SET revoked = true, revoked_at = $revoked_at
		WHERE video_id = $video_id
	`

	now := time.Now()

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$video_id", types.TextValue(videoID)),
				table.ValueParam("$user_id", types.TextValue(userID)),
				table.ValueParam("$revoked_at", types.TimestampValueFromTime(now)),
			),
		)
		return err
	})
}

// IncrementAccessCount increments access count for public video share
func (c *YDBClient) IncrementAccessCount(ctx context.Context, token string) error {
	query := `
		DECLARE $public_token AS Text;
		DECLARE $last_accessed_at AS Timestamp;

		UPDATE public_video_shares
		SET access_count = access_count + 1, last_accessed_at = $last_accessed_at
		WHERE public_token = $public_token
	`

	now := time.Now()

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$public_token", types.TextValue(token)),
				table.ValueParam("$last_accessed_at", types.TimestampValueFromTime(now)),
			),
		)
		return err
	})
}

// UpdateVideoStatus updates video publish status and public URL
func (c *YDBClient) UpdateVideoStatus(ctx context.Context, videoID, status, publicURL string) error {
	query := `
		DECLARE $video_id AS Text;
		DECLARE $status AS Text;
		DECLARE $public_url AS Optional<Text>;

		UPDATE videos
		SET publish_status = $status, public_url = $public_url
		WHERE video_id = $video_id
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$video_id", types.TextValue(videoID)),
				table.ValueParam("$status", types.TextValue(status)),
				func() table.ParameterOption {
					if publicURL == "" {
						return table.ValueParam("$public_url", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$public_url", types.OptionalValue(types.TextValue(publicURL)))
				}(),
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
				return app_errors.ErrScanFailed
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
		VALUES ($id, $timestamp, $user_id, $org_id, $action_type, $action_result, $ip_address, $user_agent, $details);
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

// internal/ydb/client.go

// ... (предыдущий код)

// GetAuditLogs получает логи аудита с фильтрацией и пагинацией
func (c *YDBClient) GetAuditLogs(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.AuditLog, int64, error) {
	var (
		declarations []string
		conditions   []string
		queryParams  []table.ParameterOption
	)

	// Helper для добавления фильтров
	addFilter := func(key, paramName, dbField, typeName string, value interface{}) {
		declarations = append(declarations, fmt.Sprintf("DECLARE $%s AS %s;", paramName, typeName))
		conditions = append(conditions, fmt.Sprintf("%s = $%s", dbField, paramName))

		var paramValue types.Value
		switch v := value.(type) {
		case string:
			paramValue = types.TextValue(v)
		default:
			// Fallback, хотя в текущем коде все фильтры строковые
			paramValue = types.TextValue(fmt.Sprintf("%v", v))
		}
		queryParams = append(queryParams, table.ValueParam("$"+paramName, paramValue))
	}

	// 1. Сборка фильтров
	if userID, ok := filters["user_id"].(string); ok && userID != "" {
		addFilter("user_id", "user_id", "user_id", "Text", userID)
	}

	if orgID, ok := filters["org_id"].(string); ok && orgID != "" {
		addFilter("org_id", "org_id", "org_id", "Text", orgID)
	}

	if actionType, ok := filters["action_type"].(string); ok && actionType != "" {
		addFilter("action_type", "action_type", "action_type", "Text", actionType)
	}

	if result, ok := filters["result"].(string); ok && result != "" {
		addFilter("result", "action_result", "action_result", "Text", result)
	}

	// Обработка дат
	if from, ok := filters["from"].(string); ok && from != "" {
		fromTime, err := time.Parse("2006-01-02", from)
		if err == nil {
			declarations = append(declarations, "DECLARE $from_date AS Timestamp;")
			conditions = append(conditions, "timestamp >= $from_date")
			queryParams = append(queryParams, table.ValueParam("$from_date", types.TimestampValueFromTime(fromTime.UTC())))
		}
	}

	if to, ok := filters["to"].(string); ok && to != "" {
		toTime, err := time.Parse("2006-01-02", to)
		if err == nil {
			// Добавляем 1 день, чтобы включить конец даты
			toTime = toTime.AddDate(0, 0, 1)
			declarations = append(declarations, "DECLARE $to_date AS Timestamp;")
			conditions = append(conditions, "timestamp < $to_date")
			queryParams = append(queryParams, table.ValueParam("$to_date", types.TimestampValueFromTime(toTime.UTC())))
		}
	}
	// Защита от отрицательных значений перед приведением к uint64
	if limit < 0 {
		limit = 0
	}
	if offset < 0 {
		offset = 0
	}
	// Сборка частей запроса
	declareClause := strings.Join(declarations, "\n")
	whereClause := ""
	if len(conditions) > 0 {
		// Добавляем перенос строки для чистоты запроса
		whereClause = "\nWHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	var logs []*models.AuditLog

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		// 2. Запрос количества (Count)
		// Используем те же параметры, что собрали выше
		// Убираем пробел перед %s, так как whereClause начинается с \n или пуст
		countQuery := fmt.Sprintf("%s\nSELECT COUNT(*) as total FROM audit_logs%s", declareClause, whereClause)

		_, res, err := session.Execute(ctx, table.DefaultTxControl(), countQuery, table.NewQueryParameters(queryParams...))
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

		// 3. Запрос данных (Data)
		// Добавляем параметры пагинации
		dataDeclarations := append(declarations,
			"DECLARE $limit AS Uint64;",
			"DECLARE $offset AS Uint64;",
		)
		dataDeclareClause := strings.Join(dataDeclarations, "\n")

		// Копируем параметры и добавляем limit/offset
		dataParams := make([]table.ParameterOption, len(queryParams))
		copy(dataParams, queryParams)
		dataParams = append(dataParams,
			table.ValueParam("$limit", types.Uint64Value(uint64(limit))),
			table.ValueParam("$offset", types.Uint64Value(uint64(offset))),
		)

		logsQuery := fmt.Sprintf(`
%s
SELECT id, timestamp, user_id, org_id, action_type, action_result, ip_address, user_agent, details
FROM audit_logs%s
ORDER BY timestamp DESC
LIMIT $limit OFFSET $offset
`, dataDeclareClause, whereClause)

		_, res, err = session.Execute(ctx, table.DefaultTxControl(), logsQuery, table.NewQueryParameters(dataParams...))
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

func (c *YDBClient) GetOrganizationsByIDs(ctx context.Context, orgIDs []string) ([]*Organization, error) {
	if len(orgIDs) == 0 {
		return []*Organization{}, nil
	}

	query := `
		DECLARE $org_ids AS List<Text>;
		SELECT org_id, name, owner_id, settings, created_at, updated_at
		FROM organizations
		WHERE org_id IN $org_ids
	`

	// Конвертируем []string в []types.Value для YDB
	ydbValues := make([]types.Value, len(orgIDs))
	for i, id := range orgIDs {
		ydbValues[i] = types.TextValue(id)
	}

	var orgs []*Organization

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_ids", types.ListValue(ydbValues...)),
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

// RegisterUserTx выполняет регистрацию пользователя, организации и подписки в одной транзакции
func (c *YDBClient) RegisterUserTx(ctx context.Context, user *User, org *Organization, membership *Membership, subscription *Subscription, invitationID string) error {
	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		var declarations strings.Builder
		var statements strings.Builder
		var paramOpts []table.ParameterOption

		// ========== ДЕКЛАРАЦИИ ==========
		// 1) Декларации для пользователя
		declarations.WriteString(`
		DECLARE $user_id AS Text;
		DECLARE $email AS Text;
		DECLARE $password_hash AS Text;
		DECLARE $full_name AS Text;
		DECLARE $email_verified AS Bool;
		DECLARE $verification_code AS Text;
		DECLARE $verification_expires_at AS Timestamp;
		DECLARE $verification_attempts AS Int32;
		DECLARE $user_created_at AS Timestamp;
		DECLARE $user_updated_at AS Timestamp;
		DECLARE $is_active AS Bool;
		DECLARE $last_org_id AS Optional<Text>;
`)

		paramOpts = append(paramOpts,
			table.ValueParam("$user_id", types.TextValue(user.UserID)),
			table.ValueParam("$email", types.TextValue(user.Email)),
			table.ValueParam("$password_hash", types.TextValue(user.PasswordHash)),
			table.ValueParam("$full_name", types.TextValue(user.FullName)),
			table.ValueParam("$email_verified", types.BoolValue(user.EmailVerified)),
			table.ValueParam("$verification_code", types.TextValue(user.VerificationCode)),
			table.ValueParam("$verification_expires_at", types.TimestampValueFromTime(user.VerificationExpiresAt)),
			table.ValueParam("$verification_attempts", types.Int32Value(user.VerificationAttempts)),
			table.ValueParam("$user_created_at", types.TimestampValueFromTime(user.CreatedAt)),
			table.ValueParam("$user_updated_at", types.TimestampValueFromTime(user.UpdatedAt)),
			table.ValueParam("$is_active", types.BoolValue(user.IsActive)),
			func() table.ParameterOption {
				if user.LastOrgID == nil {
					return table.ValueParam("$last_org_id", types.NullValue(types.TypeText))
				}
				return table.ValueParam("$last_org_id", types.OptionalValue(types.TextValue(*user.LastOrgID)))
			}(),
		)

		// 2) Декларации для организации (если нужна)
		if org != nil {
			declarations.WriteString(`
		DECLARE $org_id AS Text;
		DECLARE $org_name AS Text;
		DECLARE $owner_id AS Text;
		DECLARE $settings AS Json;
		DECLARE $org_created_at AS Timestamp;
		DECLARE $org_updated_at AS Timestamp;
`)

			settingsJSON := "{}"
			if org.Settings != "" {
				settingsJSON = org.Settings
			}

			paramOpts = append(paramOpts,
				table.ValueParam("$org_id", types.TextValue(org.OrgID)),
				table.ValueParam("$org_name", types.TextValue(org.Name)),
				table.ValueParam("$owner_id", types.TextValue(org.OwnerID)),
				table.ValueParam("$settings", types.JSONValue(settingsJSON)),
				table.ValueParam("$org_created_at", types.TimestampValueFromTime(org.CreatedAt)),
				table.ValueParam("$org_updated_at", types.TimestampValueFromTime(org.UpdatedAt)),
			)
		}

		// 3) Декларации для членства
		declarations.WriteString(`
		DECLARE $membership_id AS Text;
		DECLARE $mem_user_id AS Text;
		DECLARE $mem_org_id AS Text;
		DECLARE $role AS Text;
		DECLARE $status AS Text;
		DECLARE $invited_by AS Text;
		DECLARE $mem_created_at AS Timestamp;
		DECLARE $mem_updated_at AS Timestamp;
`)

		paramOpts = append(paramOpts,
			table.ValueParam("$membership_id", types.TextValue(membership.MembershipID)),
			table.ValueParam("$mem_user_id", types.TextValue(membership.UserID)),
			table.ValueParam("$mem_org_id", types.TextValue(membership.OrgID)),
			table.ValueParam("$role", types.TextValue(membership.Role)),
			table.ValueParam("$status", types.TextValue(membership.Status)),
			table.ValueParam("$invited_by", types.TextValue(membership.InvitedBy)),
			table.ValueParam("$mem_created_at", types.TimestampValueFromTime(membership.CreatedAt)),
			table.ValueParam("$mem_updated_at", types.TimestampValueFromTime(membership.UpdatedAt)),
		)

		// 4) Декларации для подписки (если нужна)
		if subscription != nil {
			declarations.WriteString(`
		DECLARE $subscription_id AS Text;
		DECLARE $sub_user_id AS Text;
		DECLARE $sub_org_id AS Text;
		DECLARE $plan_id AS Text;
		DECLARE $storage_limit_mb AS Int64;
		DECLARE $video_count_limit AS Int64;
		DECLARE $sub_is_active AS Bool;
		DECLARE $trial_ends_at AS Timestamp;
		DECLARE $started_at AS Timestamp;
		DECLARE $expires_at AS Timestamp;
		DECLARE $billing_cycle AS Text;
		DECLARE $sub_created_at AS Timestamp;
		DECLARE $sub_updated_at AS Timestamp;
`)

			paramOpts = append(paramOpts,
				table.ValueParam("$subscription_id", types.TextValue(subscription.SubscriptionID)),
				table.ValueParam("$sub_user_id", types.TextValue(subscription.UserID)),
				table.ValueParam("$sub_org_id", types.TextValue(subscription.OrgID)),
				table.ValueParam("$plan_id", types.TextValue(subscription.PlanID)),
				table.ValueParam("$storage_limit_mb", types.Int64Value(subscription.StorageLimitMB)),
				table.ValueParam("$video_count_limit", types.Int64Value(subscription.VideoCountLimit)),
				table.ValueParam("$sub_is_active", types.BoolValue(subscription.IsActive)),
				table.ValueParam("$trial_ends_at", types.TimestampValueFromTime(subscription.TrialEndsAt)),
				table.ValueParam("$started_at", types.TimestampValueFromTime(subscription.StartedAt)),
				table.ValueParam("$expires_at", types.TimestampValueFromTime(subscription.ExpiresAt)),
				table.ValueParam("$billing_cycle", types.TextValue(subscription.BillingCycle)),
				table.ValueParam("$sub_created_at", types.TimestampValueFromTime(subscription.CreatedAt)),
				table.ValueParam("$sub_updated_at", types.TimestampValueFromTime(subscription.UpdatedAt)),
			)
		}

		// 5) Декларации для приглашения (если нужно)
		if invitationID != "" {
			declarations.WriteString(`
		DECLARE $invitation_id AS Text;
		DECLARE $inv_status AS Text;
		DECLARE $accepted_at AS Timestamp;
`)

			paramOpts = append(paramOpts,
				table.ValueParam("$invitation_id", types.TextValue(invitationID)),
				table.ValueParam("$inv_status", types.TextValue("accepted")),
				table.ValueParam("$accepted_at", types.TimestampValueFromTime(time.Now())),
			)
		}

		// ========== SQL STATEMENTS ==========
		// 1) INSERT пользователя
		statements.WriteString(`
			INSERT INTO users (
				user_id, email, password_hash, full_name, email_verified,
				verification_code, verification_expires_at, verification_attempts,
				created_at, updated_at, is_active, last_org_id
			) VALUES (
				$user_id, $email, $password_hash, $full_name, $email_verified,
				$verification_code, $verification_expires_at, $verification_attempts,
				$user_created_at, $user_updated_at, $is_active, $last_org_id
			);
		`)
		// 2) INSERT организации (если нужна)
		if org != nil {
			statements.WriteString(`
		INSERT INTO organizations (org_id, name, owner_id, settings, created_at, updated_at)
		VALUES ($org_id, $org_name, $owner_id, $settings, $org_created_at, $org_updated_at);
`)
		}

		// 3) INSERT членства
		statements.WriteString(`
		INSERT INTO memberships (
			membership_id, user_id, org_id, role, status, invited_by, created_at, updated_at
		) VALUES (
			$membership_id, $mem_user_id, $mem_org_id, $role, $status, $invited_by, $mem_created_at, $mem_updated_at
		);
`)

		// 4) INSERT подписки (если нужна)
		if subscription != nil {
			statements.WriteString(`
		INSERT INTO subscriptions (
			subscription_id, user_id, org_id, plan_id, storage_limit_mb, video_count_limit,
			is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		) VALUES (
			$subscription_id, $sub_user_id, $sub_org_id, $plan_id, $storage_limit_mb, $video_count_limit,
			$sub_is_active, $trial_ends_at, $started_at, $expires_at, $billing_cycle, $sub_created_at, $sub_updated_at
		);
`)
		}

		// 5) UPDATE приглашения (если нужно)
		if invitationID != "" {
			statements.WriteString(`
		UPDATE invitations
		SET status = $inv_status, accepted_at = $accepted_at
		WHERE invitation_id = $invitation_id;
`)
		}

		// Собираем финальный запрос: сначала ВСЕ декларации, потом ВСЕ statements
		finalQuery := declarations.String() + "\n" + statements.String()

		// Выполняем все в одной транзакции
		_, _, err := session.Execute(
			ctx,
			table.TxControl(table.BeginTx(table.WithSerializableReadWrite()), table.CommitTx()),
			finalQuery,
			table.NewQueryParameters(paramOpts...),
		)
		return err
	})
}

func (c *YDBClient) GetInvitationByID(ctx context.Context, invitationID string) (*Invitation, error) {
	query := `
		DECLARE $invitation_id AS Text;
		SELECT invitation_id, org_id, email, role, invite_code, invited_by, status, expires_at, created_at, accepted_at
		FROM invitations
		WHERE invitation_id = $invitation_id
	`

	var invitation *Invitation
	var found bool

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$invitation_id", types.TextValue(invitationID)),
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
				return app_errors.ErrScanFailed
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

// DeleteOrganizationTx удаляет организацию и все связанные данные в одной транзакции
func (c *YDBClient) DeleteOrganizationTx(ctx context.Context, orgID string) error {
	query := `
		DECLARE $org_id AS Text;

		DELETE FROM organizations WHERE org_id = $org_id;
		DELETE FROM memberships WHERE org_id = $org_id;
		DELETE FROM invitations WHERE org_id = $org_id;
		DELETE FROM subscriptions WHERE org_id = $org_id;
		DELETE FROM videos WHERE org_id = $org_id;
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(table.ValueParam("$org_id", types.TextValue(orgID))),
		)
		return err
	})
}
