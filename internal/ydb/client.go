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
				full_name Text,
				email_verified Bool DEFAULT false,
				verification_code Text,
				verification_expires_at Optional<Timestamp>,
				created_at Timestamp,
				updated_at Timestamp,
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
				name Text,
				owner_id Text,
				settings Json,
				created_at Timestamp,
				updated_at Timestamp,
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
				role Text,
				status Text,
				invited_by Text,
				created_at Timestamp,
				updated_at Timestamp,
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
				token_hash Optional<Text>,
				expires_at Optional<Timestamp>,
				created_at Timestamp,
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
				email_type Text,
				recipient Text,
				status Text,
				postbox_message_id Text,
				sent_at Timestamp,
				delivered_at Optional<Timestamp>,
				error_message Text,
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
				name Text,
				storage_limit_gb Int64,
				video_count_limit Int64,
				price_rub Double,
				billing_cycle Text,
				features Json,
				created_at Timestamp,
				updated_at Timestamp,
				PRIMARY KEY (plan_id)
			)
		`
		err := c.executeSchemeQuery(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to create plans table: %w", err)
		}

		// Вставляем базовые тарифные планы только после создания таблицы
		plansQuery := `
			REPLACE INTO plans (plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at)
			VALUES
			('free', 'Free', 1, 10, 0, 'monthly', '{"sharing": false, "search": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp()),
			('pro', 'Pro', 100, 1000, 990, 'monthly', '{"sharing": true, "search": true, "analytics": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp()),
			('enterprise', 'Enterprise', 0, 0, 4990, 'monthly', '{"sharing": true, "search": true, "analytics": true, "api_access": true, "priority_support": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp())
		`
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
				storage_limit_gb Int64,
				video_count_limit Int64,
				is_active Bool DEFAULT true,
				trial_ends_at Timestamp,
				started_at Timestamp,
				expires_at Optional<Timestamp>,
				billing_cycle Text,
				created_at Timestamp,
				updated_at Timestamp,
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
				file_name Text,
				file_name_search Text,
				file_size_bytes Int64,
				storage_path Text,
				duration_seconds Int32,
				upload_id Text,
				upload_status Text,
				parts_uploaded Int32 DEFAULT 0,
				total_parts Int32 DEFAULT 0,
				public_share_token Text,
				share_expires_at Optional<Timestamp>,
				uploaded_at Timestamp,
				created_at Timestamp,
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
				storage_limit_gb Int64,
				video_count_limit Int64,
				event_type Text,
				changed_at Timestamp,
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
		DECLARE $full_name AS Optional<Text>;
		DECLARE $email_verified AS Bool;
		DECLARE $verification_code AS Optional<Text>;
		DECLARE $verification_expires_at AS Optional<Timestamp>;
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

				func() table.ParameterOption {
					if user.FullName == nil {
						return table.ValueParam("$full_name", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$full_name", types.OptionalValue(types.TextValue(*user.FullName)))
				}(),
				table.ValueParam("$email_verified", types.BoolValue(user.EmailVerified)),
				func() table.ParameterOption {
					if user.VerificationCode == nil {
						return table.ValueParam("$verification_code", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$verification_code", types.OptionalValue(types.TextValue(*user.VerificationCode)))
				}(),
				func() table.ParameterOption {
					if user.VerificationExpiresAt == nil {
						return table.ValueParam("$verification_expires_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$verification_expires_at", types.OptionalValue(types.TimestampValueFromTime(*user.VerificationExpiresAt)))
				}(),
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
				named.Optional("full_name", &user.FullName),
				named.Required("email_verified", &user.EmailVerified),
				named.Optional("verification_code", &user.VerificationCode),
				named.Optional("verification_expires_at", &user.VerificationExpiresAt),
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
				named.Optional("full_name", &user.FullName),
				named.Required("email_verified", &user.EmailVerified),
				named.Optional("verification_code", &user.VerificationCode),
				named.Optional("verification_expires_at", &user.VerificationExpiresAt),
				named.OptionalWithDefault("created_at", &user.CreatedAt),
				named.OptionalWithDefault("updated_at", &user.UpdatedAt),
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
		DECLARE $full_name AS Optional<Text>;
		DECLARE $email_verified AS Bool;
		DECLARE $verification_code AS Optional<Text>;
		DECLARE $verification_expires_at AS Optional<Timestamp>;
		DECLARE $updated_at AS Timestamp;
		DECLARE $is_active AS Bool;

		REPLACE INTO users (
			user_id, email, password_hash, full_name, email_verified,
			verification_code, verification_expires_at, updated_at, is_active
		) VALUES ($user_id, $email, $password_hash, $full_name, $email_verified, $verification_code, $verification_expires_at, $updated_at, $is_active)
	`

	user.UpdatedAt = time.Now()

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$user_id", types.TextValue(user.UserID)),
				table.ValueParam("$email", types.TextValue(user.Email)),
				table.ValueParam("$password_hash", types.TextValue(user.PasswordHash)),

				func() table.ParameterOption {
					if user.FullName == nil {
						return table.ValueParam("$full_name", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$full_name", types.OptionalValue(types.TextValue(*user.FullName)))
				}(),
				table.ValueParam("$email_verified", types.BoolValue(user.EmailVerified)),
				func() table.ParameterOption {
					if user.VerificationCode == nil {
						return table.ValueParam("$verification_code", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$verification_code", types.OptionalValue(types.TextValue(*user.VerificationCode)))
				}(),
				func() table.ParameterOption {
					if user.VerificationExpiresAt == nil {
						return table.ValueParam("$verification_expires_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$verification_expires_at", types.OptionalValue(types.TimestampValueFromTime(*user.VerificationExpiresAt)))
				}(),
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
		DECLARE $name AS Optional<Text>;
		DECLARE $owner_id AS Optional<Text>;
		DECLARE $settings AS Json;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO organizations (org_id, name, owner_id, settings, created_at, updated_at)
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
	if org.Settings != nil && *org.Settings != "" {
		settingsJSON = *org.Settings
	} else {
		settingsJSON = "{}"
	}

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(org.OrgID)),
				func() table.ParameterOption {
					if org.Name == nil {
						return table.ValueParam("$name", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$name", types.OptionalValue(types.TextValue(*org.Name)))
				}(),
				func() table.ParameterOption {
					if org.OwnerID == nil {
						return table.ValueParam("$owner_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$owner_id", types.OptionalValue(types.TextValue(*org.OwnerID)))
				}(),
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
		DECLARE $role AS Optional<Text>;
		DECLARE $status AS Optional<Text>;
		DECLARE $invited_by AS Optional<Text>;
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
				func() table.ParameterOption {
					if membership.Role == nil {
						return table.ValueParam("$role", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$role", types.OptionalValue(types.TextValue(*membership.Role)))
				}(),
				func() table.ParameterOption {
					if membership.Status == nil {
						return table.ValueParam("$status", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$status", types.OptionalValue(types.TextValue(*membership.Status)))
				}(),
				func() table.ParameterOption {
					if membership.InvitedBy == nil {
						return table.ValueParam("$invited_by", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$invited_by", types.OptionalValue(types.TextValue(*membership.InvitedBy)))
				}(),
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
		DECLARE $token_hash AS Optional<Text>;
		DECLARE $expires_at AS Optional<Timestamp>;
		DECLARE $created_at AS Optional<Timestamp>;

		REPLACE INTO refresh_tokens (token_id, user_id, token_hash, expires_at, created_at)
		VALUES ($token_id, $user_id, $token_hash, $expires_at, $created_at)
	`

	now := time.Now()
	if token.CreatedAt.IsZero() {
		if token.CreatedAt == nil {
			token.CreatedAt = &now
		} else {
			*token.CreatedAt = now
		}
	}

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$token_id", types.TextValue(token.TokenID)),
				table.ValueParam("$user_id", types.TextValue(token.UserID)),
				func() table.ParameterOption {
					if token.TokenHash == nil {
						return table.ValueParam("$token_hash", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$token_hash", types.OptionalValue(types.TextValue(*token.TokenHash)))
				}(),
				func() table.ParameterOption {
					if token.ExpiresAt == nil {
						return table.ValueParam("$expires_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$expires_at", types.OptionalValue(types.TimestampValueFromTime(*token.ExpiresAt)))
				}(),
				func() table.ParameterOption {
					if token.CreatedAt == nil {
						return table.ValueParam("$created_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$created_at", types.OptionalValue(types.TimestampValueFromTime(*token.CreatedAt)))
				}(),
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
				named.Optional("token_hash", &token.TokenHash),
				named.Optional("expires_at", &token.ExpiresAt),
				named.Optional("created_at", &token.CreatedAt),
				named.Required("is_revoked", &token.IsRevoked),
			)

			if err != nil {
				// TODO: Remove this log
				log.Println("Error in loop ", err)
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		return res.Err()
	})

	if err != nil {
		// TODO: Remove this log
		log.Println("Error in GetRefreshToken ", err)
		return nil, err
	}
	if !found {
		// TODO: Remove this log
		log.Println("Error in GetRefreshToken ", "not found")
		return nil, fmt.Errorf("refresh token not found")
	}

	// TODO: Remove this log
	log.Println("Debug in GetRefreshToken ", token.TokenID)
	return &token, nil
}

// RevokeRefreshToken отзывает refresh токен
func (c *YDBClient) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
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
		DECLARE $email_type AS Optional<Text>;
		DECLARE $recipient AS Optional<Text>;
		DECLARE $status AS Optional<Text>;
		DECLARE $postbox_message_id AS Optional<Text>;
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
				func() table.ParameterOption {
					if log.EmailType == nil {
						return table.ValueParam("$email_type", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$email_type", types.OptionalValue(types.TextValue(*log.EmailType)))
				}(),
				func() table.ParameterOption {
					if log.Recipient == nil {
						return table.ValueParam("$recipient", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$recipient", types.OptionalValue(types.TextValue(*log.Recipient)))
				}(),
				func() table.ParameterOption {
					if log.Status == nil {
						return table.ValueParam("$status", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$status", types.OptionalValue(types.TextValue(*log.Status)))
				}(),
				func() table.ParameterOption {
					if log.PostboxMessageID == nil {
						return table.ValueParam("$postbox_message_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$postbox_message_id", types.OptionalValue(types.TextValue(*log.PostboxMessageID)))
				}(),
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
		SELECT plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at
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
				named.Required("storage_limit_gb", &plan.StorageLimitGB),
				named.Required("video_count_limit", &plan.VideoCountLimit),
				named.Required("price_rub", &plan.PriceRub),
				named.Required("billing_cycle", &plan.BillingCycle),
				named.OptionalWithDefault("features", &plan.Features),
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
		DECLARE $storage_limit_gb AS Optional<Int64>;
		DECLARE $video_count_limit AS Optional<Int64>;
		DECLARE $is_active AS Optional<Bool>;
		DECLARE $trial_ends_at AS Optional<Timestamp>;
		DECLARE $started_at AS Timestamp;
		DECLARE $expires_at AS Optional<Timestamp>;
		DECLARE $billing_cycle AS Text;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO subscriptions (
			subscription_id, user_id, org_id, plan_id, storage_limit_gb, video_count_limit,
			is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		) VALUES ($subscription_id, $user_id, $org_id, $plan_id, $storage_limit_gb, $video_count_limit, $is_active, $trial_ends_at, $started_at, $expires_at, $billing_cycle, $created_at, $updated_at)
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

				func() table.ParameterOption {
					if subscription.StorageLimitGB == nil {
						return table.ValueParam("$storage_limit_gb", types.NullValue(types.TypeInt64))
					}
					return table.ValueParam("$storage_limit_gb", types.OptionalValue(types.Int64Value(*subscription.StorageLimitGB)))
				}(),
				func() table.ParameterOption {
					if subscription.VideoCountLimit == nil {
						return table.ValueParam("$video_count_limit", types.NullValue(types.TypeInt64))
					}
					return table.ValueParam("$video_count_limit", types.OptionalValue(types.Int64Value(*subscription.VideoCountLimit)))
				}(),
				func() table.ParameterOption {
					if subscription.IsActive == nil {
						return table.ValueParam("$is_active", types.NullValue(types.TypeBool))
					}
					return table.ValueParam("$is_active", types.OptionalValue(types.BoolValue(*subscription.IsActive)))
				}(),
				func() table.ParameterOption {
					if subscription.TrialEndsAt.IsZero() {
						return table.ValueParam("$trial_ends_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$trial_ends_at", types.OptionalValue(types.TimestampValueFromTime(*subscription.TrialEndsAt)))
				}(),
				table.ValueParam("$started_at", types.TimestampValueFromTime(subscription.StartedAt)),
				func() table.ParameterOption {
					if subscription.ExpiresAt == nil || subscription.ExpiresAt.IsZero() {
						return table.ValueParam("$expires_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$expires_at", types.OptionalValue(types.TimestampValueFromTime(*subscription.ExpiresAt)))
				}(),
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
		SELECT subscription_id, user_id, org_id, plan_id, storage_limit_gb, video_count_limit,
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
				named.Required("storage_limit_gb", &subscription.StorageLimitGB),
				named.Required("video_count_limit", &subscription.VideoCountLimit),
				named.Required("is_active", &subscription.IsActive),
				named.Optional("trial_ends_at", &subscription.TrialEndsAt),
				named.Required("started_at", &subscription.StartedAt),
				named.Optional("expires_at", &subscription.ExpiresAt),
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
		DECLARE $file_name AS Optional<Text>;
		DECLARE $file_name_search AS Optional<Text>;
		DECLARE $file_size_bytes AS Optional<Int64>;
		DECLARE $storage_path AS Optional<Text>;
		DECLARE $duration_seconds AS Optional<Int32>;
		DECLARE $upload_id AS Optional<Text>;
		DECLARE $upload_status AS Optional<Text>;
		DECLARE $created_at AS Timestamp;
		DECLARE $is_deleted AS Bool;

		REPLACE INTO videos (
			video_id, org_id, uploaded_by, file_name, file_name_search, file_size_bytes,
			storage_path, duration_seconds, upload_id, upload_status, created_at, is_deleted
		) VALUES ($video_id, $org_id, $uploaded_by, $file_name, $file_name_search, $file_size_bytes, $storage_path, $duration_seconds, $upload_id, $upload_status, $created_at, $is_deleted)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$video_id", types.TextValue(video.VideoID)),
				table.ValueParam("$org_id", types.TextValue(video.OrgID)),
				table.ValueParam("$uploaded_by", types.TextValue(video.UploadedBy)),
				func() table.ParameterOption {
					if video.FileName == nil {
						return table.ValueParam("$file_name", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$file_name", types.OptionalValue(types.TextValue(*video.FileName)))
				}(),
				func() table.ParameterOption {
					if video.FileName == nil {
						return table.ValueParam("$file_name_search", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$file_name_search", types.OptionalValue(types.TextValue(strings.ToLower(*video.FileName))))
				}(),
				func() table.ParameterOption {
					if video.FileSizeBytes == nil {
						return table.ValueParam("$file_size_bytes", types.NullValue(types.TypeInt64))
					}
					return table.ValueParam("$file_size_bytes", types.OptionalValue(types.Int64Value(*video.FileSizeBytes)))
				}(),
				func() table.ParameterOption {
					if video.StoragePath == nil {
						return table.ValueParam("$storage_path", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$storage_path", types.OptionalValue(types.TextValue(*video.StoragePath)))
				}(),
				table.ValueParam("$duration_seconds", types.NullValue(types.TypeInt32)),
				func() table.ParameterOption {
					if video.UploadID == nil {
						return table.ValueParam("$upload_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$upload_id", types.OptionalValue(types.TextValue(*video.UploadID)))
				}(),
				func() table.ParameterOption {
					if video.UploadStatus == nil {
						return table.ValueParam("$upload_status", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$upload_status", types.OptionalValue(types.TextValue(*video.UploadStatus)))
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
		SELECT video_id, org_id, uploaded_by, file_name, file_size_bytes, storage_path,
		       duration_seconds, upload_id, upload_status, total_parts, public_share_token, share_expires_at, uploaded_at
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
			err := res.ScanNamed(
				named.Required("video_id", &v.VideoID),
				named.Required("org_id", &v.OrgID),
				named.Required("uploaded_by", &v.UploadedBy),
				named.Optional("file_name", &v.FileName),
				named.Optional("file_size_bytes", &v.FileSizeBytes),
				named.Optional("storage_path", &v.StoragePath),
				named.Optional("duration_seconds", &v.DurationSeconds),
				named.Optional("upload_id", &v.UploadID),
				named.Optional("upload_status", &v.UploadStatus),
				named.Optional("total_parts", &v.TotalParts),
				named.Optional("public_share_token", &v.PublicShareToken),
				named.Optional("share_expires_at", &v.ShareExpiresAt),
				named.Optional("uploaded_at", &v.UploadedAt),
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
		DECLARE $file_name AS Optional<Text>;
		DECLARE $file_name_search AS Optional<Text>;
		DECLARE $file_size_bytes AS Optional<Int64>;
		DECLARE $storage_path AS Optional<Text>;
		DECLARE $duration_seconds AS Optional<Int32>;
		DECLARE $upload_id AS Optional<Text>;
		DECLARE $upload_status AS Optional<Text>;
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
				func() table.ParameterOption {
					if video.FileName == nil {
						return table.ValueParam("$file_name", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$file_name", types.OptionalValue(types.TextValue(*video.FileName)))
				}(),
				func() table.ParameterOption {
					if video.FileName == nil {
						return table.ValueParam("$file_name_search", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$file_name_search", types.OptionalValue(types.TextValue(strings.ToLower(*video.FileName))))
				}(),
				func() table.ParameterOption {
					if video.FileSizeBytes == nil {
						return table.ValueParam("$file_size_bytes", types.NullValue(types.TypeInt64))
					}
					return table.ValueParam("$file_size_bytes", types.OptionalValue(types.Int64Value(*video.FileSizeBytes)))
				}(),
				func() table.ParameterOption {
					if video.StoragePath == nil {
						return table.ValueParam("$storage_path", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$storage_path", types.OptionalValue(types.TextValue(*video.StoragePath)))
				}(),
				table.ValueParam("$duration_seconds", types.NullValue(types.TypeInt32)),
				func() table.ParameterOption {
					if video.UploadID == nil {
						return table.ValueParam("$upload_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$upload_id", types.OptionalValue(types.TextValue(*video.UploadID)))
				}(),
				func() table.ParameterOption {
					if video.UploadStatus == nil {
						return table.ValueParam("$upload_status", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$upload_status", types.OptionalValue(types.TextValue(*video.UploadStatus)))
				}(),
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
				table.ValueParam("$public_share_token", types.NullValue(types.TypeText)),
				table.ValueParam("$share_expires_at", types.NullValue(types.TypeTimestamp)),
				table.ValueParam("$uploaded_at", types.NullValue(types.TypeTimestamp)),
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
				named.Optional("column0", &usage),
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
		SELECT video_id, org_id, file_name, file_size_bytes, storage_path, share_expires_at
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
			err := res.ScanNamed(
				named.Required("video_id", &v.VideoID),
				named.Required("org_id", &v.OrgID),
				named.Optional("file_name", &v.FileName),
				named.Optional("file_size_bytes", &v.FileSizeBytes),
				named.Optional("storage_path", &v.StoragePath),
				named.Optional("share_expires_at", &v.ShareExpiresAt),
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
		return nil, fmt.Errorf("video not found")
	}

	return &v, nil
}

// SearchVideos ищет видео с пагинацией
func (c *YDBClient) SearchVideos(ctx context.Context, orgID, userID, query string, limit, offset int) ([]*Video, int64, error) {
	baseQuery := `FROM videos WHERE org_id = $org_id AND is_deleted = false`
	args := []types.Value{
		types.TextValue(orgID),
	}

	if userID != "" {
		baseQuery += ` AND uploaded_by = $user_id`
		args = append(args, types.TextValue(userID))
	}

	if query != "" {
		baseQuery += ` AND file_name_search LIKE $query`
		args = append(args, types.TextValue("%"+strings.ToLower(query)+"%"))
	}

	// Count total
	countQuery := `SELECT COUNT(*) ` + baseQuery
	var total int64

	err := c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), countQuery,
			table.NewQueryParameters(
				table.ValueParam("$org_id", args[0]),
				func() table.ParameterOption {
					if len(args) > 1 {
						return table.ValueParam("$user_id", args[1])
					}
					return table.ValueParam("$user_id", types.NullValue(types.TypeText))
				}(),
				func() table.ParameterOption {
					if len(args) > 2 {
						return table.ValueParam("$query", args[2])
					}
					return table.ValueParam("$query", types.NullValue(types.TypeText))
				}(),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		if res.NextResultSet(ctx) && res.NextRow() {
			err := res.ScanNamed(
				named.Optional("column0", &total),
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

	// Get data
	dataQuery := `SELECT video_id, org_id, uploaded_by, file_name, file_size_bytes, storage_path, duration_seconds, upload_status, uploaded_at ` + baseQuery + ` ORDER BY uploaded_at DESC LIMIT $limit OFFSET $offset`
	args = append(args, types.Int64Value(int64(limit)), types.Int64Value(int64(offset)))

	var videos []*Video

	err = c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, res, err := session.Execute(ctx, table.DefaultTxControl(), dataQuery,
			table.NewQueryParameters(
				table.ValueParam("$org_id", args[0]),
				func() table.ParameterOption {
					if len(args) > 1 {
						return table.ValueParam("$user_id", args[1])
					}
					return table.ValueParam("$user_id", types.NullValue(types.TypeText))
				}(),
				func() table.ParameterOption {
					if len(args) > 2 {
						return table.ValueParam("$query", args[2])
					}
					return table.ValueParam("$query", types.NullValue(types.TypeText))
				}(),
				table.ValueParam("$limit", args[len(args)-2]),
				table.ValueParam("$offset", args[len(args)-1]),
			),
		)
		if err != nil {
			return err
		}
		defer res.Close()

		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var v Video
				if err := res.ScanNamed(
					named.Required("video_id", &v.VideoID),
					named.Required("org_id", &v.OrgID),
					named.Required("uploaded_by", &v.UploadedBy),
					named.Optional("file_name", &v.FileName),
					named.Optional("file_size_bytes", &v.FileSizeBytes),
					named.Optional("storage_path", &v.StoragePath),
					named.Optional("duration_seconds", &v.DurationSeconds),
					named.Optional("upload_status", &v.UploadStatus),
					named.Optional("uploaded_at", &v.UploadedAt),
				); err != nil {
					return fmt.Errorf("scan failed: %w", err)
				}
				videos = append(videos, &v)
			}
		}
		return res.Err()
	})

	if err != nil {
		return nil, 0, err
	}

	return videos, total, nil
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
				named.Optional("name", &org.Name),
				named.Optional("owner_id", &org.OwnerID),
				named.Optional("settings", &org.Settings),
				named.OptionalWithDefault("created_at", &org.CreatedAt),
				named.OptionalWithDefault("updated_at", &org.UpdatedAt),
			)

			if err != nil {
				log.Println("Error in loop ", err)
				return fmt.Errorf("scan failed: %w", err)
			}
		}
		// TODO: Remove this log
		log.Println("Debug in loop ", org.OrgID, org.Name, org.OwnerID, org.Settings, org.CreatedAt, org.UpdatedAt)

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
					named.Optional("name", &org.Name),
					named.Optional("owner_id", &org.OwnerID),
					named.OptionalWithDefault("settings", &org.Settings),
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
		DECLARE $name AS Optional<Text>;
		DECLARE $owner_id AS Optional<Text>;
		DECLARE $settings AS Json;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO organizations (org_id, name, owner_id, settings, created_at, updated_at)
		VALUES ($org_id, $name, $owner_id, $settings, $created_at, $updated_at)
	`

	org.UpdatedAt = time.Now()

	// Settings is already a JSON string, use it directly or default to empty object
	var settingsJSON string
	if org.Settings != nil && *org.Settings != "" {
		settingsJSON = *org.Settings
	} else {
		settingsJSON = "{}"
	}

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$org_id", types.TextValue(org.OrgID)),
				func() table.ParameterOption {
					if org.Name == nil {
						return table.ValueParam("$name", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$name", types.OptionalValue(types.TextValue(*org.Name)))
				}(),
				func() table.ParameterOption {
					if org.OwnerID == nil {
						return table.ValueParam("$owner_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$owner_id", types.OptionalValue(types.TextValue(*org.OwnerID)))
				}(),
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
					named.Optional("role", &membership.Role),
					named.Optional("status", &membership.Status),
					named.Optional("invited_by", &membership.InvitedBy),
					named.OptionalWithDefault("created_at", &membership.CreatedAt),
					named.OptionalWithDefault("updated_at", &membership.UpdatedAt),
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
					named.Optional("role", &membership.Role),
					named.Optional("status", &membership.Status),
					named.Optional("invited_by", &membership.InvitedBy),
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
		DECLARE $role AS Optional<Text>;
		DECLARE $status AS Optional<Text>;
		DECLARE $invited_by AS Optional<Text>;
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
				func() table.ParameterOption {
					if membership.Role == nil {
						return table.ValueParam("$role", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$role", types.OptionalValue(types.TextValue(*membership.Role)))
				}(),
				func() table.ParameterOption {
					if membership.Status == nil {
						return table.ValueParam("$status", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$status", types.OptionalValue(types.TextValue(*membership.Status)))
				}(),
				func() table.ParameterOption {
					if membership.InvitedBy == nil {
						return table.ValueParam("$invited_by", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$invited_by", types.OptionalValue(types.TextValue(*membership.InvitedBy)))
				}(),
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
		SELECT plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at
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
					named.Required("storage_limit_gb", &plan.StorageLimitGB),
					named.Required("video_count_limit", &plan.VideoCountLimit),
					named.Required("price_rub", &plan.PriceRub),
					named.Required("billing_cycle", &plan.BillingCycle),
					named.OptionalWithDefault("features", &plan.Features),

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
		SELECT subscription_id, user_id, org_id, plan_id, storage_limit_gb, video_count_limit,
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
				named.Required("storage_limit_gb", &subscription.StorageLimitGB),
				named.Required("video_count_limit", &subscription.VideoCountLimit),
				named.Required("is_active", &subscription.IsActive),
				named.Optional("trial_ends_at", &subscription.TrialEndsAt),
				named.Required("started_at", &subscription.StartedAt),
				named.Optional("expires_at", &subscription.ExpiresAt),
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
		SELECT subscription_id, user_id, org_id, plan_id, storage_limit_gb, video_count_limit,
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
				named.Required("storage_limit_gb", &subscription.StorageLimitGB),
				named.Required("video_count_limit", &subscription.VideoCountLimit),
				named.Required("is_active", &subscription.IsActive),
				named.Optional("trial_ends_at", &subscription.TrialEndsAt),
				named.Required("started_at", &subscription.StartedAt),
				named.Optional("expires_at", &subscription.ExpiresAt),
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
		DECLARE $storage_limit_gb AS Optional<Int64>;
		DECLARE $video_count_limit AS Optional<Int64>;
		DECLARE $is_active AS Optional<Bool>;
		DECLARE $trial_ends_at AS Optional<Timestamp>;
		DECLARE $started_at AS Timestamp;
		DECLARE $expires_at AS Optional<Timestamp>;
		DECLARE $billing_cycle AS Text;
		DECLARE $created_at AS Timestamp;
		DECLARE $updated_at AS Timestamp;

		REPLACE INTO subscriptions (
			subscription_id, user_id, org_id, plan_id, storage_limit_gb, video_count_limit,
			is_active, trial_ends_at, started_at, expires_at, billing_cycle, created_at, updated_at
		) VALUES ($subscription_id, $user_id, $org_id, $plan_id, $storage_limit_gb, $video_count_limit, $is_active, $trial_ends_at, $started_at, $expires_at, $billing_cycle, $created_at, $updated_at)
	`

	subscription.UpdatedAt = time.Now()

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$subscription_id", types.TextValue(subscription.SubscriptionID)),
				table.ValueParam("$user_id", types.TextValue(subscription.UserID)),
				table.ValueParam("$org_id", types.TextValue(subscription.OrgID)),
				table.ValueParam("$plan_id", types.TextValue(subscription.PlanID)),

				func() table.ParameterOption {
					if subscription.StorageLimitGB == nil {
						return table.ValueParam("$storage_limit_gb", types.NullValue(types.TypeInt64))
					}
					return table.ValueParam("$storage_limit_gb", types.OptionalValue(types.Int64Value(*subscription.StorageLimitGB)))
				}(),
				func() table.ParameterOption {
					if subscription.VideoCountLimit == nil {
						return table.ValueParam("$video_count_limit", types.NullValue(types.TypeInt64))
					}
					return table.ValueParam("$video_count_limit", types.OptionalValue(types.Int64Value(*subscription.VideoCountLimit)))
				}(),
				func() table.ParameterOption {
					if subscription.IsActive == nil {
						return table.ValueParam("$is_active", types.NullValue(types.TypeBool))
					}
					return table.ValueParam("$is_active", types.OptionalValue(types.BoolValue(*subscription.IsActive)))
				}(),
				func() table.ParameterOption {
					if subscription.TrialEndsAt.IsZero() {
						return table.ValueParam("$trial_ends_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$trial_ends_at", types.OptionalValue(types.TimestampValueFromTime(*subscription.TrialEndsAt)))
				}(),
				table.ValueParam("$started_at", types.TimestampValueFromTime(subscription.StartedAt)),
				func() table.ParameterOption {
					if subscription.ExpiresAt == nil || subscription.ExpiresAt.IsZero() {
						return table.ValueParam("$expires_at", types.NullValue(types.TypeTimestamp))
					}
					return table.ValueParam("$expires_at", types.OptionalValue(types.TimestampValueFromTime(*subscription.ExpiresAt)))
				}(),
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
		DECLARE $subscription_id AS Optional<Text>;
		DECLARE $plan_id AS Optional<Text>;
		DECLARE $storage_limit_gb AS Optional<Int64>;
		DECLARE $video_count_limit AS Optional<Int64>;
		DECLARE $event_type AS Optional<Text>;
		DECLARE $changed_at AS Timestamp;

		REPLACE INTO subscription_history (
			history_id, subscription_id, plan_id, storage_limit_gb, video_count_limit, event_type, changed_at
		) VALUES ($history_id, $subscription_id, $plan_id, $storage_limit_gb, $video_count_limit, $event_type, $changed_at)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$history_id", types.TextValue(historyID)),
				func() table.ParameterOption {
					if history.SubscriptionID == nil {
						return table.ValueParam("$subscription_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$subscription_id", types.OptionalValue(types.TextValue(*history.SubscriptionID)))
				}(),
				func() table.ParameterOption {
					if history.PlanID == nil {
						return table.ValueParam("$plan_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$plan_id", types.OptionalValue(types.TextValue(*history.PlanID)))
				}(),
				func() table.ParameterOption {
					if history.StorageLimitGB == nil {
						return table.ValueParam("$storage_limit_gb", types.NullValue(types.TypeInt64))
					}
					return table.ValueParam("$storage_limit_gb", types.OptionalValue(types.Int64Value(*history.StorageLimitGB)))
				}(),
				func() table.ParameterOption {
					if history.VideoCountLimit == nil {
						return table.ValueParam("$video_count_limit", types.NullValue(types.TypeInt64))
					}
					return table.ValueParam("$video_count_limit", types.OptionalValue(types.Int64Value(*history.VideoCountLimit)))
				}(),
				func() table.ParameterOption {
					if history.EventType == nil {
						return table.ValueParam("$event_type", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$event_type", types.OptionalValue(types.TextValue(*history.EventType)))
				}(),
				table.ValueParam("$changed_at", types.TimestampValueFromTime(history.ChangedAt)),
			),
		)
		return err
	})
}

func (c *YDBClient) GetSubscriptionHistory(ctx context.Context, subscriptionID string) ([]*SubscriptionHistory, error) {
	query := `
		DECLARE $subscription_id AS Text;
		SELECT history_id, subscription_id, plan_id, storage_limit_gb, video_count_limit, event_type, changed_at
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
					named.Required("storage_limit_gb", &history.StorageLimitGB),
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
					named.Optional("postbox_message_id", &log.PostboxMessageID),
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
		DECLARE $email_type AS Optional<Text>;
		DECLARE $recipient AS Optional<Text>;
		DECLARE $status AS Optional<Text>;
		DECLARE $postbox_message_id AS Optional<Text>;
		DECLARE $sent_at AS Timestamp;
		DECLARE $delivered_at AS Optional<Timestamp>;
		DECLARE $error_message AS Optional<Text>;

		REPLACE INTO email_logs (
			email_id, user_id, email_type, recipient, status, postbox_message_id, sent_at, delivered_at, error_message
		) VALUES ($email_id, $user_id, $email_type, $recipient, $status, $postbox_message_id, $sent_at, $delivered_at, $error_message)
	`

	return c.driver.Table().Do(ctx, func(ctx context.Context, session table.Session) error {
		_, _, err := session.Execute(ctx, table.DefaultTxControl(), query,
			table.NewQueryParameters(
				table.ValueParam("$email_id", types.TextValue(log.EmailID)),
				table.ValueParam("$user_id", types.TextValue(log.UserID)),
				func() table.ParameterOption {
					if log.EmailType == nil {
						return table.ValueParam("$email_type", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$email_type", types.OptionalValue(types.TextValue(*log.EmailType)))
				}(),
				func() table.ParameterOption {
					if log.Recipient == nil {
						return table.ValueParam("$recipient", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$recipient", types.OptionalValue(types.TextValue(*log.Recipient)))
				}(),
				func() table.ParameterOption {
					if log.Status == nil {
						return table.ValueParam("$status", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$status", types.OptionalValue(types.TextValue(*log.Status)))
				}(),
				func() table.ParameterOption {
					if log.PostboxMessageID == nil {
						return table.ValueParam("$postbox_message_id", types.NullValue(types.TypeText))
					}
					return table.ValueParam("$postbox_message_id", types.OptionalValue(types.TextValue(*log.PostboxMessageID)))
				}(),
				table.ValueParam("$sent_at", types.TimestampValueFromTime(log.SentAt)),
				table.ValueParam("$delivered_at", types.NullValue(types.TypeTimestamp)),
				table.ValueParam("$error_message", types.NullValue(types.TypeText)),
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
					named.Optional("expires_at", &token.ExpiresAt),
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
