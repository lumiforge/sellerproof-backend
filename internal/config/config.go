package config

import (
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// S3/Storage configuration
	S3Endpoint           string
	AWSAccessKeyID       string
	AWSSecretAccessKey   string
	SPObjStoreBucketName string

	// YDB configuration
	SPYDBEndpoint     string
	SPYDBDatabasePath string

	// Telegram configuration
	TelegramBotToken    string
	TelegramAdminChatID string

	// JWT configuration
	JWTSecretKey string

	// Email/Postbox configuration
	SESEndpoint           string
	SESRegion             string
	SESAccessKeyID        string
	SESSecretAccessKey    string
	EmailFrom             string
	AppLoginURL           string
	SPYDBAutoCreateTables int

	// HTTP configuration
	HTTPPort string
}

func Load() *Config {
	// if err := godotenv.Load(); err != nil {
	// 	log.Println("No .env file found, using environment variables")
	// }

	// S3/Storage configuration
	s3Endpoint := getEnv("S3_ENDPOINT", "https://storage.yandexcloud.net")
	// If the env var is set but is an empty string, it will override the default.
	// We must fall back to the default in that case to prevent errors.
	if s3Endpoint == "" {
		s3Endpoint = "https://storage.yandexcloud.net"
	}
	if !strings.HasPrefix(s3Endpoint, "http://") && !strings.HasPrefix(s3Endpoint, "https://") {
		s3Endpoint = "https://" + s3Endpoint
		log.Printf("WARN: S3_ENDPOINT was missing a protocol scheme. Prepending 'https://'. New endpoint: %s", s3Endpoint)
	}

	return &Config{
		// S3/Storage configuration
		SPYDBAutoCreateTables: getEnvInt("SP_YDB_AUTO_CREATE_TABLES", 0, 0, 1),
		S3Endpoint:            s3Endpoint,
		AWSAccessKeyID:        getEnv("SP_SA_KEY_ID", ""),
		AWSSecretAccessKey:    getEnv("SP_SA_KEY", ""),
		SPObjStoreBucketName:  getEnv("SP_OBJSTORE_BUCKET_NAME", ""),

		// YDB configuration
		SPYDBEndpoint:     getEnv("SP_YDB_ENDPOINT", ""),
		SPYDBDatabasePath: getEnv("SP_YDB_DATABASE_PATH", ""),

		// Telegram configuration
		TelegramBotToken:    getEnv("TELEGRAM_BOT_TOKEN", ""),
		TelegramAdminChatID: getEnv("TELEGRAM_CHAT_ID", ""),

		// JWT configuration
		JWTSecretKey: getEnv("SP_JWT_SECRET_KEY", "default-secret-key-change-in-production"),

		// Email/Postbox configuration
		SESEndpoint:        getEnv("SP_POSTBOX_ENDPOINT", ""),
		SESRegion:          getEnv("SP_POSTBOX_REGION", ""),
		SESAccessKeyID:     getEnv("SP_POSTBOX_ACCESS_KEY_ID", ""),
		SESSecretAccessKey: getEnv("SP_POSTBOX_SECRET_ACCESS_KEY", ""),
		EmailFrom:          getEnv("SP_EMAIL_FROM", ""),
		AppLoginURL:        getEnv("SP_APP_LOGIN_URL", ""),

		// HTTP configuration
		HTTPPort: getEnv("SP_HTTP_PORT", "8080"),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	if fallback == "" {
		log.Fatalf("FATAL: Environment variable %s is not set.", key)
	}
	return fallback
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvInt(key string, fallback, min, max int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			if n < min {
				return min
			}
			if n > max {
				return max
			}
			return n
		}
		log.Printf("WARN: %s=%q is not an integer, using default %d", key, v, fallback)
	}

	if fallback < min {
		return min
	}
	if fallback > max {
		return max
	}
	return fallback
}
