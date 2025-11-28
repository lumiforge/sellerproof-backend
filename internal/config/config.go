package config

import (
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// S3/Storage configuration
	S3Endpoint              string
	AWSAccessKeyID          string
	AWSSecretAccessKey      string
	SPObjStorePrivateBucket string
	SPObjStorePublicBucket  string

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
	APIBaseURL            string
	SPYDBAutoCreateTables int

	// Plan configuration
	StorageLimitFree          int64
	StorageLimitPro           int64
	StorageLimitEnterprise    int64
	VideoCountLimitFree       int64
	VideoCountLimitPro        int64
	VideoCountLimitEnterprise int64
	PriceRubFree              float64
	PriceRubPro               float64
	PriceRubEnterprise        float64

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
		SPYDBAutoCreateTables:   getEnvInt("SP_YDB_AUTO_CREATE_TABLES", 0, 0, 1),
		S3Endpoint:              s3Endpoint,
		AWSAccessKeyID:          getEnv("SP_SA_KEY_ID", ""),
		AWSSecretAccessKey:      getEnv("SP_SA_KEY", ""),
		SPObjStorePrivateBucket: getEnv("SP_OBJSTORE_PRIVATE_BUCKET", "sellerproof-private"),
		SPObjStorePublicBucket:  getEnv("SP_OBJSTORE_PUBLIC_BUCKET", "sellerproof-public"),

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
		APIBaseURL:         getEnv("SP_API_BASE_URL", "https://api.sellerproof.ru"),

		// Plan configuration
		StorageLimitFree:          int64(getEnvInt("storage_limit_free", 1024, 0, 0)),
		StorageLimitPro:           int64(getEnvInt("storage_limit_pro", 102400, 0, 0)),
		StorageLimitEnterprise:    int64(getEnvInt("storage_limit_enterprise", 1024000, 0, 0)),
		VideoCountLimitFree:       int64(getEnvInt("video_count_limit_free", 10, 0, 0)),
		VideoCountLimitPro:        int64(getEnvInt("video_count_limit_pro", 1000, 0, 0)),
		VideoCountLimitEnterprise: int64(getEnvInt("video_count_limit_enterprise", 10000, 0, 0)),
		PriceRubFree:              float64(getEnvInt("price_rub_free", 0, 0, 0)),
		PriceRubPro:               float64(getEnvInt("price_rub_pro", 990, 0, 0)),
		PriceRubEnterprise:        float64(getEnvInt("price_rub_enterprise", 4990, 0, 0)),

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
