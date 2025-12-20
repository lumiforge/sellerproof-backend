package config

import (
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// S3/Storage configuration
	S3Endpoint               string
	AWSAccessKeyID           string
	AWSSecretAccessKey       string
	SPObjStoreBucketStart    string
	SPObjStoreBucketPro      string
	SPObjStoreBucketBusiness string

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
	VideoLimitMBStart           int64
	VideoLimitMBPro             int64
	VideoLimitMBBusiness        int64
	OrdersPerMonthLimitStart    int64
	OrdersPerMonthLimitPro      int64
	OrdersPerMonthLimitBusiness int64
	PriceRubStart               float64
	PriceRubPro                 float64
	PriceRubBusiness            float64

	RecommendedPartSizeMB int32
	MaxVideoFileSizeMB    int64
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
		SPYDBAutoCreateTables:    getEnvInt("SP_YDB_AUTO_CREATE_TABLES", 0, 0, 1),
		S3Endpoint:               s3Endpoint,
		AWSAccessKeyID:           getEnv("SP_SA_KEY_ID", ""),
		AWSSecretAccessKey:       getEnv("SP_SA_KEY", ""),
		SPObjStoreBucketStart:    getEnv("SP_OBJSTORE_BUCKET_START", "sub12-ice"),
		SPObjStoreBucketPro:      getEnv("SP_OBJSTORE_BUCKET_PRO", "sub24-ice"),
		SPObjStoreBucketBusiness: getEnv("SP_OBJSTORE_BUCKET_BUSINESS", "sub36-ice"),

		// YDB configuration
		SPYDBEndpoint:     getEnv("SP_YDB_ENDPOINT", ""),
		SPYDBDatabasePath: getEnv("SP_YDB_DATABASE_PATH", ""),

		// Telegram configuration
		TelegramBotToken:    getEnv("TELEGRAM_BOT_TOKEN", ""),
		TelegramAdminChatID: getEnv("TELEGRAM_CHAT_ID", ""),

		// JWT configuration
		JWTSecretKey: getEnv("SP_JWT_SECRET_KEY", ""),

		// Email/Postbox configuration
		SESEndpoint:        getEnv("SP_POSTBOX_ENDPOINT", ""),
		SESRegion:          getEnv("SP_POSTBOX_REGION", ""),
		SESAccessKeyID:     getEnv("SP_POSTBOX_ACCESS_KEY_ID", ""),
		SESSecretAccessKey: getEnv("SP_POSTBOX_SECRET_ACCESS_KEY", ""),
		EmailFrom:          getEnv("SP_EMAIL_FROM", ""),
		AppLoginURL:        getEnv("SP_APP_LOGIN_URL", ""),
		APIBaseURL:         getEnv("SP_API_BASE_URL", "https://api.sellerproof.ru"),

		// Plan configuration
		VideoLimitMBStart:           int64(getEnvInt("video_limit_mb_start", 614400, 0, 10000000)),     // 600 GB
		VideoLimitMBPro:             int64(getEnvInt("video_limit_mb_pro", 2048000, 0, 10000000)),      // 2000 GB
		VideoLimitMBBusiness:        int64(getEnvInt("video_limit_mb_business", 6144000, 0, 10000000)), // 6000 GB
		OrdersPerMonthLimitStart:    int64(getEnvInt("orders_per_month_limit_start", 300, 0, 10000)),
		OrdersPerMonthLimitPro:      int64(getEnvInt("orders_per_month_limit_pro", 1000, 0, 10000)),
		OrdersPerMonthLimitBusiness: int64(getEnvInt("orders_per_month_limit_business", 3000, 0, 10000)),
		PriceRubStart:               float64(getEnvInt("price_rub_start", 1490, 0, 10000)),
		PriceRubPro:                 float64(getEnvInt("price_rub_pro", 3490, 0, 10000)),
		PriceRubBusiness:            float64(getEnvInt("price_rub_business", 6990, 0, 10000)),

		RecommendedPartSizeMB: int32(getEnvInt("recommended_part_size_mb", 200, 1, 1000)),
		MaxVideoFileSizeMB:    int64(getEnvInt("max_video_file_size_mb", 2000, 1, 100000)),
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
