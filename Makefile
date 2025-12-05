ZIP := sellerproof-v4.zip
SHELL := /bin/bash
SP_FUNC_RUNTIME ?= golang123
storage_limit_free := 1024
storage_limit_pro := 102400
storage_limit_enterprise := 1024000
video_count_limit_free := 10
video_count_limit_pro := 1000
video_count_limit_enterprise := 10000
price_rub_free := 0
price_rub_pro := 990
price_rub_enterprise := 4990
# Function
export SP_SA
export SP_FUNC
export SP_ENTRY
# S3
export SP_OBJSTORE_PRIVATE_BUCKET
export SP_OBJSTORE_PUBLIC_BUCKET
export SP_SA_KEY_ID
export SP_SA_KEY
# YDB
export SP_YDB_ENDPOINT
export SP_YDB_DATABASE_PATH
# Telegram
export TELEGRAM_BOT_TOKEN
export TELEGRAM_CHAT_ID
# JWT
export SP_JWT_SECRET_KEY
# Email/Postbox
export SP_POSTBOX_ENDPOINT
export SP_POSTBOX_REGION
export SP_POSTBOX_ACCESS_KEY_ID
export SP_POSTBOX_SECRET_ACCESS_KEY
export SP_APP_LOGIN_URL
export SP_EMAIL_FROM

# Plan configuration
export storage_limit_free
export storage_limit_pro
export storage_limit_enterprise
export video_count_limit_free
export video_count_limit_pro
export video_count_limit_enterprise
export price_rub_free
export price_rub_pro
export price_rub_enterprise

# HTTP
export SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS
export SP_PRESIGN_TTL_SECONDS



git:
	@if [ -z "$(M)" ]; then echo 'ERROR: set MSG, e.g. make git MSG="feat: deploy function"'; exit 1; fi
	git add -A
	git commit -m "$(M)"
	git push origin main

build-zip:
	rm $(ZIP)
	zip -r $(ZIP) internal go.mod main.go -x 'internal/*/mocks/*'
	
test:
	go test -v ./...

# Development commands
run:
	go run main.go

build:
	go build -o sellerproof-backend main.go

clean:
	rm -f sellerproof-backend sellerproof.zip

test:
	go test -v ./...

deps:
	go mod tidy
	go mod download

# OpenAPI documentation commands
swag-init:
	@echo "Generating OpenAPI documentation..."
	swag init -g main.go -o docs

swag:
	@echo "Generating OpenAPI documentation..."
	swag init -g main.go -o docs --parseDependency --parseInternal

docs: swag
	@echo "OpenAPI documentation generated successfully!"
	@echo "Available at: http://localhost:8080/openapi.json"

# YDB specific commands
ydb-init:
	@echo "Initializing YDB tables..."
	yc ydb database create --name sellerproof-db || echo "Database may already exist"
	yc ydb table create --database sellerproof-db --name users || echo "Table may already exist"

# Docker commands (optional)
docker-build:
	docker build -t sellerproof-backend .

docker-run:
	docker run -p 8080:8080 --env-file .env sellerproof-backend

REQUIRED_ENV := SP_SA SP_FUNC SP_ENTRY SP_YDB_ENDPOINT SP_YDB_DATABASE_PATH SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS SP_OBJSTORE_PRIVATE_BUCKET SP_OBJSTORE_PUBLIC_BUCKET SP_PRESIGN_TTL_SECONDS SP_SA_KEY_ID SP_SA_KEY SP_JWT_SECRET_KEY SP_POSTBOX_ENDPOINT SP_POSTBOX_REGION SP_SA_KEY_ID SP_SA_KEY SP_APP_LOGIN_URL SP_EMAIL_FROM TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID

check-env:
	@for v in $(REQUIRED_ENV); do \
		val="$${!v}"; \
		if [ -z "$$val" ]; then echo "ERROR: $$v is empty"; exit 1; fi; \
		if printf "%s" "$$val" | LC_ALL=C grep -qP '[\x00-\x1F\x7F,]'; then \
			echo "ERROR: $$v contains newline/control/comma, sanitize it or use Lockbox"; exit 1; \
		fi; \
	done

# SP_YDB_AUTO_CREATE_TABLES
# Environment variables for deploy (with table creation)
ENV_ARGS_DEPLOY = "SP_YDB_AUTO_CREATE_TABLES=1,SP_SA=$$SP_SA,SP_FUNC=$$SP_FUNC,SP_ENTRY=$$SP_ENTRY,SP_YDB_ENDPOINT=$$SP_YDB_ENDPOINT,SP_YDB_DATABASE_PATH=$$SP_YDB_DATABASE_PATH,SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS=$$SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS,SP_OBJSTORE_PRIVATE_BUCKET=$$SP_OBJSTORE_PRIVATE_BUCKET,SP_OBJSTORE_PUBLIC_BUCKET=$$SP_OBJSTORE_PUBLIC_BUCKET,SP_PRESIGN_TTL_SECONDS=$$SP_PRESIGN_TTL_SECONDS,SP_SA_KEY_ID=$$SP_SA_KEY_ID,SP_SA_KEY=$$SP_SA_KEY,SP_JWT_SECRET_KEY=$$SP_JWT_SECRET_KEY,SP_POSTBOX_ENDPOINT=$$SP_POSTBOX_ENDPOINT,SP_POSTBOX_REGION=$$SP_POSTBOX_REGION,SP_POSTBOX_ACCESS_KEY_ID=$$SP_SA_KEY_ID,SP_POSTBOX_SECRET_ACCESS_KEY=$$SP_SA_KEY,SP_APP_LOGIN_URL=$$SP_APP_LOGIN_URL,SP_EMAIL_FROM=$$SP_EMAIL_FROM,TELEGRAM_BOT_TOKEN=$$TELEGRAM_BOT_TOKEN,TELEGRAM_CHAT_ID=$$TELEGRAM_CHAT_ID,storage_limit_free=$$storage_limit_free,storage_limit_pro=$$storage_limit_pro,storage_limit_enterprise=$$storage_limit_enterprise,video_count_limit_free=$$video_count_limit_free,video_count_limit_pro=$$video_count_limit_pro,video_count_limit_enterprise=$$video_count_limit_enterprise,price_rub_free=$$price_rub_free,price_rub_pro=$$price_rub_pro,price_rub_enterprise=$$price_rub_enterprise"

# Environment variables for redeploy (without table creation)
ENV_ARGS_REDEPLOY = "SP_YDB_AUTO_CREATE_TABLES=0,SP_SA=$$SP_SA,SP_FUNC=$$SP_FUNC,SP_ENTRY=$$SP_ENTRY,SP_YDB_ENDPOINT=$$SP_YDB_ENDPOINT,SP_YDB_DATABASE_PATH=$$SP_YDB_DATABASE_PATH,SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS=$$SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS,SP_OBJSTORE_PRIVATE_BUCKET=$$SP_OBJSTORE_PRIVATE_BUCKET,SP_OBJSTORE_PUBLIC_BUCKET=$$SP_OBJSTORE_PUBLIC_BUCKET,SP_PRESIGN_TTL_SECONDS=$$SP_PRESIGN_TTL_SECONDS,SP_SA_KEY_ID=$$SP_SA_KEY_ID,SP_SA_KEY=$$SP_SA_KEY,SP_JWT_SECRET_KEY=$$SP_JWT_SECRET_KEY,SP_POSTBOX_ENDPOINT=$$SP_POSTBOX_ENDPOINT,SP_POSTBOX_REGION=$$SP_POSTBOX_REGION,SP_POSTBOX_ACCESS_KEY_ID=$$SP_SA_KEY_ID,SP_POSTBOX_SECRET_ACCESS_KEY=$$SP_SA_KEY,SP_APP_LOGIN_URL=$$SP_APP_LOGIN_URL,SP_EMAIL_FROM=$$SP_EMAIL_FROM,TELEGRAM_BOT_TOKEN=$$TELEGRAM_BOT_TOKEN,TELEGRAM_CHAT_ID=$$TELEGRAM_CHAT_ID,storage_limit_free=$$storage_limit_free,storage_limit_pro=$$storage_limit_pro,storage_limit_enterprise=$$storage_limit_enterprise,video_count_limit_free=$$video_count_limit_free,video_count_limit_pro=$$video_count_limit_pro,video_count_limit_enterprise=$$video_count_limit_enterprise,price_rub_free=$$price_rub_free,price_rub_pro=$$price_rub_pro,price_rub_enterprise=$$price_rub_enterprise"

deploy: check-env build-zip
	yc serverless function version create \
	  --function-name $(SP_FUNC) \
	  --runtime $(SP_FUNC_RUNTIME) \
	  --service-account-id $(SP_SA) \
	  --entrypoint $(SP_ENTRY) \
	  --source-path ./$(ZIP) \
	  --execution-timeout $(SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS)s \
	  --environment $(ENV_ARGS_DEPLOY)

redeploy: check-env build-zip
	yc serverless function version create \
	  --function-name $(SP_FUNC) \
	  --runtime $(SP_FUNC_RUNTIME) \
	  --memory 256MB \
	  --service-account-id $(SP_SA) \
	  --entrypoint $(SP_ENTRY) \
	  --source-path ./$(ZIP) \
	  --execution-timeout $(SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS)s \
	  --environment $(ENV_ARGS_REDEPLOY)
	 