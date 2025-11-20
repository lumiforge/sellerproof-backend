ZIP := sellerproof-v4.zip
SHELL := /bin/bash
SP_FUNC_RUNTIME ?= golang123

# Function
export SP_SA
export SP_FUNC
export SP_ENTRY
# S3
export SP_OBJSTORE_BUCKET_NAME
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
	zip -r $(ZIP) . -x 'Makefile' 'README.md' 'patch.diff' 'tests/*' 'schema/*' '*/patch.diff' '.git/*' '*/.git/*' 'git/*' '*/git/*' '/bfe-sl'


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

REQUIRED_ENV := SP_SA SP_FUNC SP_ENTRY SP_YDB_ENDPOINT SP_YDB_DATABASE_PATH SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS SP_OBJSTORE_BUCKET_NAME SP_PRESIGN_TTL_SECONDS SP_SA_KEY_ID SP_SA_KEY SP_JWT_SECRET_KEY SP_POSTBOX_ENDPOINT SP_POSTBOX_REGION SP_SA_KEY_ID SP_SA_KEY SP_APP_LOGIN_URL SP_EMAIL_FROM TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID

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
ENV_ARGS_DEPLOY = "SP_YDB_AUTO_CREATE_TABLES=1,SP_SA=$$SP_SA,SP_FUNC=$$SP_FUNC,SP_ENTRY=$$SP_ENTRY,SP_YDB_ENDPOINT=$$SP_YDB_ENDPOINT,SP_YDB_DATABASE_PATH=$$SP_YDB_DATABASE_PATH,SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS=$$SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS,SP_OBJSTORE_BUCKET_NAME=$$SP_OBJSTORE_BUCKET_NAME,SP_PRESIGN_TTL_SECONDS=$$SP_PRESIGN_TTL_SECONDS,SP_SA_KEY_ID=$$SP_SA_KEY_ID,SP_SA_KEY=$$SP_SA_KEY,SP_JWT_SECRET_KEY=$$SP_JWT_SECRET_KEY,SP_POSTBOX_ENDPOINT=$$SP_POSTBOX_ENDPOINT,SP_POSTBOX_REGION=$$SP_POSTBOX_REGION,SP_POSTBOX_ACCESS_KEY_ID=$$SP_SA_KEY_ID,SP_POSTBOX_SECRET_ACCESS_KEY=$$SP_SA_KEY,SP_APP_LOGIN_URL=$$SP_APP_LOGIN_URL,SP_EMAIL_FROM=$$SP_EMAIL_FROM,TELEGRAM_BOT_TOKEN=$$TELEGRAM_BOT_TOKEN,TELEGRAM_CHAT_ID=$$TELEGRAM_CHAT_ID"

# Environment variables for redeploy (without table creation)
ENV_ARGS_REDEPLOY = "SP_YDB_AUTO_CREATE_TABLES=0,SP_SA=$$SP_SA,SP_FUNC=$$SP_FUNC,SP_ENTRY=$$SP_ENTRY,SP_YDB_ENDPOINT=$$SP_YDB_ENDPOINT,SP_YDB_DATABASE_PATH=$$SP_YDB_DATABASE_PATH,SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS=$$SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS,SP_OBJSTORE_BUCKET_NAME=$$SP_OBJSTORE_BUCKET_NAME,SP_PRESIGN_TTL_SECONDS=$$SP_PRESIGN_TTL_SECONDS,SP_SA_KEY_ID=$$SP_SA_KEY_ID,SP_SA_KEY=$$SP_SA_KEY,SP_JWT_SECRET_KEY=$$SP_JWT_SECRET_KEY,SP_POSTBOX_ENDPOINT=$$SP_POSTBOX_ENDPOINT,SP_POSTBOX_REGION=$$SP_POSTBOX_REGION,SP_POSTBOX_ACCESS_KEY_ID=$$SP_SA_KEY_ID,SP_POSTBOX_SECRET_ACCESS_KEY=$$SP_SA_KEY,SP_APP_LOGIN_URL=$$SP_APP_LOGIN_URL,SP_EMAIL_FROM=$$SP_EMAIL_FROM,TELEGRAM_BOT_TOKEN=$$TELEGRAM_BOT_TOKEN,TELEGRAM_CHAT_ID=$$TELEGRAM_CHAT_ID"

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
	  --service-account-id $(SP_SA) \
	  --entrypoint $(SP_ENTRY) \
	  --source-path ./$(ZIP) \
	  --execution-timeout $(SP_PRESIGN_TTL_FOR_ARCHIVE_SECONDS)s \
	  --environment $(ENV_ARGS_REDEPLOY)
	 