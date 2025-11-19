-- Таблица пользователей
CREATE TABLE users (
	user_id Text,
	email Text,
	password_hash Text,
	full_name Text,
	email_verified Bool DEFAULT false,
	verification_code Text,
	verification_expires_at Timestamp,
	verification_expires_at Timestamp,
	created_at Timestamp,
	updated_at Timestamp,
	is_active Bool DEFAULT true,
	PRIMARY KEY (user_id),
	INDEX email_idx GLOBAL UNIQUE ON (email) COVER (user_id, password_hash, full_name, email_verified, is_active)
);

-- Таблица организаций
CREATE TABLE organizations (
	org_id Text,
	name Text,
	owner_id Text,
	settings Json,
	settings Json,
	created_at Timestamp,
	updated_at Timestamp,
	PRIMARY KEY (org_id),
	INDEX owner_idx GLOBAL ON (owner_id)
);

-- Таблица членства
CREATE TABLE memberships (
	membership_id Text,
	user_id Text,
	org_id Text,
	role Text,
	status Text,
	invited_by Text,
	created_at Timestamp,
	updated_at Timestamp,
	PRIMARY KEY (membership_id),
	INDEX user_idx GLOBAL ON (user_id),
	INDEX org_idx GLOBAL ON (org_id),
	INDEX user_org_idx GLOBAL ON (user_id, org_id)
);

-- Таблица refresh токенов
CREATE TABLE refresh_tokens (
	token_id Text,
	user_id Text,
	token_hash Text,
	expires_at Timestamp,
	expires_at Timestamp,
	created_at Timestamp,
	is_revoked Bool DEFAULT false,
	PRIMARY KEY (token_id),
	INDEX user_idx GLOBAL ON (user_id),
	INDEX token_hash_idx GLOBAL ON (token_hash)
);

-- Таблица email логов
CREATE TABLE email_logs (
	email_id Text,
	user_id Text,
	email_type Text,
	recipient Text,
	status Text,
	postbox_message_id Text,
	postbox_message_id Text,
	sent_at Timestamp,
	delivered_at Timestamp,
	error_message Text,
	PRIMARY KEY (email_id),
	INDEX user_idx GLOBAL ON (user_id)
);

-- Таблица тарифных планов
CREATE TABLE plans (
	plan_id Text,
	name Text,
	storage_limit_gb Int64,
	video_count_limit Int64,
	price_rub Double,
	billing_cycle Text,
	features Json,
	features Json,
	created_at Timestamp,
	updated_at Timestamp,
	PRIMARY KEY (plan_id)
);

-- Вставляем базовые тарифные планы
INSERT INTO plans (plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at) VALUES
("free", "Free", 1, 10, 0, "monthly", '{"sharing": false, "search": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp());

INSERT INTO plans (plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at) VALUES
("pro", "Pro", 100, 1000, 990, "monthly", '{"sharing": true, "search": true, "analytics": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp());

INSERT INTO plans (plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at) VALUES
("enterprise", "Enterprise", 0, 0, 4990, "monthly", '{"sharing": true, "search": true, "analytics": true, "api_access": true, "priority_support": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp());

-- Таблица подписок
CREATE TABLE subscriptions (
	subscription_id Text,
	user_id Text,
	org_id Text,
	plan_id Text,
	storage_limit_gb Int64,
	video_count_limit Int64,
	is_active Bool DEFAULT true,
	trial_ends_at Timestamp,
	trial_ends_at Timestamp,
	started_at Timestamp,
	expires_at Timestamp,
	billing_cycle Text,
	created_at Timestamp,
	updated_at Timestamp,
	PRIMARY KEY (subscription_id),
	INDEX user_idx GLOBAL ON (user_id),
	INDEX org_idx GLOBAL ON (org_id)
);

-- Таблица видео
CREATE TABLE videos (
	video_id Text,
	org_id Text,
	uploaded_by Text,
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
	share_expires_at Timestamp,
	uploaded_at Timestamp,
	share_expires_at Timestamp,
	uploaded_at Timestamp,
	created_at Timestamp,
	is_deleted Bool DEFAULT false,
	PRIMARY KEY (video_id),
	INDEX org_idx GLOBAL ON (org_id),
	INDEX org_user_idx GLOBAL ON (org_id, uploaded_by),
	INDEX org_deleted_idx GLOBAL ON (org_id, is_deleted),
	INDEX share_token_idx GLOBAL ON (public_share_token)
);

-- Таблица истории подписок
CREATE TABLE subscription_history (
	history_id Text,
	subscription_id Text,
	plan_id Text,
	storage_limit_gb Int64,
	video_count_limit Int64,
	event_type Text,
	changed_at Timestamp,
	PRIMARY KEY (history_id),
	INDEX subscription_idx GLOBAL ON (subscription_id)
);
