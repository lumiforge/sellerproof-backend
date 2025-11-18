-- Таблица пользователей
CREATE TABLE users (
    user_id String PRIMARY KEY,
    email String,
    password_hash String,
    full_name String,
    email_verified Bool DEFAULT false,
    verification_code String,
    verification_expires_at Timestamp,
    created_at Timestamp,
    updated_at Timestamp,
    is_active Bool DEFAULT true,
    INDEX email_idx GLOBAL ON (email)
);

-- Таблица организаций
CREATE TABLE organizations (
    org_id String PRIMARY KEY,
    name String,
    owner_id String,
    settings Json,
    created_at Timestamp,
    updated_at Timestamp,
    INDEX owner_idx GLOBAL ON (owner_id)
);

-- Таблица членства в организациях
CREATE TABLE memberships (
    membership_id String PRIMARY KEY,
    user_id String,
    org_id String,
    role String, -- "admin", "manager", "user"
    status String, -- "active", "invited", "declined"
    invited_by String,
    created_at Timestamp,
    updated_at Timestamp,
    INDEX user_idx GLOBAL ON (user_id),
    INDEX org_idx GLOBAL ON (org_id),
    INDEX user_org_idx GLOBAL ON (user_id, org_id)
);

-- Таблица тарифных планов
CREATE TABLE plans (
    plan_id String PRIMARY KEY,
    name String,
    storage_limit_gb Int64,
    video_count_limit Int64,
    price_rub Double,
    billing_cycle String, -- "monthly", "yearly"
    features Json,
    created_at Timestamp,
    updated_at Timestamp
);

-- Таблица подписок
CREATE TABLE subscriptions (
    subscription_id String PRIMARY KEY,
    user_id String,
    org_id String,
    plan_id String,
    storage_limit_gb Int64,
    video_count_limit Int64,
    is_active Bool DEFAULT true,
    trial_ends_at Timestamp,
    started_at Timestamp,
    expires_at Timestamp,
    billing_cycle String,
    created_at Timestamp,
    updated_at Timestamp,
    INDEX user_idx GLOBAL ON (user_id),
    INDEX org_idx GLOBAL ON (org_id)
);

-- Таблица истории подписок
CREATE TABLE subscription_history (
    history_id String PRIMARY KEY,
    subscription_id String,
    plan_id String,
    storage_limit_gb Int64,
    video_count_limit Int64,
    event_type String, -- "created", "upgraded", "downgraded", "canceled"
    changed_at Timestamp,
    INDEX subscription_idx GLOBAL ON (subscription_id)
);

-- Таблица логов email
CREATE TABLE email_logs (
    email_id String PRIMARY KEY,
    user_id String,
    email_type String, -- "verification", "password_reset", "subscription"
    recipient String,
    status String, -- "sent", "delivered", "bounced", "failed"
    postbox_message_id String,
    sent_at Timestamp,
    delivered_at Timestamp,
    error_message String,
    INDEX user_idx GLOBAL ON (user_id)
);

-- Таблица refresh токенов
CREATE TABLE refresh_tokens (
    token_id String PRIMARY KEY,
    user_id String,
    token_hash String,
    expires_at Timestamp,
    created_at Timestamp,
    is_revoked Bool DEFAULT false,
    INDEX user_idx GLOBAL ON (user_id),
    INDEX token_hash_idx GLOBAL ON (token_hash)
);

-- Вставка базовых тарифных планов
INSERT INTO plans (plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at) VALUES
    ("free", "Free", 1, 10, 0, "monthly", {"sharing": false, "search": true}, CurrentUtcTimestamp(), CurrentUtcTimestamp()),
    ("pro", "Pro", 100, 1000, 990, "monthly", {"sharing": true, "search": true, "analytics": true}, CurrentUtcTimestamp(), CurrentUtcTimestamp()),
    ("enterprise", "Enterprise", 0, 0, 4990, "monthly", {"sharing": true, "search": true, "analytics": true, "api_access": true, "priority_support": true}, CurrentUtcTimestamp(), CurrentUtcTimestamp());