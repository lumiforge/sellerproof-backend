
CREATE TABLE memberships (
membership_id String,
user_id String,
org_id String,
role String,
status String,
invited_by String,
created_at Timestamp,
updated_at Timestamp,
PRIMARY KEY (membership_id),
INDEX user_idx GLOBAL ON (user_id),
INDEX org_idx GLOBAL ON (org_id),
INDEX user_org_idx GLOBAL ON (user_id, org_id)
);


CREATE TABLE plans (
plan_id String,
name String,
storage_limit_gb Int64,
video_count_limit Int64,
price_rub Double,
billing_cycle String,
features Json,
created_at Timestamp,
updated_at Timestamp,
PRIMARY KEY (plan_id)
);

CREATE TABLE subscriptions (
subscription_id String,
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
PRIMARY KEY (subscription_id),
INDEX user_idx GLOBAL ON (user_id),
INDEX org_idx GLOBAL ON (org_id)
);

CREATE TABLE subscription_history (
history_id String,
subscription_id String,
plan_id String,
storage_limit_gb Int64,
video_count_limit Int64,
event_type String,
changed_at Timestamp,
PRIMARY KEY (history_id),
INDEX subscription_idx GLOBAL ON (subscription_id)
);

CREATE TABLE email_logs (
email_id String,
user_id String,
email_type String,
recipient String,
status String,
postbox_message_id String,
sent_at Timestamp,
delivered_at Timestamp,
error_message String,
PRIMARY KEY (email_id),
INDEX user_idx GLOBAL ON (user_id)
);

CREATE TABLE refresh_tokens (
token_id String,
user_id String,
token_hash String,
expires_at Timestamp,
created_at Timestamp,
is_revoked Bool DEFAULT false,
PRIMARY KEY (token_id),
INDEX user_idx GLOBAL ON (user_id),
INDEX token_hash_idx GLOBAL ON (token_hash)
);

INSERT INTO plans (plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at) VALUES
("free", "Free", 1, 10, 0, "monthly", '{"sharing": false, "search": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp());

INSERT INTO plans (plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at) VALUES
("pro", "Pro", 100, 1000, 990, "monthly", '{"sharing": true, "search": true, "analytics": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp());


INSERT INTO plans (plan_id, name, storage_limit_gb, video_count_limit, price_rub, billing_cycle, features, created_at, updated_at) VALUES
("enterprise", "Enterprise", 0, 0, 4990, "monthly", '{"sharing": true, "search": true, "analytics": true, "api_access": true, "priority_support": true}', CurrentUtcTimestamp(), CurrentUtcTimestamp());

