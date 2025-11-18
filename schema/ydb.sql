CREATE TABLE users (
    user_id String,           
    email String,             
    password_hash String,     
    email_verified Bool,      -- NEW: статус верификации
    verification_code String, -- NEW: код верификации
    verification_expires_at Timestamp, -- NEW: истекает через 24ч
    created_at Timestamp,
    updated_at Timestamp,
    is_active Bool,           
    PRIMARY KEY (user_id),
    INDEX email_idx GLOBAL ON (email)
);


CREATE TABLE videos (
    video_id String,          
    org_id String,            
    uploaded_by String,       
    file_name String,
    file_name_search String,  -- NEW: lowercase для поиска
    file_size_bytes Int64,
    storage_path String,      
    storage_class String,     
    duration_seconds Int32,   
    upload_id String,         -- NEW: для multipart upload
    upload_status String,     -- NEW: "pending", "uploading", "completed", "failed"
    parts_uploaded Int32,     -- NEW: количество загруженных частей
    total_parts Int32,        -- NEW: общее количество частей
    public_share_token String, -- NEW: токен для публичных ссылок
    share_expires_at Timestamp, -- NEW: срок действия ссылки (nullable)
    uploaded_at Timestamp,
    moved_to_archive_at Timestamp,
    is_deleted Bool,          
    PRIMARY KEY (video_id),
    INDEX org_idx GLOBAL ON (org_id, uploaded_at),
    INDEX uploader_idx GLOBAL ON (uploaded_by),
    INDEX search_idx GLOBAL ON (org_id, file_name_search), -- NEW: для поиска
    INDEX share_token_idx GLOBAL ON (public_share_token) -- NEW: для публичного доступа
);


CREATE TABLE email_logs (
    email_id String,          -- UUID
    user_id String,           -- FK to users
    email_type String,        -- "verification", "password_reset", "subscription"
    recipient String,         -- email адрес
    status String,            -- "sent", "delivered", "bounced", "failed"
    postbox_message_id String, -- ID из Postbox
    sent_at Timestamp,
    delivered_at Timestamp,
    error_message String,
    PRIMARY KEY (email_id),
    INDEX user_idx GLOBAL ON (user_id)
);


