Да, ты абсолютно прав! Я именно это и предлагал в разделе "Архитектура загрузки/скачивания видео" — presigned URL для прямой загрузки в Object Storage без прохождения через Cloud Function. Твой код идеален для этого подхода. Обновлю архитектуру с учётом всех новых требований.[1][2]

***

## 🔄 Обновлённая архитектура SellerProof

### Новые требования
- ✅ Email верификация через Yandex Cloud Postbox
- ✅ Multipart upload для больших видео
- ✅ Полнотекстовый поиск по названиям
- ✅ Публичные ссылки для sharing

***

## 📊 Обновлённая схема YDB

### Новые/изменённые таблицы

#### **users** (обновлено)
```sql
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
```

#### **videos** (обновлено)
```sql
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
```

#### **email_logs** (новая таблица)
```sql
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
```

***

## 📧 Email верификация через Yandex Cloud Postbox

### Настройка Postbox

**1. Создание сервисного аккаунта**:[3]
```bash
yc iam service-account create --name postbox-sender

# Выдать права
yc postbox address add-access-binding <ADDRESS_ID> \
  --role postbox.sender \
  --service-account-id <SA_ID>
```

**2. Создание статического ключа**:[3]
```bash
yc iam access-key create --service-account-name postbox-sender
# Сохранить ACCESS_KEY_ID и SECRET_ACCESS_KEY
```

**3. Проверка домена (DNS записи)**:[4][3]
```
# TXT запись для DKIM
postbox._domainkey.sellerproof.ru. TXT "v=DKIM1;h=sha256;k=rsa;p=MIIBIj..."

# SPF запись
sellerproof.ru. TXT "v=spf1 include:_spf.yandex.net ~all"
```

### Код отправки email верификации

```go
package email

import (
    "fmt"
    "net/smtp"
    "os"
    "crypto/rand"
    "encoding/hex"
)

type PostboxClient struct {
    Host       string
    Port       string
    Username   string // ACCESS_KEY_ID
    Password   string // SECRET_ACCESS_KEY
    FromEmail  string
}

func NewPostboxClient() *PostboxClient {
    return &PostboxClient{
        Host:      "smtp.postbox.cloud.yandex.net",
        Port:      "587",
        Username:  os.Getenv("POSTBOX_ACCESS_KEY_ID"),
        Password:  os.Getenv("POSTBOX_SECRET_ACCESS_KEY"),
        FromEmail: "noreply@sellerproof.ru",
    }
}

func (p *PostboxClient) SendVerificationEmail(toEmail, verificationCode string) error {
    subject := "Подтвердите email - SellerProof"
    body := fmt.Sprintf(`
        <html>
        <body>
            <h2>Добро пожаловать в SellerProof!</h2>
            <p>Ваш код верификации: <strong>%s</strong></p>
            <p>Код действителен 24 часа.</p>
            <p>Если вы не регистрировались, проигнорируйте это письмо.</p>
        </body>
        </html>
    `, verificationCode)

    message := fmt.Sprintf("From: %s\r\n", p.FromEmail) +
        fmt.Sprintf("To: %s\r\n", toEmail) +
        fmt.Sprintf("Subject: %s\r\n", subject) +
        "MIME-version: 1.0;\r\n" +
        "Content-Type: text/html; charset=\"UTF-8\";\r\n\r\n" +
        body

    auth := smtp.PlainAuth("", p.Username, p.Password, p.Host)
    err := smtp.SendMail(
        p.Host+":"+p.Port,
        auth,
        p.FromEmail,
        []string{toEmail},
        []byte(message),
    )
    
    return err
}

func GenerateVerificationCode() (string, error) {
    bytes := make([]byte, 3) // 6 символов в hex
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}
```

### Обновлённый flow регистрации

```go
func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
    // 1. Проверить, что email не занят
    existingUser, _ := s.ydb.GetUserByEmail(ctx, req.Email)
    if existingUser != nil {
        return nil, status.Error(codes.AlreadyExists, "Email уже используется")
    }
    
    // 2. Создать пользователя (email_verified = false)
    userID := uuid.New().String()
    passwordHash := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    verificationCode, _ := email.GenerateVerificationCode()
    
    user := &User{
        UserID:           userID,
        Email:            req.Email,
        PasswordHash:     string(passwordHash),
        EmailVerified:    false,
        VerificationCode: verificationCode,
        VerificationExpiresAt: time.Now().Add(24 * time.Hour),
        CreatedAt:        time.Now(),
    }
    
    if err := s.ydb.CreateUser(ctx, user); err != nil {
        return nil, err
    }
    
    // 3. Отправить email верификации
    postboxClient := email.NewPostboxClient()
    if err := postboxClient.SendVerificationEmail(req.Email, verificationCode); err != nil {
        s.logger.Warn("Failed to send verification email", err)
        // Логируем в email_logs со статусом "failed"
    }
    
    // 4. Создать триальную подписку (free на 7 дней)
    subscription := &Subscription{
        SubscriptionID: uuid.New().String(),
        UserID:         userID,
        PlanType:       "free",
        StorageLimitGB: 1,
        TrialEndsAt:    time.Now().Add(7 * 24 * time.Hour),
        IsActive:       true,
        CreatedAt:      time.Now(),
    }
    s.ydb.CreateSubscription(ctx, subscription)
    
    return &pb.RegisterResponse{
        Message: "Регистрация успешна. Проверьте email для верификации.",
        UserID:  userID,
    }, nil
}

func (s *Server) VerifyEmail(ctx context.Context, req *pb.VerifyEmailRequest) (*pb.VerifyEmailResponse, error) {
    user, err := s.ydb.GetUserByEmail(ctx, req.Email)
    if err != nil {
        return nil, status.Error(codes.NotFound, "Пользователь не найден")
    }
    
    // Проверить код и срок действия
    if user.VerificationCode != req.Code {
        return nil, status.Error(codes.InvalidArgument, "Неверный код")
    }
    
    if time.Now().After(user.VerificationExpiresAt) {
        return nil, status.Error(codes.DeadlineExceeded, "Код истёк")
    }
    
    // Обновить статус
    user.EmailVerified = true
    user.VerificationCode = "" // очистить
    s.ydb.UpdateUser(ctx, user)
    
    return &pb.VerifyEmailResponse{
        Message: "Email успешно подтверждён",
    }, nil
}
```

***

## 📤 Multipart Upload с Presigned URLs

### Структура для multipart upload

```go
package storage

import (
    "context"
    "fmt"
    "time"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/aws/aws-sdk-go-v2/aws"
)

type MultipartUpload struct {
    UploadID   string
    PartURLs   []string
    TotalParts int
}

// Шаг 1: Инициализация multipart upload
func (c *S3Client) InitiateMultipartUpload(objectKey string) (string, error) {
    input := &s3.CreateMultipartUploadInput{
        Bucket:      &c.BucketName,
        Key:         &objectKey,
        ContentType: aws.String("video/mp4"),
    }
    
    result, err := c.Client.CreateMultipartUpload(context.TODO(), input)
    if err != nil {
        return "", err
    }
    
    return *result.UploadId, nil
}

// Шаг 2: Генерация presigned URLs для каждой части
func (c *S3Client) GenerateMultipartPresignedURLs(objectKey, uploadID string, totalParts int) ([]string, error) {
    urls := make([]string, totalParts)
    
    for i := 1; i <= totalParts; i++ {
        req, err := c.PresignClient.PresignUploadPart(context.TODO(), &s3.UploadPartInput{
            Bucket:     &c.BucketName,
            Key:        &objectKey,
            UploadId:   &uploadID,
            PartNumber: aws.Int32(int32(i)),
        }, func(opts *s3.PresignOptions) {
            opts.Expires = 1 * time.Hour // TTL для каждой части
        })
        
        if err != nil {
            return nil, err
        }
        
        urls[i-1] = req.URL
    }
    
    return urls, nil
}

// Шаг 3: Завершение multipart upload
func (c *S3Client) CompleteMultipartUpload(objectKey, uploadID string, parts []CompletedPart) error {
    completedParts := make([]types.CompletedPart, len(parts))
    for i, p := range parts {
        completedParts[i] = types.CompletedPart{
            ETag:       &p.ETag,
            PartNumber: aws.Int32(int32(p.PartNumber)),
        }
    }
    
    input := &s3.CompleteMultipartUploadInput{
        Bucket:   &c.BucketName,
        Key:      &objectKey,
        UploadId: &uploadID,
        MultipartUpload: &types.CompletedMultipartUpload{
            Parts: completedParts,
        },
    }
    
    _, err := c.Client.CompleteMultipartUpload(context.TODO(), input)
    return err
}

type CompletedPart struct {
    ETag       string
    PartNumber int
}
```

### gRPC методы для multipart

```protobuf
// В proto файл добавить:
service VideoService {
  // Multipart upload
  rpc InitiateMultipartUpload(InitiateMultipartUploadRequest) returns (InitiateMultipartUploadResponse);
  rpc GetPartUploadURLs(GetPartUploadURLsRequest) returns (GetPartUploadURLsResponse);
  rpc CompleteMultipartUpload(CompleteMultipartUploadRequest) returns (CompleteMultipartUploadResponse);
  rpc AbortMultipartUpload(AbortMultipartUploadRequest) returns (AbortMultipartUploadResponse);
}

message InitiateMultipartUploadRequest {
  string org_id = 1;
  string file_name = 2;
  int64 file_size_bytes = 3;
  int32 duration_seconds = 4;
}

message InitiateMultipartUploadResponse {
  string video_id = 1;
  string upload_id = 2;
  int32 recommended_part_size_mb = 3; // рекомендуем 10MB
}

message GetPartUploadURLsRequest {
  string video_id = 1;
  int32 total_parts = 2; // клиент рассчитывает сам
}

message GetPartUploadURLsResponse {
  repeated string part_urls = 1;
  int64 expires_at = 2;
}

message CompleteMultipartUploadRequest {
  string video_id = 1;
  repeated CompletedPart parts = 2;
}

message CompletedPart {
  int32 part_number = 1;
  string etag = 2; // получает клиент из S3 response headers
}

message CompleteMultipartUploadResponse {
  string message = 1;
  string video_url = 2;
}
```

### Обработчик в Cloud Function

```go
func (s *Server) InitiateMultipartUpload(ctx context.Context, req *pb.InitiateMultipartUploadRequest) (*pb.InitiateMultipartUploadResponse, error) {
    // 1. Проверить JWT и RBAC
    claims := GetClaimsFromContext(ctx)
    hasPermission, _ := s.rbac.CheckPermission(ctx, claims.UserID, req.OrgId, "upload")
    if !hasPermission {
        return nil, status.Error(codes.PermissionDenied, "Нет прав на загрузку")
    }
    
    // 2. Проверить лимит storage
    usage, _ := s.ydb.GetStorageUsage(ctx, req.OrgId)
    subscription, _ := s.ydb.GetSubscriptionByUserID(ctx, claims.UserID)
    
    if subscription.StorageLimitGB > 0 { // 0 = unlimited для enterprise
        limitBytes := subscription.StorageLimitGB * 1024 * 1024 * 1024
        if usage + req.FileSizeBytes > limitBytes {
            return nil, status.Error(codes.ResourceExhausted, "Превышен лимит storage")
        }
    }
    
    // 3. Инициировать multipart upload в S3
    videoID := uuid.New().String()
    objectKey := fmt.Sprintf("videos/%s/%s/%s", req.OrgId, videoID, req.FileName)
    
    uploadID, err := s.s3.InitiateMultipartUpload(objectKey)
    if err != nil {
        return nil, err
    }
    
    // 4. Создать запись в YDB
    video := &Video{
        VideoID:       videoID,
        OrgID:         req.OrgId,
        UploadedBy:    claims.UserID,
        FileName:      req.FileName,
        FileNameSearch: strings.ToLower(req.FileName), // для поиска
        FileSizeBytes: req.FileSizeBytes,
        StoragePath:   objectKey,
        UploadID:      uploadID,
        UploadStatus:  "pending",
        CreatedAt:     time.Now(),
    }
    s.ydb.CreateVideo(ctx, video)
    
    return &pb.InitiateMultipartUploadResponse{
        VideoId:              videoID,
        UploadId:             uploadID,
        RecommendedPartSizeMb: 10, // 10MB части
    }, nil
}

func (s *Server) GetPartUploadURLs(ctx context.Context, req *pb.GetPartUploadURLsRequest) (*pb.GetPartUploadURLsResponse, error) {
    // 1. Получить видео из YDB
    video, err := s.ydb.GetVideo(ctx, req.VideoId)
    if err != nil {
        return nil, err
    }
    
    // 2. Сгенерировать presigned URLs для частей
    urls, err := s.s3.GenerateMultipartPresignedURLs(video.StoragePath, video.UploadID, int(req.TotalParts))
    if err != nil {
        return nil, err
    }
    
    // 3. Обновить статус и количество частей
    video.UploadStatus = "uploading"
    video.TotalParts = req.TotalParts
    s.ydb.UpdateVideo(ctx, video)
    
    return &pb.GetPartUploadURLsResponse{
        PartUrls:  urls,
        ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
    }, nil
}

func (s *Server) CompleteMultipartUpload(ctx context.Context, req *pb.CompleteMultipartUploadRequest) (*pb.CompleteMultipartUploadResponse, error) {
    video, _ := s.ydb.GetVideo(ctx, req.VideoId)
    
    // Собрать CompletedPart из запроса
    parts := make([]storage.CompletedPart, len(req.Parts))
    for i, p := range req.Parts {
        parts[i] = storage.CompletedPart{
            ETag:       p.Etag,
            PartNumber: int(p.PartNumber),
        }
    }
    
    // Завершить multipart upload в S3
    if err := s.s3.CompleteMultipartUpload(video.StoragePath, video.UploadID, parts); err != nil {
        return nil, err
    }
    
    // Обновить статус в YDB
    video.UploadStatus = "completed"
    video.UploadedAt = time.Now()
    s.ydb.UpdateVideo(ctx, video)
    
    return &pb.CompleteMultipartUploadResponse{
        Message: "Загрузка завершена успешно",
    }, nil
}
```

***

## 🔍 Полнотекстовый поиск в YDB

### Реализация простого поиска

YDB не поддерживает встроенный full-text search, но можно реализовать через индекс по lowercase полю:[5]

```go
func (db *YDB) SearchVideos(ctx context.Context, orgID, searchQuery string) ([]*Video, error) {
    query := `
        DECLARE $org_id AS String;
        DECLARE $search_pattern AS String;
        
        SELECT video_id, file_name, file_size_bytes, uploaded_at, uploaded_by
        FROM videos
        WHERE org_id = $org_id 
          AND file_name_search LIKE $search_pattern
          AND is_deleted = false
        ORDER BY uploaded_at DESC
        LIMIT 50;
    `
    
    searchPattern := "%" + strings.ToLower(searchQuery) + "%"
    
    res, err := db.Execute(ctx, query, 
        table.NewQueryParameters(
            table.ValueParam("$org_id", types.StringValue([]byte(orgID))),
            table.ValueParam("$search_pattern", types.StringValue([]byte(searchPattern))),
        ),
    )
    
    // Парсинг результатов...
    return videos, err
}
```

### gRPC метод поиска

```protobuf
service VideoService {
  rpc SearchVideos(SearchVideosRequest) returns (SearchVideosResponse);
}

message SearchVideosRequest {
  string org_id = 1;
  string query = 2;
  int32 page = 3;
  int32 page_size = 4;
}

message SearchVideosResponse {
  repeated Video videos = 1;
  int32 total_count = 2;
}
```

***

## 🔗 Публичные ссылки для sharing

### Генерация публичной ссылки

```go
func (s *Server) CreatePublicShareLink(ctx context.Context, req *pb.CreateShareLinkRequest) (*pb.CreateShareLinkResponse, error) {
    claims := GetClaimsFromContext(ctx)
    
    // 1. Проверить права (только admin и manager могут шарить)
    hasPermission, _ := s.rbac.CheckPermission(ctx, claims.UserID, claims.OrgID, "upload")
    if !hasPermission {
        return nil, status.Error(codes.PermissionDenied, "Нет прав на создание ссылок")
    }
    
    // 2. Получить видео
    video, err := s.ydb.GetVideo(ctx, req.VideoId)
    if err != nil {
        return nil, err
    }
    
    // 3. Сгенерировать уникальный токен
    shareToken := generateSecureToken(32) // random 32 символа
    
    // 4. Установить срок действия (опционально)
    var expiresAt *time.Time
    if req.ExpiresInHours > 0 {
        expTime := time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
        expiresAt = &expTime
    }
    
    // 5. Обновить видео в YDB
    video.PublicShareToken = shareToken
    video.ShareExpiresAt = expiresAt
    s.ydb.UpdateVideo(ctx, video)
    
    // 6. Сгенерировать публичную ссылку
    publicURL := fmt.Sprintf("https://sellerproof.ru/share/%s", shareToken)
    
    return &pb.CreateShareLinkResponse{
        ShareUrl:  publicURL,
        ExpiresAt: expiresAt.Unix(),
    }, nil
}

func (s *Server) GetPublicVideo(ctx context.Context, req *pb.GetPublicVideoRequest) (*pb.GetPublicVideoResponse, error) {
    // Этот метод НЕ требует авторизации
    
    // 1. Найти видео по токену
    video, err := s.ydb.GetVideoByShareToken(ctx, req.ShareToken)
    if err != nil {
        return nil, status.Error(codes.NotFound, "Видео не найдено")
    }
    
    // 2. Проверить срок действия
    if video.ShareExpiresAt != nil && time.Now().After(*video.ShareExpiresAt) {
        return nil, status.Error(codes.PermissionDenied, "Ссылка истекла")
    }
    
    // 3. Сгенерировать временный presigned URL для скачивания (TTL 1 час)
    downloadURL, err := s.s3.GeneratePresignedDownloadURL(video.StoragePath, 1*time.Hour)
    if err != nil {
        return nil, err
    }
    
    return &pb.GetPublicVideoResponse{
        FileName:    video.FileName,
        FileSize:    video.FileSizeBytes,
        DownloadUrl: downloadURL,
        ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
    }, nil
}

func generateSecureToken(length int) string {
    bytes := make([]byte, length)
    rand.Read(bytes)
    return hex.EncodeToString(bytes)
}
```

### Proto определения

```protobuf
service VideoService {
  rpc CreatePublicShareLink(CreateShareLinkRequest) returns (CreateShareLinkResponse);
  rpc GetPublicVideo(GetPublicVideoRequest) returns (GetPublicVideoResponse); // без auth
  rpc RevokeShareLink(RevokeShareLinkRequest) returns (RevokeShareLinkResponse);
}

message CreateShareLinkRequest {
  string video_id = 1;
  int32 expires_in_hours = 2; // 0 = бессрочно
}

message CreateShareLinkResponse {
  string share_url = 1;
  int64 expires_at = 2; // 0 если бессрочно
}

message GetPublicVideoRequest {
  string share_token = 1;
}

message GetPublicVideoResponse {
  string file_name = 1;
  int64 file_size = 2;
  string download_url = 3;
  int64 expires_at = 4;
}
```

***

## 🔧 Обновлённые переменные окружения

```makefile
# Добавить в Makefile
export POSTBOX_ACCESS_KEY_ID
export POSTBOX_SECRET_ACCESS_KEY
export POSTBOX_FROM_EMAIL
export VERIFICATION_LINK_BASE_URL

REQUIRED_ENV := ... POSTBOX_ACCESS_KEY_ID POSTBOX_SECRET_ACCESS_KEY ...

ENV_ARGS = "...,POSTBOX_ACCESS_KEY_ID=$$POSTBOX_ACCESS_KEY_ID,POSTBOX_SECRET_ACCESS_KEY=$$POSTBOX_SECRET_ACCESS_KEY,POSTBOX_FROM_EMAIL=$$POSTBOX_FROM_EMAIL,VERIFICATION_LINK_BASE_URL=$$VERIFICATION_LINK_BASE_URL"
```

***

## 📱 Flutter клиент flow

### Multipart upload на клиенте

```dart
class VideoUploadService {
  final VideoServiceClient grpcClient;
  
  Future<void> uploadLargeVideo(File videoFile, String orgId) async {
    final fileSize = await videoFile.length();
    const partSizeMB = 10;
    final partSizeBytes = partSizeMB * 1024 * 1024;
    final totalParts = (fileSize / partSizeBytes).ceil();
    
    // 1. Инициировать multipart upload
    final initResponse = await grpcClient.initiateMultipartUpload(
      InitiateMultipartUploadRequest(
        orgId: orgId,
        fileName: videoFile.path.split('/').last,
        fileSizeBytes: Int64(fileSize),
      ),
    );
    
    // 2. Получить presigned URLs для частей
    final urlsResponse = await grpcClient.getPartUploadURLs(
      GetPartUploadURLsRequest(
        videoId: initResponse.videoId,
        totalParts: totalParts,
      ),
    );
    
    // 3. Загрузить каждую часть параллельно
    final completedParts = <CompletedPart>[];
    final dio = Dio();
    
    for (int i = 0; i < totalParts; i++) {
      final start = i * partSizeBytes;
      final end = min((i + 1) * partSizeBytes, fileSize);
      final partData = await videoFile.openRead(start, end).toList();
      
      final response = await dio.put(
        urlsResponse.partUrls[i],
        data: Stream.fromIterable(partData),
        options: Options(
          headers: {'Content-Type': 'video/mp4'},
        ),
      );
      
      // ETag из response headers
      final etag = response.headers.value('etag')!.replaceAll('"', '');
      completedParts.add(CompletedPart(
        partNumber: i + 1,
        etag: etag,
      ));
    }
    
    // 4. Завершить multipart upload
    await grpcClient.completeMultipartUpload(
      CompleteMultipartUploadRequest(
        videoId: initResponse.videoId,
        parts: completedParts,
      ),
    );
  }
}
```

***

## 📊 Обновлённая диаграмма потоков

### Multipart Upload Flow

```
Flutter Client                Cloud Function                    Object Storage
     |                              |                                  |
     |--InitiateMultipartUpload---->|                                  |
     |                              |--CreateMultipartUpload---------->|
     |                              |<----UploadID---------------------|
     |<----VideoID + UploadID-------|                                  |
     |                              |                                  |
     |--GetPartUploadURLs(n parts)->|                                  |
     |<----[URL1, URL2, ... URLn]---|                                  |
     |                              |                                  |
     |--PUT part1 data------------------------------------->|           |
     |<----ETag1-------------------------------------------|           |
     |--PUT part2 data------------------------------------->|           |
     |<----ETag2-------------------------------------------|           |
     |                              |                                  |
     |--CompleteMultipartUpload---->|                                  |
     |(with [ETag1, ETag2...])      |--CompleteMultipartUpload-------->|
     |                              |<----Success----------------------|
     |<----Success------------------|                                  |
```

### Email Verification Flow

```
Flutter Client          Cloud Function           Postbox              User Email
     |                        |                      |                    |
     |--Register(email)------>|                      |                    |
     |                        |--SendEmail---------->|                    |
     |                        |                      |--Deliver---------->|
     |<--"Check email"--------|                      |                    |
     |                        |                      |                    |
     |                        |                      |<--User clicks link-|
     |--VerifyEmail(code)---->|                      |                    |
     |                        |--Update YDB--------->|                    |
     |<--"Verified!-----------|                      |                    |
```

***

## ✅ Итоговый чеклист обновлений

- [x] Presigned URLs для загрузки (без прохождения через Function)
- [x] Email верификация через Yandex Cloud Postbox
- [x] Multipart upload для видео >100MB
- [x] Полнотекстовый поиск по file_name_search (LIKE)
- [x] Публичные ссылки с токенами и expiration
- [x] Лимиты только по storage (не по количеству)
- [x] Все операции через Flutter (нет админки)

Архитектура теперь полностью покрывает требования SellerProof с учётом всех уточнений. Готов к реализации![2][6][1][3]

[1](https://stackoverflow.com/questions/43662755/s3-golang-multipart-upload-using-presigned-url)
[2](https://github.com/prestonlimlianjie/aws-s3-multipart-presigned-upload)
[3](https://yandex.cloud/en/docs/tutorials/serverless/postbox-webhook)
[4](https://yandex.cloud/ru/docs/tutorials/serverless/domain-identity-creating)
[5](https://docs.yugabyte.com/preview/develop/learn/text-search/full-text-search/)
[6](https://yandex.cloud/ru/services/postbox)
[7](https://github.com/yandex-cloud-examples/yc-postbox-bulkemails)
[8](https://yandex.cloud/ru/docs/postbox/)
[9](https://stackoverflow.com/questions/12685879/full-text-search-indexeddb-example-implementations)
[10](https://yandex.cloud/en/docs/serverless-integrations/concepts/workflows/yawl/integration/postbox)