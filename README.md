# SellerProof Backend

Бэкенд для системы управления видео с регистрацией, авторизацией и управлением доступом на базе Yandex Cloud.

## Архитектура

- **Язык**: Go 1.24+
- **База данных**: Yandex Database (YDB)
- **Хранилище**: Yandex Object Storage
- **Email**: Yandex Cloud Postbox
- **Аутентификация**: JWT токены
- **Авторизация**: RBAC (Role-Based Access Control)
- **API**: REST API

## Структура проекта

```
sellerproof-backend/
├── cmd/                    # Точка входа в приложение
├── internal/                # Внутренние пакеты
│   ├── auth/              # Сервис аутентификации
│   ├── rbac/              # Система управления доступом
│   ├── jwt/               # Управление JWT токенами
│   ├── email/             # Интеграция с Postbox
│   ├── ydb/               # Клиент YDB
│   ├── http/              # HTTP сервер и обработчики
│   ├── video/             # Сервис управления видео
│   └── storage/           # Клиент S3 хранилища
├── schema/                 # SQL схемы YDB
├── demo/                   # Демонстрационное приложение
└── Makefile               # Сценарии сборки и деплоя
```

## Функциональность

### ✅ Реализовано

- **Регистрация пользователей** с email верификацией
- **Авторизация** через JWT токены
- **Обновление токенов** (refresh flow)
- **RBAC система** с ролями admin/manager/user
- **Email верификация** через Yandex Cloud Postbox
- **Управление организациями** и членством
- **Подписки** с тарифными планами
- **Логирование** email отправок
- **REST API** для всех операций
- **Multipart upload** для больших файлов
- **Публичные ссылки** для sharing
- **Полнотекстовый поиск** по видео

## Быстрый старт

### 1. Клонирование и установка зависимостей

```bash
git clone https://github.com/lumiforge/sellerproof-backend.git
cd sellerproof-backend
go mod tidy
```

### 2. Настройка переменных окружения

Скопируйте файл с примером:

```bash
cp .env.example .env
```

Отредактируйте `.env` файл с вашими данными:

```bash
# Yandex Cloud YDB
SP_YDB_ENDPOINT=grpcs://ydb.serverless.yandexcloud.net:2135
SP_YDB_DATABASE_PATH=/ru-central1/b1gia87mbaomkf2ssg3/sellerproof

# JWT
JWT_SECRET_KEY=your-super-secret-jwt-key

# Yandex Cloud Postbox
POSTBOX_ACCESS_KEY_ID=your-postbox-access-key-id
POSTBOX_SECRET_ACCESS_KEY=your-postbox-secret-access-key
POSTBOX_FROM_EMAIL=noreply@sellerproof.ru

# Yandex Object Storage
S3_ENDPOINT=https://storage.yandexcloud.net
SP_SA_KEY_ID=your-service-account-key-id
SP_SA_KEY=your-service-account-key
SP_OBJSTORE_BUCKET_NAME=your-bucket-name

# HTTP порт
SP_HTTP_PORT=8080

# Другие настройки...
```

### 3. Создание таблиц в YDB

Выполните SQL схему из файла `schema/ydb.sql` в вашей YDB базе данных.

### 4. Запуск локально

```bash
go run cmd/main.go
```

Сервер будет доступен на порту `8080` (HTTP API).

### 5. Демонстрация

Запустите демо-приложение:

```bash
go run demo/main.go
```

## API

### REST API эндпоинты

#### Аутентификация

- `POST /api/v1/auth/register` - Регистрация нового пользователя
- `POST /api/v1/auth/login` - Вход пользователя
- `POST /api/v1/auth/refresh` - Обновление токена
- `POST /api/v1/auth/logout` - Выход пользователя
- `POST /api/v1/auth/verify-email` - Подтверждение email
- `GET /api/v1/auth/profile` - Получение профиля
- `PUT /api/v1/auth/profile` - Обновление профиля

#### Видео

- `POST /api/v1/video/upload/initiate` - Инициализация multipart загрузки
- `POST /api/v1/video/upload/urls` - Получение URL для частей загрузки
- `POST /api/v1/video/upload/complete` - Завершение multipart загрузки
- `GET /api/v1/video` - Получение информации о видео
- `GET /api/v1/video/search` - Поиск видео
- `POST /api/v1/video/share` - Создание публичной ссылки
- `POST /api/v1/video/share/revoke` - Отзыв публичной ссылки
- `GET /api/v1/video/public` - Получение видео по публичной ссылке

#### Системные

- `GET /health` - Проверка состояния сервера
- `GET /` - Корневой эндпоинт (health check)

### Примеры запросов

#### Регистрация

```json
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "full_name": "John Doe"
}
```

#### Вход

```json
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Ответ при входе

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": 1700365678,
  "user": {
    "user_id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "full_name": "John Doe",
    "role": "admin",
    "org_id": "org-987654321",
    "email_verified": true
  }
}
```

#### Загрузка видео

```json
POST /api/v1/video/upload/initiate
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "file_name": "video.mp4",
  "file_size_bytes": 1048576,
  "duration_seconds": 120
}
```

## Роли и права доступа

### Роли

- **admin** - Полный доступ ко всем функциям
- **manager** - Управление видео и пользователями в рамках организации
- **user** - Только просмотр и скачивание видео

### Права доступа

| Операция | Admin | Manager | User |
|------------|--------|----------|-------|
| Просмотр видео | ✅ | ✅ | ✅ |
| Загрузка видео | ✅ | ✅ | ❌ |
| Удаление видео | ✅ | ✅ | ❌ |
| Создание ссылок | ✅ | ✅ | ❌ |
| Управление пользователями | ✅ | ✅ | ❌ |

## Деплой в Yandex Cloud

### 1. Сборка

```bash
make build
```

### 2. Деплой

```bash
make deploy
```

Убедитесь, что все переменные окружения установлены:

```bash
export SP_SA=your-service-account-id
export SP_FUNC=sellerproof-auth
export SP_ENTRY=cmd.main
# ... другие переменные
```

## Мониторинг и логирование

- Логи отправляются в stdout
- Email логи сохраняются в таблицу `email_logs`
- Ошибки аутентификации логируются с детализацией
- HTTP запросы логируются с request ID

## Безопасность

- Пароли хешируются с использованием bcrypt
- JWT токены имеют ограниченный срок действия
- Refresh токены отзываются при выходе
- Email верификация обязательна для активации аккаунта
- RBAC проверяется на каждом запросе
- CORS заголовки для веб-клиентов

## Тестирование

```bash
# Запуск тестов
go test ./...

# Запуск с покрытием
go test -cover ./...
```

## Траблшутинг

### Проблемы с подключением к YDB

1. Проверьте переменные `SP_YDB_ENDPOINT` и `SP_YDB_DATABASE_PATH`
2. Убедитесь, что сервисный аккаунт имеет права доступа к YDB
3. Проверьте сетевые настройки

### Проблемы с отправкой email

1. Проверьте настройки Postbox (`POSTBOX_*` переменные)
2. Убедитесь, что домен подтвержден в Yandex Cloud
3. Проверьте DNS записи (SPF, DKIM)

### Проблемы с JWT

1. Проверьте `JWT_SECRET_KEY`
2. Убедитесь, что время на сервере синхронизировано
3. Проверьте срок действия токена

## Лицензия

MIT License