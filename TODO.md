Цель: в сервисе больше не используется корзина и нет удаления файлов вообще. Все файлы будут храниться год а потом автоматически средствами Yandex Object Storage удаляться.

## Твоя задача
Полностью удалить функционал корзины и удаление файлов в сервисе.

### Компоненты для удаления

#### API эндпоинты (router.go)
- `DELETE /api/v1/video/{id}` — удаление видео (перемещение в корзину)
- `GET /api/v1/video/trash` — получение списка удаленных видео
- `POST /api/v1/video/restore` — восстановление видео из корзины

#### Database интерфейс (ydb/interface.go)
- `MoveVideoToTrash` — перемещение видео в корзину
- `RestoreVideoFromTrash` — восстановление из корзины
- `GetTrashVideos` — получение списка видео в корзине
- `GetTrashVideo` — получение информации о видео в корзине
- `DeleteTrashVideo` — окончательное удаление видео из корзины

#### Модели данных
- `TrashVideo` структура в `models/video.go`
- `TrashVideo` таблица в `ydb/types.go` с полями: `video_id`, `deleted_at`, `storage_path`, и др.
- `Video.IsDeleted` и `Video.DeletedAt` поля в основной таблице

#### Storage Provider (storage/interface.go)
- `DeletePrivateObject` — удаление файла из приватного бакета
- `DeletePublicObject` — удаление из публичного бакета
- `DeleteObject` — общий метод удаления

### Рекомендации по удалению

#### Шаг 1: Удалить API handlers
Из `internal/http/handlers.go` удалить обработчики:
- `DeleteVideo`
- `GetTrashVideos`
- `RestoreVideo`

#### Шаг 2: Удалить маршруты
Из `internal/http/router.go` удалить:
- Маршрут `DELETE /api/v1/video/`
- Маршрут `GET /api/v1/video/trash`
- Маршрут `POST /api/v1/video/restore`

#### Шаг 3: Упростить модели
Из `internal/models/video.go` удалить:
- `TrashVideo` структуру
- `DeleteVideoRequest` и `DeleteVideoResponse`
- `RestoreVideoRequest` и `RestoreVideoResponse`
- `GetTrashVideosResponse`

Из `internal/ydb/types.go`:
- Удалить `TrashVideo` структуру
- Из `Video` структуры удалить поля `IsDeleted` и `DeletedAt`

#### Шаг 4: Очистить database интерфейс
Из `internal/ydb/interface.go` и его реализации в `internal/ydb/client.go` удалить методы:
- `MoveVideoToTrash`
- `RestoreVideoFromTrash`
- `GetTrashVideos`
- `GetTrashVideo`
- `DeleteTrashVideo`


### Детали

1.  **Обработка вредоносных файлов (System Cleanup):**
    В текущей реализации `internal/video/service.go` (метод `CompleteMultipartUploadDirect`), если загруженный файл не проходит проверку (например, это `.exe` вместо видео), система вызывает `s.storage.DeletePrivateObject`, чтобы удалить его.
    *   **Пояснение:**  Оставь метод удаления (например, переименовав его в `DeleteObject` или `CleanupObject`) *исключительно* для внутренних системных нужд (удаление битых/вредоносных файлов при загрузке);

2.  **Логика отзыва публичного доступа (Revoke Video):**
    В задании указано удалить `DeletePublicObject`. Однако метод `RevokeVideo` (который *не* указан в списке на удаление) использует `DeletePublicObject`, чтобы физически убрать файл из публичного бакета при отзыве доступа.
    *   **Пояснение:** Нужно сохранить `DeletePublicObject` для работы функционала `RevokeVideo`;

3.  **Конфигурация (Trash Bucket):**
    В `internal/config/config.go` и `internal/storage/client.go` используется переменная `SPObjStoreTrashBucket`.
    *   **Пояснение:** Тебе нужно вычистить упоминания бакета корзины (`trash bucket`) из конфигурации и инициализации клиента хранилища;

4.  **SQL запросы и оставшиеся колонки:**
    Миграция БД не требуется. Это значит, что, например, колонки `is_deleted`, `deleted_at` и таблица `trash_videos` просто не нужно добавлять в YDB.
    *   **Пояснение:** Все таблицы создаются из метода internal/ydb/client.go:82-82```createTables``` так что ты должен просто удалить эти колонки из таблицы в YDB.


5.  **Audit Logs:**
    *   **Пояснение:** Нужно удалить константы `AuditVideoDelete` и `AuditVideoRestore` из `internal/models/audit.go`, так как эти действия больше невозможны;


### Важные моменты

**Миграция базы данных**: Не требуется. Исторических данных нет, новый сервис выкатываем все с нуля!


**Тесты**: Удалить тесты для удаленных handlers из `internal/http/handlers_test.go`.

**OpenAPI документация**: Обновить комментарии для Swagger документации.

Полное удаление функционала корзины должно произвестись без нарушения остальной логики приложения, так как эти компоненты изолированы и не используются критическими частями системы.

**Важно:** это production-ready решение, это **не** MVP, писать только production-ready код.

