Задача: сейчас при регистрации пользователя он регистрируется с подпиской start, но is_active = false и expires_at = now.
Нужно изменить так, чтобы создавался
freePlan, err := s.db.GetPlanByID(ctx, "free")
subscription = &ydb.Subscription{
    PlanID:              "free",
    VideoLimitMB:        0,      // Нельзя загружать
    OrdersPerMonthLimit: 0,      // Нельзя загружать
    IsActive:            true,   // ✅ Активна
    ExpiresAt:           навсегда
}

Измени код.

Детали:

1.  **Инициализация плана в БД:**
    В файле `internal/ydb/client.go` сейчас жестко прописана вставка планов `start`, `pro`, `business`.
    *   Нужно добавить автоматическую вставку плана `free` в таблицу `plans` при инициализации;
    *   Использовать для полей значения: `name` "FREE",`price_rub` (0), `features` {"retention_months": 0};

2.  **Техническая реализация "Навсегда":**
    Поле `ExpiresAt` в базе данных имеет тип `Timestamp`.
    *   Значение времени считать для "навсегда" `time.Now().AddDate(100, 0, 0)` (через 100 лет);

3.  **Конфигурация (Config):**
    В `internal/config/config.go` лимиты для других планов вынесены в переменные окружения.
    *  Не нужно выносить лимиты для `free` плана (0 MB, 0 orders) в конфиг; 

4.  **Billing Cycle:**
    Какое значение записать в поле `BillingCycle` для бесплатной подписки: `"infinite"`

5.  **Обработка существующих тестов:**
    В `internal/auth/service_test.go` тесты ожидают план `start`.
    *   Обнови тесты, чтобы они ожидали `free` план и новые параметры (`IsActive: true`);


**Важно:** это production-ready решение, это **не** MVP, писать только production-ready код.



