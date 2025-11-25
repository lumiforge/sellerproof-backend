# Validation Package

Пакет `validation` предоставляет централизованные функции для валидации данных в проекте SellerProof Backend.

## Структура пакета

- `validator.go` - Основные интерфейсы и функции валидации
- `sql.go` - Функции для защиты от SQL-инъекций
- `xss.go` - Функции для защиты от XSS-атак
- `unicode.go` - Функции для защиты от Unicode-атак
- `email.go` - Функции для валидации email адресов
- `filename.go` - Функции для валидации имен файлов
- `content_type.go` - Функции для валидации Content-Type

## Основные интерфейсы

### ValidationError
```go
type ValidationError struct {
    Field   string
    Message string
}
```

### ValidationResult
```go
type ValidationResult struct {
    IsValid bool
    Errors  []ValidationError
}
```

### Validator
```go
type Validator interface {
    Validate(input string) ValidationResult
}
```

## Основные функции

### ValidateInput
Основная функция для валидации входных данных с настраиваемыми опциями:

```go
func ValidateInput(input string, fieldName string, options ValidationOptions) error
```

### ValidationOptions
```go
type ValidationOptions struct {
    CheckSQLInjection     bool
    CheckXSS              bool
    CheckUnicodeSecurity  bool
    CheckEmailFormat       bool
    CheckFilenameSecurity  bool
}
```

### Функции-билдеры для опций
```go
func WithSQLInjectionCheck() ValidationOptions
func WithXSSCheck() ValidationOptions
func WithUnicodeSecurityCheck() ValidationOptions
func WithEmailFormatCheck() ValidationOptions
func WithFilenameSecurityCheck() ValidationOptions
```

## Защита от SQL-инъекций

### Функции
- `ContainsSQLInjection(input string) bool` - Проверяет наличие SQL-инъекций
- `ValidateSQLInjection(input string, fieldName string) error` - Валидация с ошибкой
- `ValidateSQLInjectionStrict(input string, fieldName string) error` - Строгая валидация
- `SanitizeForSQL(input string) string` - Очистка для безопасного использования в SQL

### Обнаруживаемые паттерны
- Кавычки: `'`, `"`
- Комментарии: `--`, `/*`, `*/`
- SQL команды: `DROP`, `DELETE`, `INSERT`, `UPDATE`, `SELECT`, `UNION`
- Функции: `xp_`, `sp_`, `exec`, `execute`
- Временные атаки: `sleep(`, `benchmark(`, `waitfor delay`

## Защита от XSS-атак

### Функции
- `ContainsXSS(input string) bool` - Проверяет наличие XSS-атак
- `ValidateXSS(input string, fieldName string) error` - Валидация с ошибкой
- `ValidateXSSStrict(input string, fieldName string) error` - Строгая валидация
- `SanitizeForHTML(input string) string` - Очистка для HTML
- `SanitizeForAttribute(input string) string` - Очистка для атрибутов HTML

### Обнаруживаемые паттерны
- Теги скриптов: `<script`, `</script>`
- Протоколы: `javascript:`, `vbscript:`
- Обработчики событий: `onload=`, `onerror=`, `onclick=`, и т.д.
- Опасные функции: `eval(`, `expression(`, `alert(`
- HTML элементы: `iframe`, `object`, `embed`, `link`

## Защита от Unicode-атак

### Функции
- `ContainsUnicodeAttack(input string) bool` - Проверяет наличие Unicode-атак
- `ValidateUnicodeSecurity(input string, fieldName string) error` - Валидация с ошибкой
- `ValidateFilenameUnicode(input string, fieldName string) error` - Валидация имен файлов
- `SanitizeUnicode(input string) string` - Очистка от опасных Unicode-символов
- `NormalizeUnicode(input string) string` - Нормализация Unicode-строки

### Обнаруживаемые атаки
- RTL override: `\u202A-\u202E`
- Поповка направления: `\u2066-\u2069`
- Нулевые символы: `\u200B-\u200F`
- Гомограф атаки: кириллица похожая на латиницу
- Полноширинные символы: `\uFF00-\uFFEF`
- Комбинируемые символы: диакритические знаки

## Валидация email

### Функции
- `IsValidEmail(email string) bool` - Базовая проверка
- `IsValidEmailStrict(email string) bool` - Строгая проверка
- `ValidateEmail(email string, fieldName string) error` - Валидация с ошибкой
- `ValidateEmailStrict(email string, fieldName string) error` - Строгая валидация
- `SanitizeEmail(email string) string` - Очистка email
- `NormalizeEmail(email string) string` - Нормализация email

### Правила валидации
- Формат: `local@domain.tld`
- Длина: до 254 символов
- Локальная часть: до 64 символов
- Домен: до 253 символов
- Запрещенные символы: пробелы в начале/конце, двойные точки

## Валидация имен файлов

### Функции
- `IsValidFilename(filename string) bool` - Базовая проверка
- `IsValidFilenameStrict(filename string) bool` - Строгая проверка
- `ValidateFilename(filename string, fieldName string) error` - Валидация с ошибкой
- `ValidateFilenameStrict(filename string, fieldName string) error` - Строгая валидация
- `SanitizeFilename(filename string) string` - Очистка имени файла
- `NormalizeFilename(filename string) string` - Нормализация имени файла

### Правила валидации
- Длина: до 255 символов (строгая: до 100)
- Запрещенные символы: `<`, `>`, `:`, `"`, `|`, `?`, `*`, `/`, `\`
- Зарезервированные имена: `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`
- Безопасные расширения: проверка на опасные типы файлов

## Валидация Content-Type

### Функции
- `IsValidContentType(contentType string) bool` - Базовая проверка
- `IsSafeContentType(contentType string) bool` - Проверка безопасности
- `ValidateContentType(contentType string, fieldName string) error` - Валидация с ошибкой
- `ValidateSafeContentType(contentType string, fieldName string) error` - Проверка безопасности
- `GetContentTypeFromExtension(filename string) string` - Определение по расширению
- `ValidateContentTypeForExtension(filename, contentType string, fieldName string) error` - Соответствие расширению

### Поддерживаемые типы
- Изображения: `image/jpeg`, `image/png`, `image/gif`, `image/webp`
- Видео: `video/mp4`, `video/webm`, `video/quicktime`
- Аудио: `audio/mpeg`, `audio/wav`, `audio/ogg`
- Документы: `application/pdf`, `text/plain`
- JSON/XML: `application/json`, `application/xml`

## Примеры использования

### Базовая валидация
```go
import "github.com/lumiforge/sellerproof-backend/internal/validation"

// Валидация email
err := validation.ValidateEmail("user@example.com", "email")
if err != nil {
    // обработка ошибки
}

// Валидация имени файла
err = validation.ValidateFilename("document.pdf", "filename")
if err != nil {
    // обработка ошибки
}
```

### Комплексная валидация
```go
// Валидация с несколькими проверками
options := validation.WithSQLInjectionCheck().
    WithXSSCheck().
    WithUnicodeSecurityCheck()

err := validation.ValidateInput(userInput, "comment", options)
if err != nil {
    // обработка ошибки
}
```

### Валидация списков
```go
// Валидация списка email
emails := []string{"user1@example.com", "user2@example.com"}
err := validation.ValidateEmailList(emails, "emails")
if err != nil {
    // обработка ошибки
}
```

### Очистка данных
```go
// Очистка HTML
safeHTML := validation.SanitizeForHTML(userInput)

// Очистка для SQL
safeSQL := validation.SanitizeForSQL(userInput)

// Очистка имени файла
safeFilename := validation.SanitizeFilename(userInput)
```

## Рекомендации по использованию

1. **Всегда используйте параметризованные запросы** - функции очистки SQL не заменяют их
2. **Применяйте валидацию на всех входных данных** - особенно от пользователей
3. **Используйте строгие функции для критически важных данных**
4. **Очищайте данные перед отображением в HTML** - даже после валидации
5. **Проверяйте типы содержимого файлов** - не доверяйте расширениям
6. **Используйте нормализацию для пользовательских данных** - для консистентности

## Тестирование

Пакет включает комплексные тесты для всех функций валидации. Запустите их с помощью:

```bash
go test ./internal/validation/...
```

## Безопасность

Пакет разработан с учетом современных угроз безопасности:
- Регулярно обновляемые паттерны атак
- Защита от новых векторов атак
- Многоуровневая валидация
- Поддержка Unicode безопасности