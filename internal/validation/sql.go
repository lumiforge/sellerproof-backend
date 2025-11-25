package validation

import (
	"strings"
)

// SQLInjectionPatterns содержит паттерны для обнаружения SQL-инъекций
var SQLInjectionPatterns = []string{
	"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
	"drop ", "delete ", "insert ", "update ", "select ",
	"union ", "exec ", "execute ", "truncate ", "alter ",
	"create ", "table ", "from ", "where ", "or 1=1",
	"and 1=1", "sleep(", "benchmark(", "waitfor delay",
	"convert(", "cast(", "char(", "ascii(", "substring(",
	"concat(", "load_file(", "into outfile", "into dumpfile",
}

// ContainsSQLInjection проверяет наличие SQL-инъекций в строке
func ContainsSQLInjection(input string) bool {
	if input == "" {
		return false
	}

	inputLower := strings.ToLower(input)
	for _, pattern := range SQLInjectionPatterns {
		if strings.Contains(input, pattern) || strings.Contains(inputLower, pattern) {
			return true
		}
	}
	return false
}

// ValidateSQLInjection выполняет валидацию SQL-инъекций и возвращает ошибку
func ValidateSQLInjection(input string, fieldName string) error {
	if ContainsSQLInjection(input) {
		return ValidationError{
			Field:   fieldName,
			Message: "contains invalid characters (potential SQL injection)",
		}
	}
	return nil
}

// ValidateSQLInjectionStrict выполняет строгую валидацию SQL-инъекций
func ValidateSQLInjectionStrict(input string, fieldName string) error {
	if input == "" {
		return nil
	}

	// Дополнительные паттерны для строгой проверки
	strictPatterns := []string{
		"||", "&&", "|", "&", "^", "%", "_", "[", "]",
		"(", ")", "{", "}", "<", ">", "=",
	}

	inputLower := strings.ToLower(input)

	// Проверяем базовые паттерны
	for _, pattern := range SQLInjectionPatterns {
		if strings.Contains(input, pattern) || strings.Contains(inputLower, pattern) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains invalid characters (potential SQL injection)",
			}
		}
	}

	// Проверяем строгие паттерны
	for _, pattern := range strictPatterns {
		if strings.Contains(input, pattern) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains forbidden characters",
			}
		}
	}

	return nil
}

// SanitizeForSQL очищает строку для безопасного использования в SQL
// ВАЖНО: Эта функция не заменяет параметризованные запросы!
func SanitizeForSQL(input string) string {
	// Удаляем потенциально опасные символы
	replacements := map[string]string{
		"'":  "''",
		"\"": "\\\"",
		"\\": "\\\\",
		"\n": "\\n",
		"\r": "\\r",
		"\t": "\\t",
	}

	result := input
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}

	return result
}
