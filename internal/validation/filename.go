package validation

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// FilenameRegex содержит регулярное выражение для базовой валидации имен файлов
// Обновлено для поддержки Unicode символов, включая кириллицу
var FilenameRegex = regexp.MustCompile(`^[^<>:"|?*\\]+$`)

// StrictFilenameRegex содержит строгое регулярное выражение для валидации имен файлов
var StrictFilenameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$`)

// UnsafeFilenamePatterns содержит паттерны для обнаружения небезопасных имен файлов
var UnsafeFilenamePatterns = []*regexp.Regexp{
	// Паттерны для путей
	regexp.MustCompile(`[/\\]`), // Слэши
	regexp.MustCompile(`\.\.`),  // Родительский каталог
	regexp.MustCompile(`^\.`),   // Скрытые файлы
	regexp.MustCompile(`\.$`),   // Точка в конце
	regexp.MustCompile(`\s+$`),  // Пробелы в конце
	regexp.MustCompile(`^\s+`),  // Пробелы в начале
	// Специальные символы
	regexp.MustCompile(`[<>:"|?*]`),   // Недопустимые символы Windows
	regexp.MustCompile(`[\x00-\x1f]`), // Контрольные символы
	// Подозрительные расширения
	regexp.MustCompile(`\.(exe|bat|cmd|com|pif|scr|vbs|js|jar|sh|ps1|php|asp|aspx|jsp|py|rb|pl)$`),
	// Подозрительные имена
	regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])$`),
}

// IsValidFilename проверяет валидность имени файла
func IsValidFilename(filename string) bool {
	if filename == "" {
		return false
	}

	// Базовая проверка с помощью регулярного выражения
	if !FilenameRegex.MatchString(filename) {
		return false
	}

	// Дополнительные проверки
	if !isValidFilenameFormat(filename) {
		return false
	}

	return true
}

// IsValidFilenameStrict выполняет строгую проверку имени файла
func IsValidFilenameStrict(filename string) bool {
	if filename == "" {
		return false
	}

	// Строгая проверка с помощью регулярного выражения
	if !StrictFilenameRegex.MatchString(filename) {
		return false
	}

	// Дополнительные проверки
	if !isValidFilenameFormat(filename) {
		return false
	}

	// Дополнительные строгие проверки
	if !isValidFilenameStrictFormat(filename) {
		return false
	}

	return true
}

// ValidateFilename выполняет валидацию имени файла и возвращает ошибку
func ValidateFilename(filename string, fieldName string) error {
	if !IsValidFilename(filename) {
		return ValidationError{
			Field:   fieldName,
			Message: "is not a valid filename",
		}
	}
	return nil
}

// ValidateFilenameStrict выполняет строгую валидацию имени файла и возвращает ошибку
func ValidateFilenameStrict(filename string, fieldName string) error {
	if !IsValidFilenameStrict(filename) {
		return ValidationError{
			Field:   fieldName,
			Message: "is not a valid filename",
		}
	}
	return nil
}

// isValidFilenameFormat выполняет дополнительные проверки формата имени файла
func isValidFilenameFormat(filename string) bool {
	filename = strings.TrimSpace(filename)

	// Проверка длины
	if len(filename) == 0 || len(filename) > 255 {
		return false
	}

	// Проверка на небезопасные паттерны
	for _, pattern := range UnsafeFilenamePatterns {
		if pattern.MatchString(filename) {
			return false
		}
	}

	// Проверка на зарезервированные имена
	if isReservedFilename(filename) {
		return false
	}

	// Проверка на Unicode-атаки
	if ContainsUnicodeAttack(filename) {
		return false
	}

	return true
}

// isValidFilenameStrictFormat выполняет строгие проверки формата имени файла
func isValidFilenameStrictFormat(filename string) bool {
	filename = strings.TrimSpace(filename)

	// Строгая проверка длины
	if len(filename) < 1 || len(filename) > 100 {
		return false
	}

	// Проверка на наличие только буквенно-цифровых символов в начале и конце
	first := filename[0]
	last := filename[len(filename)-1]
	if !unicode.IsLetter(rune(first)) && !unicode.IsDigit(rune(first)) {
		return false
	}
	if !unicode.IsLetter(rune(last)) && !unicode.IsDigit(rune(last)) {
		return false
	}

	// Проверка на наличие двух точек подряд
	if strings.Contains(filename, "..") {
		return false
	}

	// Проверка на наличие пробелов
	if strings.Contains(filename, " ") {
		return false
	}

	// Проверка на наличие специальных символов
	specialChars := []string{"<", ">", ":", "\"", "|", "?", "*", "/", "\\"}
	for _, char := range specialChars {
		if strings.Contains(filename, char) {
			return false
		}
	}

	return true
}

// isReservedFilename проверяет, является ли имя файла зарезервированным
func isReservedFilename(filename string) bool {
	// Получаем имя файла без расширения
	name := strings.ToLower(filename)
	if dotIndex := strings.LastIndex(name, "."); dotIndex != -1 {
		name = name[:dotIndex]
	}

	// Зарезервированные имена в Windows
	reservedNames := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	}

	for _, reserved := range reservedNames {
		if name == reserved {
			return true
		}
	}

	return false
}

// SanitizeFilename очищает имя файла
func SanitizeFilename(filename string) string {
	if filename == "" {
		return ""
	}

	// Удаление пробелов в начале и конце
	filename = strings.TrimSpace(filename)

	// Замена недопустимых символов
	replacements := map[string]string{
		"/":  "_",
		"\\": "_",
		"<":  "_",
		">":  "_",
		":":  "_",
		"\"": "_",
		"|":  "_",
		"?":  "_",
		"*":  "_",
		" ":  "_",
	}

	for old, new := range replacements {
		filename = strings.ReplaceAll(filename, old, new)
	}

	// Замена ".." на "_"
	for strings.Contains(filename, "..") {
		filename = strings.ReplaceAll(filename, "..", "_")
	}

	// Удаление точек в начале
	for strings.HasPrefix(filename, ".") {
		filename = filename[1:]
	}

	// Удаление точек в конце
	for strings.HasSuffix(filename, ".") {
		filename = filename[:len(filename)-1]
	}

	// Ограничение длины
	if len(filename) > 255 {
		filename = filename[:255]
	}

	// Удаление опасных Unicode-символов
	filename = SanitizeUnicode(filename)

	return filename
}

// NormalizeFilename нормализует имя файла
func NormalizeFilename(filename string) string {
	if filename == "" {
		return ""
	}

	// Базовая очистка
	filename = SanitizeFilename(filename)

	// Дополнительная нормализация
	filename = strings.ToLower(filename)

	// Удаление множественных подчеркиваний
	for strings.Contains(filename, "__") {
		filename = strings.ReplaceAll(filename, "__", "_")
	}

	// Удаление подчеркивания в начале и конце
	filename = strings.Trim(filename, "_")

	// Если имя файла стало пустым, используем значение по умолчанию
	if filename == "" {
		filename = "file"
	}

	return filename
}

// ValidateFileExtension проверяет расширение файла
func ValidateFileExtension(filename string, allowedExtensions []string, fieldName string) error {
	if len(allowedExtensions) == 0 {
		return nil // Если нет ограничений, разрешаем любое расширение
	}

	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		return ValidationError{
			Field:   fieldName,
			Message: "must have a file extension",
		}
	}

	// Удаляем точку из расширения
	ext = ext[1:]

	for _, allowed := range allowedExtensions {
		if strings.ToLower(allowed) == ext {
			return nil
		}
	}

	return ValidationError{
		Field:   fieldName,
		Message: "has an invalid file extension",
	}
}

// IsSafeFileExtension проверяет, является ли расширение файла безопасным
func IsSafeFileExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		return true // Файлы без расширения считаются безопасными
	}

	// Удаляем точку из расширения
	ext = ext[1:]

	// Список небезопасных расширений
	unsafeExtensions := []string{
		"exe", "bat", "cmd", "com", "pif", "scr", "vbs", "js", "jar",
		"sh", "ps1", "php", "asp", "aspx", "jsp", "py", "rb", "pl",
		"msi", "deb", "rpm", "dmg", "app", "pkg", "run", "bin",
	}

	for _, unsafe := range unsafeExtensions {
		if ext == unsafe {
			return false
		}
	}

	return true
}

// ValidateFileSize проверяет размер файла
func ValidateFileSize(size int64, maxSize int64, fieldName string) error {
	if size < 0 {
		return ValidationError{
			Field:   fieldName,
			Message: "has invalid size",
		}
	}

	if maxSize > 0 && size > maxSize {
		return ValidationError{
			Field:   fieldName,
			Message: "is too large",
		}
	}

	return nil
}

// ValidateFilenameList проверяет список имен файлов
func ValidateFilenameList(filenames []string, fieldName string) error {
	if len(filenames) == 0 {
		return ValidationError{
			Field:   fieldName,
			Message: "cannot be empty",
		}
	}

	for i, filename := range filenames {
		if !IsValidFilename(filename) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains invalid filename at position " + string(rune(i)),
			}
		}
	}

	return nil
}

// ValidateFilenameListStrict выполняет строгую проверку списка имен файлов
func ValidateFilenameListStrict(filenames []string, fieldName string) error {
	if len(filenames) == 0 {
		return ValidationError{
			Field:   fieldName,
			Message: "cannot be empty",
		}
	}

	for i, filename := range filenames {
		if !IsValidFilenameStrict(filename) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains invalid filename at position " + string(rune(i)),
			}
		}
	}

	return nil
}
