package validation

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// UnicodeAttackPatterns содержит паттерны для обнаружения Unicode-атак
var UnicodeAttackPatterns = []*regexp.Regexp{
	// RTL override атаки
	regexp.MustCompile(`[\x{202A}-\x{202E}]`),
	// Поповка направления
	regexp.MustCompile(`[\x{2066}-\x{2069}]`),
	// Нулевые символы
	regexp.MustCompile(`[\x{200B}-\x{200F}]`),
	// Символы замены
	regexp.MustCompile(`[\x{FE00}-\x{FE0F}]`),
	// Различные специальные символы
	regexp.MustCompile(`[\x{FFF9}-\x{FFFB}]`),
	// Удаляем гомограф атаки из общих паттернов - будем проверять их в hasMixedScripts
	// Полноширинные символы
	regexp.MustCompile(`[\x{FF00}-\x{FFEF}]`),
	// Комбинируемые символы
	regexp.MustCompile(`[\x{0300}-\x{036F}]`),
	regexp.MustCompile(`[\x{1AB0}-\x{1AFF}]`),
	regexp.MustCompile(`[\x{20D0}-\x{20FF}]`),
}

// ContainsUnicodeAttack проверяет наличие Unicode-атак в строке
func ContainsUnicodeAttack(input string) bool {
	if input == "" {
		return false
	}

	// Проверяем с помощью регулярных выражений
	for _, pattern := range UnicodeAttackPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}

	// Дополнительные проверки
	if containsSuspiciousUnicode(input) {
		return true
	}

	return false
}

// ValidateUnicodeSecurity выполняет валидацию Unicode-атак и возвращает ошибку
func ValidateUnicodeSecurity(input string, fieldName string) error {
	if ContainsUnicodeAttack(input) {
		return ValidationError{
			Field:   fieldName,
			Message: "contains potentially dangerous Unicode characters",
		}
	}
	return nil
}

// containsSuspiciousUnicode выполняет дополнительные проверки Unicode-символов
func containsSuspiciousUnicode(input string) bool {
	// Проверяем на наличие смешанных скриптов (могут указывать на гомограф атаки)
	if hasMixedScripts(input) {
		return true
	}

	// Проверяем на наличие подозрительных комбинаций символов
	if hasSuspiciousCombinations(input) {
		return true
	}

	// Проверяем на наличие невидимых символов
	if hasInvisibleCharacters(input) {
		return true
	}

	return false
}

// hasMixedScripts проверяет наличие смешанных скриптов в строке
func hasMixedScripts(input string) bool {
	scripts := make(map[string]bool)

	for _, r := range input {
		if !unicode.IsControl(r) && !unicode.IsSpace(r) {
			script := getScript(r)
			if script != "" {
				scripts[script] = true
			}
		}
	}

	// Для имен файлов разрешаем:
	// 1. Один скрипт (например, только кириллица)
	// 2. Латиница + один другой скрипт (например, латиница + цифры, латиница + кириллица)
	// 3. Блокируем только если есть 3 или более разных скрипта И есть латиница
	if len(scripts) <= 2 {
		return false
	}

	// Если есть латиница и кириллица одновременно, это может быть гомограф атака
	// Но только если есть подозрительные комбинации (например, латинские слова с кириллическими буквами)
	if scripts["Latin"] && scripts["Cyrillic"] {
		// Проверяем на наличие символов кириллицы, похожих на латиницу
		// но только если они смешаны в одном слове с латиницей
		if hasMixedLatinCyrillicWords(input) {
			return true
		}
	}

	// Блокируем только если есть 3 или более разных скрипта И есть латиница
	return len(scripts) > 2 && scripts["Latin"]
}

// hasMixedLatinCyrillicWords проверяет, есть ли слова со смешанными латинскими и кириллическими буквами
func hasMixedLatinCyrillicWords(input string) bool {
	words := strings.Fields(input)
	for _, word := range words {
		if hasMixedScriptInWord(word) {
			return true
		}
	}
	return false
}

// hasMixedScriptInWord проверяет, есть ли в слове смешанные латинские и кириллические буквы
func hasMixedScriptInWord(word string) bool {
	hasLatin := false
	hasCyrillic := false
	hasHomograph := false

	for _, r := range word {
		if unicode.Is(unicode.Latin, r) {
			hasLatin = true
		}
		if unicode.Is(unicode.Cyrillic, r) {
			hasCyrillic = true
			if isCyrillicHomograph(r) {
				hasHomograph = true
			}
		}
	}

	// Блокируем только если есть и латиница, и кириллица, и есть гомографы
	return hasLatin && hasCyrillic && hasHomograph
}

// getScript определяет скрипт символа
func getScript(r rune) string {
	// Упрощенная проверка скриптов
	switch {
	case unicode.Is(unicode.Latin, r):
		return "Latin"
	case unicode.Is(unicode.Cyrillic, r):
		return "Cyrillic"
	case unicode.Is(unicode.Greek, r):
		return "Greek"
	case unicode.Is(unicode.Han, r):
		return "Han"
	case unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r):
		return "Japanese"
	case unicode.Is(unicode.Arabic, r):
		return "Arabic"
	case unicode.Is(unicode.Hebrew, r):
		return "Hebrew"
	case unicode.Is(unicode.Thai, r):
		return "Thai"
	case unicode.Is(unicode.Devanagari, r):
		return "Devanagari"
	default:
		return "Other"
	}
}

// isCyrillicHomograph проверяет, является ли кириллический символ гомографом (похожим на латиницу)
func isCyrillicHomograph(r rune) bool {
	cyrillicHomographs := []rune{
		'а', 'А', // латинское a, A
		'с', 'С', // латинское c, C
		'е', 'Е', // латинское e, E
		'о', 'О', // латинское o, O
		'р', 'Р', // латинское p, P
		'х', 'Х', // латинское x, X
		'у', 'У', // латинское y, Y
		'і', 'І', // латинское i, I
		'ј', 'Ј', // латинское j, J
		'ӏ', // латинское l
	}

	for _, homograph := range cyrillicHomographs {
		if r == homograph {
			return true
		}
	}
	return false
}

// hasSuspiciousCombinations проверяет наличие подозрительных комбинаций символов
func hasSuspiciousCombinations(input string) bool {
	// Проверяем на наличие символов, которые могут использоваться для обмана
	suspiciousChars := []rune{
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // RTL override
		0x2066, 0x2067, 0x2068, 0x2069, // Pop direction
		0x200B, 0x200C, 0x200D, 0x200E, 0x200F, // Zero-width characters
		0xFEFF, // BOM
	}

	for _, r := range input {
		for _, suspicious := range suspiciousChars {
			if r == suspicious {
				return true
			}
		}
	}

	return false
}

// hasInvisibleCharacters проверяет наличие невидимых символов
func hasInvisibleCharacters(input string) bool {
	for _, r := range input {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return true
		}
		if r == 0x200B || r == 0x200C || r == 0x200D { // Zero-width characters
			return true
		}
	}
	return false
}

// SanitizeUnicode очищает строку от опасных Unicode-символов
func SanitizeUnicode(input string) string {
	var result strings.Builder

	for _, r := range input {
		if !isDangerousUnicode(r) {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// isDangerousUnicode проверяет, является ли символ опасным
func isDangerousUnicode(r rune) bool {
	// Контрольные символы (кроме стандартных)
	if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
		return true
	}

	// RTL override и поповка направления
	if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
		return true
	}

	// Нулевые символы
	if r >= 0x200B && r <= 0x200F {
		return true
	}

	// Символы замены
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}

	// Специальные символы
	if r >= 0xFFF9 && r <= 0xFFFB {
		return true
	}

	// BOM
	if r == 0xFEFF {
		return true
	}

	return false
}

// ValidateFilenameUnicode выполняет валидацию Unicode для имен файлов
func ValidateFilenameUnicode(input string, fieldName string) error {
	if input == "" {
		return nil
	}

	// Проверяем длину имени файла (максимум 255 символов для файловой системы)
	if len(input) > 255 {
		return ValidationError{
			Field:   fieldName,
			Message: "is too long (maximum 255 characters)",
		}
	}

	// Проверяем на наличие опасных символов
	if ContainsUnicodeAttack(input) {
		return ValidationError{
			Field:   fieldName,
			Message: "contains potentially dangerous Unicode characters",
		}
	}

	// Проверяем на наличие символов, недопустимых в именах файлов
	if containsInvalidFilenameChars(input) {
		return ValidationError{
			Field:   fieldName,
			Message: "contains characters not allowed in filenames",
		}
	}

	// Проверяем на зарезервированные имена
	if isReservedFilename(input) {
		return ValidationError{
			Field:   fieldName,
			Message: "is a reserved filename",
		}
	}

	return nil
}

// containsInvalidFilenameChars проверяет наличие символов, недопустимых в именах файлов
func containsInvalidFilenameChars(input string) bool {
	invalidChars := []rune{
		'<', '>', ':', '"', '|', '?', '*', '\\', '/',
	}

	for _, r := range input {
		for _, invalid := range invalidChars {
			if r == invalid {
				return true
			}
		}

		// Проверяем только на контрольные символы (кроме стандартных whitespace)
		// Разрешаем все Unicode символы, включая кириллицу
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return true
		}
	}

	return false
}

// NormalizeUnicode нормализует Unicode-строку
func NormalizeUnicode(input string) string {
	// Простая нормализация - удаление опасных символов
	return SanitizeUnicode(input)
}

// IsValidUnicode проверяет, является ли строка валидной UTF-8 строкой
func IsValidUnicode(input string) bool {
	return utf8.ValidString(input)
}
