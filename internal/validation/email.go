package validation

import (
	"regexp"
	"strings"
	"unicode"
)

// EmailRegex содержит регулярное выражение для валидации email
var EmailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// StrictEmailRegex содержит строгое регулярное выражение для валидации email
var StrictEmailRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$`)

// IsValidEmail проверяет валидность email адреса
func IsValidEmail(email string) bool {
	if email == "" {
		return false
	}

	// Базовая проверка с помощью регулярного выражения
	if !EmailRegex.MatchString(email) {
		return false
	}

	// Дополнительные проверки
	if !isValidEmailFormat(email) {
		return false
	}

	return true
}

// IsValidEmailStrict выполняет строгую проверку email адреса
func IsValidEmailStrict(email string) bool {
	if email == "" {
		return false
	}

	// Строгая проверка с помощью регулярного выражения
	if !StrictEmailRegex.MatchString(email) {
		return false
	}

	// Дополнительные проверки
	if !isValidEmailFormat(email) {
		return false
	}

	// Дополнительные строгие проверки
	if !isValidEmailStrictFormat(email) {
		return false
	}

	return true
}

// ValidateEmail выполняет валидацию email и возвращает ошибку
func ValidateEmail(email string, fieldName string) error {
	if !IsValidEmail(email) {
		return ValidationError{
			Field:   fieldName,
			Message: "is not a valid email address",
		}
	}

	// Дополнительная проверка на опасные Unicode символы (но не все Unicode)
	if containsDangerousUnicodeInEmail(email) {
		return ValidationError{
			Field:   fieldName,
			Message: "contains potentially dangerous Unicode characters",
		}
	}

	return nil
}

// ValidateEmailStrict выполняет строгую валидацию email и возвращает ошибку
func ValidateEmailStrict(email string, fieldName string) error {
	if !IsValidEmailStrict(email) {
		return ValidationError{
			Field:   fieldName,
			Message: "is not a valid email address",
		}
	}
	return nil
}

// isValidEmailFormat выполняет дополнительные проверки формата email
func isValidEmailFormat(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))

	// Проверка длины
	if len(email) > 254 {
		return false
	}

	// Разделение на локальную часть и домен
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	local := parts[0]
	domain := parts[1]

	// Проверка локальной части
	if len(local) == 0 || len(local) > 64 {
		return false
	}

	// Проверка домена
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Проверка на наличие точек в начале или конце локальной части
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") {
		return false
	}

	// Проверка на наличие двух точек подряд в локальной части
	if strings.Contains(local, "..") {
		return false
	}

	// Проверка на наличие недопустимых символов
	if !isValidLocalPart(local) {
		return false
	}

	// Проверка домена
	if !isValidDomain(domain) {
		return false
	}

	return true
}

// isValidEmailStrictFormat выполняет строгие проверки формата email
func isValidEmailStrictFormat(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))

	parts := strings.Split(email, "@")
	local := parts[0]
	domain := parts[1]

	// Строгая проверка локальной части
	if !isValidLocalPartStrict(local) {
		return false
	}

	// Строгая проверка домена
	if !isValidDomainStrict(domain) {
		return false
	}

	return true
}

// isValidLocalPart проверяет валидность локальной части email
func isValidLocalPart(local string) bool {
	if local == "" {
		return false
	}

	// Проверка на наличие недопустимых символов
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-+"
	for _, r := range local {
		if !strings.ContainsRune(validChars, r) {
			return false
		}
	}

	return true
}

// isValidLocalPartStrict выполняет строгую проверку локальной части email
func isValidLocalPartStrict(local string) bool {
	if local == "" {
		return false
	}

	// Локальная часть должна начинаться и заканчиваться буквой или цифрой
	first := local[0]
	last := local[len(local)-1]
	if !unicode.IsLetter(rune(first)) && !unicode.IsDigit(rune(first)) {
		return false
	}
	if !unicode.IsLetter(rune(last)) && !unicode.IsDigit(rune(last)) {
		return false
	}

	// Проверка на наличие двух точек подряд
	if strings.Contains(local, "..") {
		return false
	}

	// Проверка на наличие точки в начале или конце
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") {
		return false
	}

	// Проверка на наличие дефиса в начале или конце
	if strings.HasPrefix(local, "-") || strings.HasSuffix(local, "-") {
		return false
	}

	return true
}

// isValidDomain проверяет валидность домена
func isValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// Проверка на наличие недопустимых символов
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
	for _, r := range domain {
		if !strings.ContainsRune(validChars, r) {
			return false
		}
	}

	// Проверка на наличие двух точек подряд
	if strings.Contains(domain, "..") {
		return false
	}

	// Проверка на наличие точки в начале или конце
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	// Проверка на наличие дефиса в начале или конце
	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return false
	}

	return true
}

// isValidDomainStrict выполняет строгую проверку домена
func isValidDomainStrict(domain string) bool {
	if domain == "" {
		return false
	}

	// Разделение домена на части
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	// Проверка каждой части домена
	for _, part := range parts {
		if part == "" {
			return false
		}

		// Проверка на наличие недопустимых символов
		validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
		for _, r := range part {
			if !strings.ContainsRune(validChars, r) {
				return false
			}
		}

		// Проверка на наличие дефиса в начале или конце
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}

		// Проверка длины части домена
		if len(part) > 63 {
			return false
		}
	}

	// Проверка TLD (последней части)
	tld := parts[len(parts)-1]
	if len(tld) < 2 {
		return false
	}

	// TLD должен содержать только буквы
	for _, r := range tld {
		if !unicode.IsLetter(r) {
			return false
		}
	}

	return true
}

// SanitizeEmail очищает email адрес
func SanitizeEmail(email string) string {
	// Удаление пробелов в начале и конце
	email = strings.TrimSpace(email)

	// Приведение к нижнему регистру
	email = strings.ToLower(email)

	// Удаление лишних пробелов
	email = strings.ReplaceAll(email, " ", "")

	return email
}

// NormalizeEmail нормализует email адрес
func NormalizeEmail(email string) string {
	// Базовая очистка
	email = SanitizeEmail(email)

	// Дополнительная нормализация
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	local := parts[0]
	domain := parts[1]

	// Удаление точек из локальной части (для Gmail и некоторых других сервисов)
	// Это может быть настроено в зависимости от требований
	local = strings.ReplaceAll(local, ".", "")

	// Удаление тегов (+tag)
	if plusIndex := strings.Index(local, "+"); plusIndex != -1 {
		local = local[:plusIndex]
	}

	return local + "@" + domain
}

// ValidateEmailList проверяет список email адресов
func ValidateEmailList(emails []string, fieldName string) error {
	if len(emails) == 0 {
		return ValidationError{
			Field:   fieldName,
			Message: "cannot be empty",
		}
	}

	for i, email := range emails {
		if !IsValidEmail(email) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains invalid email at position " + string(rune(i)),
			}
		}
	}

	return nil
}

// ValidateEmailListStrict выполняет строгую проверку списка email адресов
func ValidateEmailListStrict(emails []string, fieldName string) error {
	if len(emails) == 0 {
		return ValidationError{
			Field:   fieldName,
			Message: "cannot be empty",
		}
	}

	for i, email := range emails {
		if !IsValidEmailStrict(email) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains invalid email at position " + string(rune(i)),
			}
		}
	}

	return nil
}

// containsDangerousUnicodeInEmail проверяет наличие опасных Unicode символов в email
func containsDangerousUnicodeInEmail(email string) bool {
	for _, r := range email {
		// Проверяем только действительно опасные символы, которые могут использоваться для атак
		// Исключаем большинство нормальных Unicode символов, которые могут быть в email

		// Zero-width characters (эти действительно опасные)
		if r == 0x200B || r == 0x200C || r == 0x200D || r == 0x200E || r == 0x200F {
			return true
		}

		// BOM (опасный)
		if r == 0xFEFF {
			return true
		}

		// Control characters (кроме стандартных \n, \r, \t)
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return true
		}
	}
	return false
}
