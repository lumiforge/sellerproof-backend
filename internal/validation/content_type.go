package validation

import (
	"mime"
	"strings"
)

// ValidContentTypes содержит список разрешенных Content-Type
var ValidContentTypes = map[string]bool{
	"application/json":                  true,
	"application/xml":                   true,
	"text/plain":                        true,
	"text/html":                         true,
	"text/css":                          true,
	"text/javascript":                   true,
	"application/javascript":            true,
	"application/x-www-form-urlencoded": true,
	"multipart/form-data":               true,
	"image/jpeg":                        true,
	"image/png":                         true,
	"image/gif":                         true,
	"image/webp":                        true,
	"image/svg+xml":                     true,
	"video/mp4":                         true,
	"video/webm":                        true,
	"video/quicktime":                   true,
	"audio/mpeg":                        true,
	"audio/wav":                         true,
	"audio/ogg":                         true,
	"application/pdf":                   true,
	"application/zip":                   true,
	"application/x-rar-compressed":      true,
	"application/x-7z-compressed":       true,
}

// SafeContentTypes содержит список безопасных Content-Type для загрузки
var SafeContentTypes = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"image/gif":       true,
	"image/webp":      true,
	"video/mp4":       true,
	"video/webm":      true,
	"video/quicktime": true,
	"audio/mpeg":      true,
	"audio/wav":       true,
	"audio/ogg":       true,
	"text/plain":      true,
	"application/pdf": true,
}

// IsValidContentType проверяет валидность Content-Type
func IsValidContentType(contentType string) bool {
	if contentType == "" {
		return false
	}

	// Нормализация Content-Type
	contentType = strings.ToLower(strings.TrimSpace(contentType))

	// Разделение на основной тип и подтип
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return false
	}

	mainType := strings.TrimSpace(parts[0])

	// Проверка основного типа
	return ValidContentTypes[mainType]
}

// ValidateContentType выполняет валидацию Content-Type и возвращает ошибку
func ValidateContentType(contentType string, fieldName string) error {
	if !IsValidContentType(contentType) {
		return ValidationError{
			Field:   fieldName,
			Message: "is not a valid content type",
		}
	}
	return nil
}

// IsSafeContentType проверяет, является ли Content-Type безопасным
func IsSafeContentType(contentType string) bool {
	if contentType == "" {
		return false
	}

	// Нормализация Content-Type
	contentType = strings.ToLower(strings.TrimSpace(contentType))

	// Разделение на основной тип и подтип
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return false
	}

	mainType := strings.TrimSpace(parts[0])

	// Проверка основного типа
	return SafeContentTypes[mainType]
}

// ValidateSafeContentType выполняет проверку безопасности Content-Type и возвращает ошибку
func ValidateSafeContentType(contentType string, fieldName string) error {
	if !IsSafeContentType(contentType) {
		return ValidationError{
			Field:   fieldName,
			Message: "is not a safe content type",
		}
	}
	return nil
}

// GetContentTypeFromExtension определяет Content-Type по расширению файла
func GetContentTypeFromExtension(filename string) string {
	if filename == "" {
		return ""
	}

	// Используем стандартную библиотеку для определения MIME типа
	contentType := mime.TypeByExtension(filename)
	if contentType != "" {
		return contentType
	}

	// Дополнительные расширения
	extensionMap := map[string]string{
		".webp":  "image/webp",
		".svg":   "image/svg+xml",
		".webm":  "video/webm",
		".woff":  "font/woff",
		".woff2": "font/woff2",
		".ttf":   "font/ttf",
		".eot":   "application/vnd.ms-fontobject",
	}

	// Получаем расширение файла
	dotIndex := strings.LastIndex(filename, ".")
	if dotIndex == -1 {
		return ""
	}

	extension := strings.ToLower(filename[dotIndex:])
	if contentType, exists := extensionMap[extension]; exists {
		return contentType
	}

	return ""
}

// ValidateContentTypeForExtension проверяет соответствие Content-Type расширению файла
func ValidateContentTypeForExtension(filename, contentType string, fieldName string) error {
	if filename == "" || contentType == "" {
		return ValidationError{
			Field:   fieldName,
			Message: "filename and content type cannot be empty",
		}
	}

	// Получаем ожидаемый Content-Type из расширения
	expectedContentType := GetContentTypeFromExtension(filename)
	if expectedContentType == "" {
		// Если не можем определить тип по расширению, пропускаем проверку
		return nil
	}

	// Нормализация Content-Type
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	expectedContentType = strings.ToLower(strings.TrimSpace(expectedContentType))

	// Разделение на основной тип и подтип
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return ValidationError{
			Field:   fieldName,
			Message: "has invalid content type format",
		}
	}

	mainContentType := strings.TrimSpace(parts[0])

	// Проверяем соответствие
	if mainContentType != expectedContentType {
		return ValidationError{
			Field:   fieldName,
			Message: "content type does not match file extension",
		}
	}

	return nil
}

// IsImageContentType проверяет, является ли Content-Type изображением
func IsImageContentType(contentType string) bool {
	if contentType == "" {
		return false
	}

	contentType = strings.ToLower(strings.TrimSpace(contentType))
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return false
	}

	mainType := strings.TrimSpace(parts[0])
	return strings.HasPrefix(mainType, "image/")
}

// IsVideoContentType проверяет, является ли Content-Type видео
func IsVideoContentType(contentType string) bool {
	if contentType == "" {
		return false
	}

	contentType = strings.ToLower(strings.TrimSpace(contentType))
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return false
	}

	mainType := strings.TrimSpace(parts[0])
	return strings.HasPrefix(mainType, "video/")
}

// IsAudioContentType проверяет, является ли Content-Type аудио
func IsAudioContentType(contentType string) bool {
	if contentType == "" {
		return false
	}

	contentType = strings.ToLower(strings.TrimSpace(contentType))
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return false
	}

	mainType := strings.TrimSpace(parts[0])
	return strings.HasPrefix(mainType, "audio/")
}

// IsTextContentType проверяет, является ли Content-Type текстовым
func IsTextContentType(contentType string) bool {
	if contentType == "" {
		return false
	}

	contentType = strings.ToLower(strings.TrimSpace(contentType))
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return false
	}

	mainType := strings.TrimSpace(parts[0])
	return strings.HasPrefix(mainType, "text/")
}

// IsApplicationContentType проверяет, является ли Content-Type приложением
func IsApplicationContentType(contentType string) bool {
	if contentType == "" {
		return false
	}

	contentType = strings.ToLower(strings.TrimSpace(contentType))
	parts := strings.Split(contentType, ";")
	if len(parts) == 0 {
		return false
	}

	mainType := strings.TrimSpace(parts[0])
	return strings.HasPrefix(mainType, "application/")
}

// ValidateContentTypeList проверяет список Content-Type
func ValidateContentTypeList(contentTypes []string, fieldName string) error {
	if len(contentTypes) == 0 {
		return ValidationError{
			Field:   fieldName,
			Message: "cannot be empty",
		}
	}

	for i, contentType := range contentTypes {
		if !IsValidContentType(contentType) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains invalid content type at position " + string(rune(i)),
			}
		}
	}

	return nil
}

// ValidateSafeContentTypeList проверяет список безопасных Content-Type
func ValidateSafeContentTypeList(contentTypes []string, fieldName string) error {
	if len(contentTypes) == 0 {
		return ValidationError{
			Field:   fieldName,
			Message: "cannot be empty",
		}
	}

	for i, contentType := range contentTypes {
		if !IsSafeContentType(contentType) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains unsafe content type at position " + string(rune(i)),
			}
		}
	}

	return nil
}

// SanitizeContentType очищает Content-Type
func SanitizeContentType(contentType string) string {
	if contentType == "" {
		return ""
	}

	// Удаление пробелов в начале и конце
	contentType = strings.TrimSpace(contentType)

	// Приведение к нижнему регистру
	contentType = strings.ToLower(contentType)

	// Удаление параметров (после ;)
	if semicolonIndex := strings.Index(contentType, ";"); semicolonIndex != -1 {
		contentType = contentType[:semicolonIndex]
	}

	// Удаление лишних пробелов
	contentType = strings.ReplaceAll(contentType, " ", "")

	return contentType
}

// NormalizeContentType нормализует Content-Type
func NormalizeContentType(contentType string) string {
	return SanitizeContentType(contentType)
}
