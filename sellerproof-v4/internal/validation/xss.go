package validation

import (
	"regexp"
	"strings"
)

// XSSPatterns содержит паттерны для обнаружения XSS-атак
var XSSPatterns = []string{
	"<script", "</script>", "javascript:", "vbscript:",
	"onload=", "onerror=", "onclick=", "onmouseover=",
	"onfocus=", "onblur=", "onchange=", "onsubmit=",
	"onreset=", "onselect=", "onunload=", "onabort=",
	"onkeydown=", "onkeyup=", "onkeypress=", "onmousedown=",
	"onmouseup=", "onmousemove=", "onmouseout=", "onmouseenter=",
	"onmouseleave=", "ondblclick=", "oncontextmenu=", "onwheel=",
	"oncut=", "oncopy=", "onpaste=", "ondrag=", "ondrop=",
	"eval(", "expression(", "url(", "import(", "link(",
	"meta ", "iframe ", "object ", "embed ", "form ",
	"input ", "textarea ", "button ", "select ", "option ",
	"alert(", "confirm(", "prompt(", "document.cookie",
	"document.write", "document.createElement", "window.location",
	"window.open", "setTimeout(", "setInterval(",
}

// XSSRegexPatterns содержит регулярные выражения для обнаружения XSS-атак
var XSSRegexPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
	regexp.MustCompile(`(?i)javascript\s*:`),
	regexp.MustCompile(`(?i)vbscript\s*:`),
	regexp.MustCompile(`(?i)on\w+\s*=`),
	regexp.MustCompile(`(?i)eval\s*\(`),
	regexp.MustCompile(`(?i)expression\s*\(`),
	regexp.MustCompile(`(?i)url\s*\(`),
	regexp.MustCompile(`(?i)@import`),
	regexp.MustCompile(`(?i)binding\s*:`),
	regexp.MustCompile(`(?i)<iframe[^>]*>`),
	regexp.MustCompile(`(?i)<object[^>]*>`),
	regexp.MustCompile(`(?i)<embed[^>]*>`),
	regexp.MustCompile(`(?i)<link[^>]*>`),
	regexp.MustCompile(`(?i)<meta[^>]*>`),
	regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`),
	regexp.MustCompile(`(?i)<form[^>]*>`),
	regexp.MustCompile(`(?i)alert\s*\(`),
	regexp.MustCompile(`(?i)confirm\s*\(`),
	regexp.MustCompile(`(?i)prompt\s*\(`),
	regexp.MustCompile(`(?i)document\.cookie`),
	regexp.MustCompile(`(?i)document\.write`),
	regexp.MustCompile(`(?i)window\.location`),
	regexp.MustCompile(`(?i)window\.open`),
}

// ContainsXSS проверяет наличие XSS-атак в строке
func ContainsXSS(input string) bool {
	if input == "" {
		return false
	}

	inputLower := strings.ToLower(input)

	// Проверяем простые паттерны
	for _, pattern := range XSSPatterns {
		if strings.Contains(input, pattern) || strings.Contains(inputLower, pattern) {
			return true
		}
	}

	// Проверяем регулярные выражения
	for _, regex := range XSSRegexPatterns {
		if regex.MatchString(input) {
			return true
		}
	}

	return false
}

// ValidateXSS выполняет валидацию XSS и возвращает ошибку
func ValidateXSS(input string, fieldName string) error {
	if ContainsXSS(input) {
		return ValidationError{
			Field:   fieldName,
			Message: "contains potentially dangerous content (XSS)",
		}
	}
	return nil
}

// ValidateXSSStrict выполняет строгую валидацию XSS
func ValidateXSSStrict(input string, fieldName string) error {
	if input == "" {
		return nil
	}

	// Дополнительные паттерны для строгой проверки
	strictPatterns := []string{
		"<", ">", "&", "\"", "'", "/", "\\",
		"=", "+", "-", "*", "%", "^", "|", "~",
		"`", "!", "@", "#", "$", "(", ")", "[", "]",
		"{", "}", ":", ";", ",", ".", "?",
	}

	inputLower := strings.ToLower(input)

	// Проверяем базовые паттерны
	for _, pattern := range XSSPatterns {
		if strings.Contains(input, pattern) || strings.Contains(inputLower, pattern) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains potentially dangerous content (XSS)",
			}
		}
	}

	// Проверяем регулярные выражения
	for _, regex := range XSSRegexPatterns {
		if regex.MatchString(input) {
			return ValidationError{
				Field:   fieldName,
				Message: "contains potentially dangerous content (XSS)",
			}
		}
	}

	// Проверяем строгие паттерны (только для HTML-подобного контента)
	if strings.Contains(input, "<") || strings.Contains(input, ">") {
		for _, pattern := range strictPatterns {
			if strings.Contains(input, pattern) {
				return ValidationError{
					Field:   fieldName,
					Message: "contains forbidden characters for HTML content",
				}
			}
		}
	}

	return nil
}

// SanitizeForHTML очищает строку для безопасного отображения в HTML
func SanitizeForHTML(input string) string {
	// Используем strings.NewReplacer для детерминированной замены за один проход.
	// Это предотвращает двойное экранирование (например, & -> &amp; -> &amp;amp;)
	// и гарантирует предсказуемый результат.
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#x27;",
	).Replace(input)
}

// SanitizeForAttribute очищает строку для безопасного использования в атрибутах HTML
func SanitizeForAttribute(input string) string {
	// Более строгое экранирование для атрибутов
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#x27;",
		"/", "&#x2F;",
		"=", "&#x3D;",
		"`", "&#x60;",
		"\n", "&#xA;",
		"\r", "&#xD;",
		"\t", "&#x9;",
	).Replace(input)
}
