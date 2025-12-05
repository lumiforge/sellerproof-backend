package validation

import (
	"fmt"
	"strings"
)

// ValidationResult представляет результат валидации
type ValidationResult struct {
	IsValid bool     `json:"is_valid"`
	Errors  []string `json:"errors,omitempty"`
}

// ValidationError представляет ошибку валидации
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error реализует интерфейс error
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error in field '%s': %s", e.Field, e.Message)
}

// ValidationOptions представляет опции валидации
type ValidationOptions struct {
	CheckSQLInjection     bool
	CheckXSS              bool
	CheckUnicodeSecurity  bool
	CheckEmailFormat      bool
	CheckFilenameSecurity bool
}

// DefaultValidationOptions возвращает опции валидации по умолчанию
func DefaultValidationOptions() ValidationOptions {
	return ValidationOptions{
		CheckSQLInjection:     true,
		CheckXSS:              true,
		CheckUnicodeSecurity:  true,
		CheckEmailFormat:      false,
		CheckFilenameSecurity: false,
	}
}

// ValidateInput выполняет комплексную валидацию входных данных
func ValidateInput(input string, options ValidationOptions) ValidationResult {
	result := ValidationResult{
		IsValid: true,
		Errors:  make([]string, 0),
	}

	if options.CheckSQLInjection && ContainsSQLInjection(input) {
		result.IsValid = false
		result.Errors = append(result.Errors, "input contains potential SQL injection")
	}

	if options.CheckXSS && ContainsXSS(input) {
		result.IsValid = false
		result.Errors = append(result.Errors, "input contains potential XSS attack")
	}

	if options.CheckUnicodeSecurity && ContainsUnicodeAttack(input) {
		result.IsValid = false
		result.Errors = append(result.Errors, "input contains potential Unicode security attack")
	}

	if options.CheckEmailFormat && !IsValidEmail(input) {
		result.IsValid = false
		result.Errors = append(result.Errors, "invalid email format")
	}

	if options.CheckFilenameSecurity && !IsValidFilename(input) {
		result.IsValid = false
		result.Errors = append(result.Errors, "invalid filename format")
	}

	return result
}

// ValidateInputWithError выполняет валидацию и возвращает ошибку
func ValidateInputWithError(input string, fieldName string, options ValidationOptions) error {
	result := ValidateInput(input, options)
	if !result.IsValid {
		return ValidationError{
			Field:   fieldName,
			Message: strings.Join(result.Errors, "; "),
		}
	}
	return nil
}

// Функции-конструкторы для опций валидации
func WithSQLInjectionCheck() ValidationOptions {
	opts := ValidationOptions{} // Пустые опции, не по умолчанию
	opts.CheckSQLInjection = true
	return opts
}

func WithXSSCheck() ValidationOptions {
	opts := ValidationOptions{} // Пустые опции, не по умолчанию
	opts.CheckXSS = true
	return opts
}

func WithUnicodeSecurityCheck() ValidationOptions {
	opts := ValidationOptions{} // Пустые опции, не по умолчанию
	opts.CheckUnicodeSecurity = true
	return opts
}

func WithEmailCheck() ValidationOptions {
	opts := ValidationOptions{} // Пустые опции, не по умолчанию
	opts.CheckEmailFormat = true
	return opts
}

func WithFilenameCheck() ValidationOptions {
	opts := ValidationOptions{} // Пустые опции, не по умолчанию
	opts.CheckFilenameSecurity = true
	return opts
}

// CombineOptions объединяет несколько опций валидации
func CombineOptions(options ...ValidationOptions) ValidationOptions {
	result := ValidationOptions{} // Начинаем с пустых опций, не по умолчанию
	for _, opt := range options {
		if opt.CheckSQLInjection {
			result.CheckSQLInjection = true
		}
		if opt.CheckXSS {
			result.CheckXSS = true
		}
		if opt.CheckUnicodeSecurity {
			result.CheckUnicodeSecurity = true
		}
		if opt.CheckEmailFormat {
			result.CheckEmailFormat = true
		}
		if opt.CheckFilenameSecurity {
			result.CheckFilenameSecurity = true
		}
	}
	return result
}
