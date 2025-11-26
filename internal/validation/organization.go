package validation

import (
	"fmt"
	"strings"
)

// sanitizeOrganizationInput performs normalization, invisible character stripping,
// optional length check, and SQLi/XSS/Unicode validation for organization fields.
func sanitizeOrganizationInput(value string, field string, required bool, minLen, maxLen int) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		if required {
			return "", ValidationError{Field: field, Message: "is required"}
		}
		return "", nil
	}

	sanitized := SanitizeUnicode(trimmed)

	if minLen > 0 && len([]rune(sanitized)) < minLen {
		return "", ValidationError{Field: field, Message: fmt.Sprintf("must be at least %d characters", minLen)}
	}
	if maxLen > 0 && len([]rune(sanitized)) > maxLen {
		return "", ValidationError{Field: field, Message: fmt.Sprintf("must be at most %d characters", maxLen)}
	}

	opts := CombineOptions(WithSQLInjectionCheck(), WithXSSCheck(), WithUnicodeSecurityCheck())
	if err := ValidateInputWithError(sanitized, field, opts); err != nil {
		return "", err
	}

	return sanitized, nil
}

// SanitizeOrganizationName normalizes and validates organization names (required 1-100 chars).
func SanitizeOrganizationName(name string) (string, error) {
	return sanitizeOrganizationInput(name, "name", true, 1, 100)
}

// SanitizeOrganizationDescription normalizes and validates organization descriptions (optional <=500 chars).
func SanitizeOrganizationDescription(desc string) (string, error) {
	return sanitizeOrganizationInput(desc, "description", false, 0, 500)
}
