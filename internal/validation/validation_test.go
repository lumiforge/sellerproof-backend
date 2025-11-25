package validation

import (
	"strings"
	"testing"
)

func TestContainsSQLInjection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Safe input", "hello world", false},
		{"SQL injection with quotes", "'; DROP TABLE users; --", true},
		{"SQL injection with UNION", "' UNION SELECT * FROM users", true},
		{"SQL injection with INSERT", "'; INSERT INTO users", true},
		{"SQL injection with exec", "EXEC xp_cmdshell", true},
		{"SQL injection with sleep", "SLEEP(5)", true},
		{"SQL injection with benchmark", "BENCHMARK(1000000,MD5(1))", true},
		{"SQL injection with time", "WAITFOR DELAY '00:00:05'", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsSQLInjection(tt.input)
			if result != tt.expected {
				t.Errorf("ContainsSQLInjection(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateSQLInjection(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		fieldName string
		wantErr   bool
	}{
		{"Valid input", "hello world", "comment", false},
		{"SQL injection", "'; DROP TABLE users; --", "comment", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSQLInjection(tt.input, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSQLInjection(%q, %q) error = %v; wantErr %v", tt.input, tt.fieldName, err, tt.wantErr)
			}
		})
	}
}

func TestContainsXSS(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Safe input", "hello world", false},
		{"Script tag", "<script>alert('xss')</script>", true},
		{"JavaScript protocol", "javascript:alert('xss')", true},
		{"Event handler", "onload='alert(\"xss\")'", true},
		{"Eval function", "eval('alert(\"xss\")')", true},
		{"Iframe", "<iframe src=\"javascript:alert('xss')\"></iframe>", true},
		{"Expression", "expression(alert('xss'))", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsXSS(tt.input)
			if result != tt.expected {
				t.Errorf("ContainsXSS(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateXSS(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		fieldName string
		wantErr   bool
	}{
		{"Valid input", "hello world", "comment", false},
		{"XSS attack", "<script>alert('xss')</script>", "comment", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateXSS(tt.input, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateXSS(%q, %q) error = %v; wantErr %v", tt.input, tt.fieldName, err, tt.wantErr)
			}
		})
	}
}

func TestContainsUnicodeAttack(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Safe input", "hello world", false},
		{"RTL override", "test\u202Etest", true},
		{"Zero-width character", "test\u200Btest", true},
		{"Homograph attack - simple", "tes\u0442", false},                   // Cyrillic 't' - now allowed for emails
		{"Homograph attack - mixed scripts dangerous", "admin\u0430", true}, // Cyrillic 'a' that looks like Latin 'a'
		{"Fullwidth characters", "ｔｅｓｔ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsUnicodeAttack(tt.input)
			if result != tt.expected {
				t.Errorf("ContainsUnicodeAttack(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateUnicodeSecurity(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		fieldName string
		wantErr   bool
	}{
		{"Valid input", "hello world", "comment", false},
		{"Unicode attack", "test\u202Etest", "comment", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUnicodeSecurity(tt.input, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUnicodeSecurity(%q, %q) error = %v; wantErr %v", tt.input, tt.fieldName, err, tt.wantErr)
			}
		})
	}
}

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{"Valid email", "user@example.com", true},
		{"Valid email with subdomain", "user@mail.example.com", true},
		{"Invalid email - no @", "userexample.com", false},
		{"Invalid email - no domain", "user@", false},
		{"Invalid email - no local", "@example.com", false},
		{"Invalid email - double @", "user@@example.com", false},
		{"Invalid email - spaces", "user @ example.com", false},
		{"Too long local part", strings.Repeat("a", 65) + "@example.com", false},
		{"Too long email", strings.Repeat("a", 255) + "@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidEmail(tt.email)
			if result != tt.expected {
				t.Errorf("IsValidEmail(%q) = %v; want %v", tt.email, result, tt.expected)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		fieldName string
		wantErr   bool
	}{
		{"Valid email", "user@example.com", "email", false},
		{"Invalid email", "userexample.com", "email", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail(%q, %q) error = %v; wantErr %v", tt.email, tt.fieldName, err, tt.wantErr)
			}
		})
	}
}

func TestIsValidFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		{"Valid filename", "document.pdf", true},
		{"Valid filename with extension", "image.jpeg", true},
		{"Invalid filename - path traversal", "../etc/passwd", false},
		{"Invalid filename - invalid chars", "file<name>.txt", false},
		{"Invalid filename - reserved", "CON", false},
		{"Invalid filename - empty", "", false},
		{"Too long filename", strings.Repeat("a", 256), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidFilename(tt.filename)
			if result != tt.expected {
				t.Errorf("IsValidFilename(%q) = %v; want %v", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestValidateFilename(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		fieldName string
		wantErr   bool
	}{
		{"Valid filename", "document.pdf", "filename", false},
		{"Invalid filename", "file<name>.txt", "filename", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilename(tt.filename, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilename(%q, %q) error = %v; wantErr %v", tt.filename, tt.fieldName, err, tt.wantErr)
			}
		})
	}
}

func TestIsValidContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{"Valid JSON", "application/json", true},
		{"Valid image", "image/jpeg", true},
		{"Valid text", "text/plain", true},
		{"Invalid content type", "invalid/type", false},
		{"Empty content type", "", false},
		{"Content type with charset", "application/json; charset=utf-8", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidContentType(tt.contentType)
			if result != tt.expected {
				t.Errorf("IsValidContentType(%q) = %v; want %v", tt.contentType, result, tt.expected)
			}
		})
	}
}

func TestValidateContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		fieldName   string
		wantErr     bool
	}{
		{"Valid content type", "application/json", "content_type", false},
		{"Invalid content type", "invalid/type", "content_type", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContentType(tt.contentType, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContentType(%q, %q) error = %v; wantErr %v", tt.contentType, tt.fieldName, err, tt.wantErr)
			}
		})
	}
}

func TestValidateInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		fieldName string
		options   ValidationOptions
		wantErr   bool
	}{
		{
			name:      "Valid input with no checks",
			input:     "hello world",
			fieldName: "comment",
			options:   ValidationOptions{},
			wantErr:   false,
		},
		{
			name:      "SQL injection with SQL check",
			input:     "'; DROP TABLE users; --",
			fieldName: "comment",
			options:   ValidationOptions{CheckSQLInjection: true},
			wantErr:   true,
		},
		{
			name:      "XSS attack with XSS check",
			input:     "<script>alert('xss')</script>",
			fieldName: "comment",
			options:   ValidationOptions{CheckXSS: true},
			wantErr:   true,
		},
		{
			name:      "Unicode attack with Unicode check",
			input:     "test\u202Etest",
			fieldName: "comment",
			options:   ValidationOptions{CheckUnicodeSecurity: true},
			wantErr:   true,
		},
		{
			name:      "Invalid email with email check",
			input:     "userexample.com",
			fieldName: "email",
			options:   ValidationOptions{CheckEmailFormat: true},
			wantErr:   true,
		},
		{
			name:      "Invalid filename with filename check",
			input:     "file<name>.txt",
			fieldName: "filename",
			options:   ValidationOptions{CheckFilenameSecurity: true},
			wantErr:   true,
		},
		{
			name:      "Multiple checks",
			input:     "<script>alert('xss')</script>",
			fieldName: "comment",
			options:   ValidationOptions{CheckSQLInjection: true, CheckXSS: true},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateInput(tt.input, tt.options)
			hasError := !result.IsValid
			if hasError != tt.wantErr {
				t.Errorf("ValidateInput(%q, options) IsValid = %v; wantErr %v", tt.input, result.IsValid, tt.wantErr)
			}
		})
	}
}


func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Safe filename",
			input:    "document.pdf",
			expected: "document.pdf",
		},
		{
			name:     "Invalid characters",
			input:    "file<name>.txt",
			expected: "file_name_.txt",
		},
		{
			name:     "Path traversal",
			input:    "../etc/passwd",
			expected: "__etc_passwd",
		},
		{
			name:     "Reserved name",
			input:    "CON",
			expected: "CON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeFilename(%q) = %q; want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkContainsSQLInjection(b *testing.B) {
	input := "'; DROP TABLE users; --"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ContainsSQLInjection(input)
	}
}

func BenchmarkContainsXSS(b *testing.B) {
	input := "<script>alert('xss')</script>"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ContainsXSS(input)
	}
}

func BenchmarkIsValidEmail(b *testing.B) {
	input := "user@example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidEmail(input)
	}
}

func BenchmarkIsValidFilename(b *testing.B) {
	input := "document.pdf"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidFilename(input)
	}
}
