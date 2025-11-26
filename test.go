package main

import (
	"fmt"

	"github.com/lumiforge/sellerproof-backend/internal/validation"
)

func main() {
	// Test cases
	testCases := []struct {
		name     string
		expected string // "DETECTED" or "ALLOWED"
	}{
		{"vidеo.mp4", "DETECTED"},  // Cyrillic 'е' instead of Latin 'e' - HOMOGRAPH ATTACK
		{"gοοgle.mp4", "DETECTED"}, // Greek 'ο' instead of Latin 'o' - HOMOGRAPH ATTACK
		{"video.mр4", "DETECTED"},  // Cyrillic 'р' instead of Latin 'p' - HOMOGRAPH ATTACK
		{"видео.мп4", "ALLOWED"},   // Pure Cyrillic - SHOULD BE ALLOWED
		{"βιδεο.μπ4", "ALLOWED"},   // Pure Greek - SHOULD BE ALLOWED
		{"видео.mp4", "DETECTED"},  // Mixed Cyrillic + Latin (m,p) - HOMOGRAPH ATTACK
	}

	fmt.Println("Testing homograph attack detection:")
	for _, tc := range testCases {
		fmt.Printf("Testing: %s (Expected: %s)\n", tc.name, tc.expected)

		// Test ValidateFilenameUnicode
		err := validation.ValidateFilenameUnicode(tc.name, "file_name")
		if err != nil {
			if tc.expected == "DETECTED" {
				fmt.Printf("  ✓ ValidateFilenameUnicode: DETECTED - %s\n", err.Error())
			} else {
				fmt.Printf("  ✗ ValidateFilenameUnicode: UNEXPECTEDLY DETECTED - %s\n", err.Error())
			}
		} else {
			if tc.expected == "ALLOWED" {
				fmt.Printf("  ✓ ValidateFilenameUnicode: ALLOWED\n")
			} else {
				fmt.Printf("  ✗ ValidateFilenameUnicode: UNEXPECTEDLY ALLOWED\n")
			}
		}

		// Test ContainsUnicodeAttack
		detected := validation.ContainsUnicodeAttack(tc.name)
		if detected {
			if tc.expected == "DETECTED" {
				fmt.Printf("  ✓ ContainsUnicodeAttack: DETECTED\n")
			} else {
				fmt.Printf("  ✗ ContainsUnicodeAttack: UNEXPECTEDLY DETECTED\n")
			}
		} else {
			if tc.expected == "ALLOWED" {
				fmt.Printf("  ✓ ContainsUnicodeAttack: ALLOWED\n")
			} else {
				fmt.Printf("  ✗ ContainsUnicodeAttack: UNEXPECTEDLY ALLOWED\n")
			}
		}

		fmt.Println()
	}

	fmt.Println("\nSummary:")
	allPassed := true
	for _, tc := range testCases {
		err := validation.ValidateFilenameUnicode(tc.name, "file_name")
		detected := validation.ContainsUnicodeAttack(tc.name)

		expectedDetected := tc.expected == "DETECTED"
		actualDetected := err != nil || detected

		if expectedDetected != actualDetected {
			allPassed = false
			fmt.Printf("✗ FAILED: %s - Expected %s, got %s\n", tc.name, tc.expected, map[bool]string{true: "DETECTED", false: "ALLOWED"}[actualDetected])
		} else {
			fmt.Printf("✓ PASSED: %s\n", tc.name)
		}
	}

	if allPassed {
		fmt.Println("🎉 All tests PASSED! Homograph attacks are correctly detected while allowing legitimate non-ASCII filenames.")
	} else {
		fmt.Println("❌ Some tests FAILED!")
	}
}
