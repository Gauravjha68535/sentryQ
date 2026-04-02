package utils

import "strings"

// IsTestFile checks if the filePath looks like a test, mock, or fixture file.
// This is used across scanner and AI modules to avoid circular dependencies.
func IsTestFile(filePath string) bool {
	// Normalize to forward slashes so checks work on Windows too
	lowerPath := strings.ToLower(strings.ReplaceAll(filePath, "\\", "/"))
	testIndicators := []string{
		"_test.go", "test.js", "test.ts", "spec.js", "spec.ts",
		"/test/", "/tests/", "/testdata/", "/mock/", "/mocks/", "/fixture/",
		"/__tests__/", "/__mocks__/", "/node_modules/",
		"_test.py", "test_", "/spec/", "/specs/", "/fixtures/",
	}

	for _, indicator := range testIndicators {
		if strings.Contains(lowerPath, indicator) {
			return true
		}
	}
	return false
}
