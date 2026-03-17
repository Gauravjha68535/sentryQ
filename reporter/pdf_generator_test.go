package reporter

import (
	"testing"
)

func TestSanitizePDFText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ASCII only",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "em-dash",
			input:    "Test — Report",
			expected: "Test - Report",
		},
		{
			name:     "en-dash",
			input:    "Test – Report",
			expected: "Test - Report",
		},
		{
			name:     "smart single quotes",
			input:    "It's a test",
			expected: "It's a test",
		},
		{
			name:     "smart double quotes",
			input:    `"Hello World"`,
			expected: `"Hello World"`,
		},
		{
			name:     "ellipsis",
			input:    "Test…",
			expected: "Test...",
		},
		{
			name:     "bullet",
			input:    "• Item",
			expected: "* Item",
		},
		{
			name:     "non-breaking space",
			input:    "Hello\u00A0World",
			expected: "Hello World",
		},
		{
			name:     "mixed unicode",
			input:    "Hello — World 你好",
			expected: "Hello - World ??",
		},
		{
			name:     "control characters",
			input:    "Hello\x00World\x1FTest",
			expected: "HelloWorldTest",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "all common unicode",
			input:    `"It's a — test •"`,
			expected: `"It's a - test *"`,
		},
		{
			name:     "greek letters",
			input:    "αβγδ",
			expected: "????",
		},
		{
			name:     "cyrillic",
			input:    "Привет",
			expected: "??????",
		},
		{
			name:     "emoji",
			input:    "Hello 👋 World",
			expected: "Hello ? World",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizePDFText(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizePDFText(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizePDFTextPreservesASCII(t *testing.T) {
	// Ensure all ASCII characters are preserved
	ascii := ""
	for i := 32; i <= 126; i++ {
		ascii += string(rune(i))
	}

	result := sanitizePDFText(ascii)
	if result != ascii {
		t.Errorf("sanitizePDFText should preserve ASCII, got %q", result)
	}
}

func TestTruncateStringWithRunes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "short string",
			input:    "Hello",
			maxLen:   10,
			expected: "Hello",
		},
		{
			name:     "exact length",
			input:    "Hello",
			maxLen:   5,
			expected: "Hello",
		},
		{
			name:     "longer string",
			input:    "Hello World",
			maxLen:   5,
			expected: "Hello...",
		},
		{
			name:     "unicode characters",
			input:    "你好世界",
			maxLen:   3,
			expected: "你好世...",
		},
		{
			name:     "mixed ascii and unicode",
			input:    "Hello世界",
			maxLen:   5,
			expected: "Hello...",
		},
		{
			name:     "zero max length",
			input:    "Hello",
			maxLen:   0,
			expected: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}
