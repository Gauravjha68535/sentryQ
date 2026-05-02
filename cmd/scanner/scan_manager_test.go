package main

import (
	"testing"
)

func TestIsValidGitURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://github.com/user/repo.git", true},
		{"http://gitlab.com/user/repo", true},
		{"git@github.com:user/repo.git", true},
		{"ssh://git@github.com/user/repo.git", true},
		{"--upload-pack=touch /tmp/pwned", false},
		{"-oProxyCommand=touch /tmp/pwned", false},
		{"   ", false},
		{"ftp://example.com/repo", false},
	}

	for _, tt := range tests {
		result := isValidGitURL(tt.url)
		if result != tt.expected {
			t.Errorf("isValidGitURL(%q) = %v, want %v", tt.url, result, tt.expected)
		}
	}
}

func TestSanitizeGitOutput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Cloning into 'repo'...", "Cloning into 'repo'..."},
		{"https://user:pass123@github.com/repo", "https://***:***@github.com/repo"},
		{"fatal: could not read Password for 'https://gaurav:mysecret@gitlab.com':", "fatal: could not read Password for 'https://***:***@gitlab.com':"},
	}

	for _, tt := range tests {
		result := sanitizeGitOutput(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeGitOutput(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseStartLine(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"42", 42},
		{"42-50", 42},
		{"12", 12},
		{"-5", 0},
		{"abc", 0},
		{"", 0},
	}

	for _, tt := range tests {
		result := parseStartLine(tt.input)
		if result != tt.expected {
			t.Errorf("parseStartLine(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestIsTrivialLine(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"}", true},
		{"   }   ", true},
		{"]", true},
		{"  ];  ", true},
		{")", true},
		{"", true},
		{"   ", true},
		{"// comment", true},
		{"/* comment */", true},
		{"func main() {", false},
		{"x = y + 1", false},
		{"if (true) {", false},
		{"return", false},
		{"break;", false},
	}

	for _, tt := range tests {
		result := isTrivialLine(tt.input)
		if result != tt.expected {
			t.Errorf("isTrivialLine(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}
