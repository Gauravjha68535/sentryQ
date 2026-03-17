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
