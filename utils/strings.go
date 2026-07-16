package utils

import (
	"fmt"
	"strings"
)

// NormalizeNewlines safely converts Windows "\r\n" and classic macOS "\r" to standard Unix "\n".
// This prevents cross-platform parsing issues in String matching and AI prompt payloads.
func NormalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

// TruncateString truncates s to at most maxLen Unicode code points, appending "..." if cut.
// Using rune-based slicing prevents splitting multi-byte UTF-8 characters.
func TruncateString(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// ParseStartLine extracts the leading integer from a line reference like "42" or "42-45".
// Returns 0 if no integer can be parsed. Canonical implementation shared across all
// packages — replaces parseLineNum (fp_suppressor), parseStartLine (scan_manager),
// and parseFirstLine (pr_decorator).
func ParseStartLine(lineRef string) int {
	var n int
	fmt.Sscanf(strings.SplitN(lineRef, "-", 2)[0], "%d", &n)
	return n
}
