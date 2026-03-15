package scanner

import (
	"fmt"
	"regexp"
	"strings"

	treeSitter "github.com/smacker/go-tree-sitter"
)

// IsTestFile checks if the filePath looks like a test or mock file
func IsTestFile(filePath string) bool {
	// Normalize to forward slashes so checks work on Windows too
	lowerPath := strings.ToLower(strings.ReplaceAll(filePath, "\\", "/"))
	if strings.Contains(lowerPath, "_test.go") ||
		strings.Contains(lowerPath, "/test/") ||
		strings.Contains(lowerPath, "/tests/") ||
		strings.Contains(lowerPath, "/mock/") ||
		strings.Contains(lowerPath, "/fixture/") ||
		strings.Contains(lowerPath, "__test__") ||
		strings.Contains(lowerPath, "test.js") ||
		strings.Contains(lowerPath, "test.ts") ||
		strings.Contains(lowerPath, "spec.js") ||
		strings.Contains(lowerPath, "spec.ts") {
		return true
	}
	return false
}

// Pre-compiled regexes for StripComments (avoid recompiling per file)
var (
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reLineCommentC = regexp.MustCompile(`//.*`)
	reLineCommentH = regexp.MustCompile(`#.*`)
	reHTMLComment  = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// StripComments replaces comments with spaces to preserve line numbers/offsets
func StripComments(source string, ext string) string {
	ext = strings.ToLower(ext)

	replacer := func(match string) string {
		result := make([]byte, len(match))
		for i, b := range []byte(match) {
			if b == '\n' || b == '\r' {
				result[i] = b
			} else {
				result[i] = ' '
			}
		}
		return string(result)
	}

	switch ext {
	case ".go", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".php", ".swift", ".kt", ".dart", ".scala", ".rs":
		source = reBlockComment.ReplaceAllStringFunc(source, replacer)
		source = reLineCommentC.ReplaceAllStringFunc(source, replacer)
	case ".py", ".rb", ".sh", ".bash", ".yaml", ".yml", ".dockerfile", ".tf", ".pl":
		source = reLineCommentH.ReplaceAllStringFunc(source, replacer)
	case ".html", ".xml", ".vue":
		source = reHTMLComment.ReplaceAllStringFunc(source, replacer)
	}

	return source
}

func countLines(s string) int {
	return strings.Count(s, "\n")
}

func formatLineRef(start, end int) string {
	if start == end {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func containsStringFormatting(node *treeSitter.Node, content []byte) bool {
	if node == nil {
		return false
	}
	text := node.Content(content)
	return strings.Contains(text, "%") || strings.Contains(text, ".format") || strings.Contains(text, "f\"") || strings.Contains(text, "f'") || strings.Contains(text, "+")
}

func containsUserInput(node *treeSitter.Node, content []byte) bool {
	if node == nil {
		return false
	}
	text := strings.ToLower(node.Content(content))
	return strings.Contains(text, "req") || strings.Contains(text, "sys.argv") || strings.Contains(text, "input") || strings.Contains(text, "param")
}

func isSecretVariableName(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "token") || strings.Contains(lower, "credential")
}

func isHardcodedValue(value string) bool {
	return strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") || strings.HasPrefix(value, "`")
}

func stripQuotes(s string) string {
	return strings.Trim(s, "\"'`")
}

func hasHighEntropy(s string) bool {
	// calculateEntropy is in secret_detector.go and available in the scanner package
	return calculateEntropy(s) > 4.5
}

func containsPattern(node *treeSitter.Node, content []byte, pattern string) bool {
	if node == nil {
		return false
	}
	return strings.Contains(node.Content(content), pattern)
}
