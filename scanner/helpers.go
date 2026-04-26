package scanner

import (
	"fmt"
	"regexp"
	"strings"

	treeSitter "github.com/smacker/go-tree-sitter"
)

// Pre-compiled regexes for StripComments (avoid recompiling per file)
var (
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reLineCommentC = regexp.MustCompile(`//.*`)
	reLineCommentH = regexp.MustCompile(`#.*`)
	reHTMLComment  = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// StripComments replaces comments with spaces to preserve line numbers/offsets.
//
// KNOWN LIMITATION: This function uses regex-based replacement without tracking
// string literal context. Comment delimiters inside string literals (e.g.
// url = "https://example.com") may be incorrectly treated as comments. A full
// state-machine parser would fix this but is not yet implemented. The pattern
// engine compensates by running regexes against the original source for URL-heavy
// rules and relying on the cleaned source only for code-structure patterns.
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



// buildNewlineIndices builds a slice of byte offsets for each newline in the source string.
// This allows O(log N) line number lookups for regex matches instead of O(N) string counts.
func buildNewlineIndices(source string) []int {
	var indices []int
	indices = append(indices, -1) // Virtual newline at start for 1-based indexing
	for i, i_byte := range []byte(source) {
		if i_byte == '\n' {
			indices = append(indices, i)
		}
	}
	indices = append(indices, len(source)) // Virtual newline at end
	return indices
}

// getLineNumber returns the 1-based line number for a given byte offset using binary search.
func getLineNumber(indices []int, offset int) int {
	low, high := 0, len(indices)-1
	for low <= high {
		mid := low + (high-low)/2
		if indices[mid] == offset {
			return mid // Line ends exactly at this offset
		}
		if indices[mid] < offset {
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return low // 'low' is the index of the interval containing the offset
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

// Pre-compiled regexes for user input detection (compiled once at startup)
var (
	userInputPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\breq\.`),
		regexp.MustCompile(`\brequest\.`),
		regexp.MustCompile(`\bhttp\.Request\b`),
		regexp.MustCompile(`\.form\[`),
		regexp.MustCompile(`\.query\[`),
		regexp.MustCompile(`\.params\[`),
		regexp.MustCompile(`\.postForm\[`),
		regexp.MustCompile(`\.Body\b`),
		regexp.MustCompile(`\.Form\[`),
		regexp.MustCompile(`\.PostForm\b`),
		regexp.MustCompile(`request\.form`),
		regexp.MustCompile(`request\.args`),
		regexp.MustCompile(`request\.values`),
		regexp.MustCompile(`flask\.request`),
		regexp.MustCompile(`django\.request`),
		regexp.MustCompile(`sys\.argv`),
		regexp.MustCompile(`os\.environ`),
		regexp.MustCompile(`os\.getenv`),
		regexp.MustCompile(`\binput\(`),
		regexp.MustCompile(`\breadline\(`),
		regexp.MustCompile(`req\.body`),
		regexp.MustCompile(`req\.query`),
		regexp.MustCompile(`req\.params`),
		regexp.MustCompile(`req\.cookies`),
		regexp.MustCompile(`express\.request`),
		regexp.MustCompile(`\.getQuery\(`),
		regexp.MustCompile(`\.getParam\(`),
		regexp.MustCompile(`\.getParameter\(`),
		regexp.MustCompile(`\.getQueryString\(`),
		regexp.MustCompile(`servletRequest\.`),
		regexp.MustCompile(`HttpServletRequest\.`),
		regexp.MustCompile(`\$_GET`),
		regexp.MustCompile(`\$_POST`),
		regexp.MustCompile(`\$_REQUEST`),
		regexp.MustCompile(`\$_COOKIE`),
		regexp.MustCompile(`\$_SERVER`),
		regexp.MustCompile(`params\[`),
		regexp.MustCompile(`request\[`),
		regexp.MustCompile(`env\[`),
		regexp.MustCompile(`r\.Form\[`),
		regexp.MustCompile(`r\.Body`),
		regexp.MustCompile(`r\.PostForm\[`),
	}
)

func containsUserInput(node *treeSitter.Node, content []byte) bool {
	if node == nil {
		return false
	}
	text := strings.ToLower(node.Content(content))

	// Use pre-compiled regex patterns for better performance
	for _, pattern := range userInputPatterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
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
	// Uses the package-level HighEntropyThreshold constant from secret_detector.go
	return calculateEntropy(s) > HighEntropyThreshold
}

func containsPattern(node *treeSitter.Node, content []byte, pattern string) bool {
	if node == nil {
		return false
	}
	return strings.Contains(node.Content(content), pattern)
}
