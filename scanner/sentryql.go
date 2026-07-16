package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// SentryQLQuery is a parsed SentryQL query ready for execution.
// SentryQL is a lightweight declarative query language for expressing
// multi-condition vulnerability patterns:
//
//	FIND <pattern> IN <scope> [WHERE <condition>] [AND NOT <negation>]
//
// Scopes: "source", "function", "class", "import"
// Conditions are regex patterns applied to the matched line or its ±5-line context.
type SentryQLQuery struct {
	FindPattern  *regexp.Regexp
	Scope        string
	WherePattern *regexp.Regexp // optional filter condition
	NotPattern   *regexp.Regexp // optional negation condition
	raw          string
}

// ParseSentryQL parses a SentryQL query string and returns a compiled query.
// Returns an error if the query cannot be parsed or patterns cannot be compiled.
//
// Grammar (case-insensitive):
//
//	FIND <regex> [IN source|function|class|import] [WHERE <regex>] [AND NOT <regex>]
func ParseSentryQL(query string) (*SentryQLQuery, error) {
	if query == "" {
		return nil, fmt.Errorf("sentryql: empty query")
	}

	q := &SentryQLQuery{raw: query}
	rest := strings.TrimSpace(query)

	// Extract FIND pattern (mandatory)
	upper := strings.ToUpper(rest)
	if !strings.HasPrefix(upper, "FIND ") {
		return nil, fmt.Errorf("sentryql: query must start with FIND, got: %q", query)
	}
	rest = rest[5:] // skip "FIND "

	// Extract optional "AND NOT <pattern>" suffix first (so it doesn't confuse IN/WHERE)
	notIdx := indexCaseInsensitive(rest, " AND NOT ")
	if notIdx >= 0 {
		notPat := strings.TrimSpace(rest[notIdx+9:])
		rest = strings.TrimSpace(rest[:notIdx])
		re, err := regexp.Compile("(?i)" + notPat)
		if err != nil {
			return nil, fmt.Errorf("sentryql: invalid AND NOT pattern %q: %w", notPat, err)
		}
		q.NotPattern = re
	}

	// Extract optional "WHERE <pattern>"
	whereIdx := indexCaseInsensitive(rest, " WHERE ")
	if whereIdx >= 0 {
		wherePat := strings.TrimSpace(rest[whereIdx+7:])
		rest = strings.TrimSpace(rest[:whereIdx])
		re, err := regexp.Compile("(?i)" + wherePat)
		if err != nil {
			return nil, fmt.Errorf("sentryql: invalid WHERE pattern %q: %w", wherePat, err)
		}
		q.WherePattern = re
	}

	// Extract optional "IN <scope>"
	inIdx := indexCaseInsensitive(rest, " IN ")
	if inIdx >= 0 {
		scope := strings.TrimSpace(rest[inIdx+4:])
		rest = strings.TrimSpace(rest[:inIdx])
		q.Scope = strings.ToLower(scope)
	} else {
		q.Scope = "source" // default scope
	}

	// The remaining text is the FIND pattern
	findPat := strings.TrimSpace(rest)
	if findPat == "" {
		return nil, fmt.Errorf("sentryql: FIND pattern is empty in query: %q", query)
	}
	re, err := regexp.Compile("(?i)" + findPat)
	if err != nil {
		return nil, fmt.Errorf("sentryql: invalid FIND pattern %q: %w", findPat, err)
	}
	q.FindPattern = re

	return q, nil
}

// RunSentryQL executes a compiled SentryQL query against file content and returns
// the (1-based) line numbers of matching lines. The caller is responsible for
// converting these to reporter.Finding values.
func RunSentryQL(q *SentryQLQuery, filePath, content string) []int {
	if q == nil || q.FindPattern == nil {
		return nil
	}

	lines := strings.Split(content, "\n")
	var matchingLines []int

	for i, line := range lines {
		lineNum := i + 1

		// Apply scope filter
		if !sentryqlScopeMatch(q.Scope, line, lines, i) {
			continue
		}

		// Apply FIND pattern
		if !q.FindPattern.MatchString(line) {
			continue
		}

		// Apply WHERE condition (must ALSO match within ±5 line context)
		if q.WherePattern != nil {
			ctx := contextWindow(lines, i, 5)
			if !q.WherePattern.MatchString(ctx) {
				continue
			}
		}

		// Apply AND NOT negation (must NOT match in ±5 line context)
		if q.NotPattern != nil {
			ctx := contextWindow(lines, i, 5)
			if q.NotPattern.MatchString(ctx) {
				continue // suppressed by negation
			}
		}

		matchingLines = append(matchingLines, lineNum)
	}

	return matchingLines
}

// Package-level compiled regexes for sentryqlScopeMatch — compiled once, not per-line.
var (
	sentryqlFuncScopeRe   = regexp.MustCompile(`(?i)(func |def |function |public |private |protected )`)
	sentryqlClassScopeRe  = regexp.MustCompile(`(?i)(class |struct |interface )`)
	sentryqlImportScopeRe = regexp.MustCompile(`(?i)^(import |require\(|from |use |#include)`)
)

// sentryqlScopeMatch returns true if line belongs to the requested scope.
func sentryqlScopeMatch(scope, line string, lines []string, idx int) bool {
	switch scope {
	case "function":
		for j := idx; j >= 0 && j > idx-30; j-- {
			if sentryqlFuncScopeRe.MatchString(strings.TrimSpace(lines[j])) {
				return true
			}
		}
		return false
	case "class":
		for j := idx; j >= 0 && j > idx-50; j-- {
			if sentryqlClassScopeRe.MatchString(strings.TrimSpace(lines[j])) {
				return true
			}
		}
		return false
	case "import":
		return sentryqlImportScopeRe.MatchString(strings.TrimSpace(line))
	default:
		return true
	}
}

// contextWindow returns a string of lines[max(0,idx-n) .. min(len,idx+n+1)] joined by newlines.
func contextWindow(lines []string, idx, n int) string {
	start := idx - n
	if start < 0 {
		start = 0
	}
	end := idx + n + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// indexCaseInsensitive returns the first index of substr in s (case-insensitive), or -1.
func indexCaseInsensitive(s, substr string) int {
	sUp := strings.ToUpper(s)
	subUp := strings.ToUpper(substr)
	return strings.Index(sUp, subUp)
}
