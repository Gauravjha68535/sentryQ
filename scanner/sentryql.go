package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// SentryQLQuery is a parsed SentryQL query ready for execution.
// SentryQL is a lightweight declarative query language for expressing
// multi-condition vulnerability patterns.
//
// Grammar (case-insensitive):
//
//	FIND <regex> [IN source|function|class|import]
//	     [WHERE <regex> [AND <regex>]...]
//	     [AND NOT <regex>]*
//
// Semantics:
//   - WHERE p1 AND p2 AND p3 → all three must match in the ±5-line context window
//   - AND NOT n1 AND NOT n2  → none of the negations may match in the context window
//   - Multiple AND NOT clauses are chained implicitly
//
// Examples:
//
//	FIND exec\.Command WHERE os\.Stdin AND NOT args
//	FIND query\s*= WHERE request AND NOT prepared AND NOT parameterized
//	     AND NOT Exec\(query AND NOT sanitize
type SentryQLQuery struct {
	FindPattern  *regexp.Regexp
	Scope        string
	WherePatterns []*regexp.Regexp // ALL must match in context (AND logic)
	NotPatterns   []*regexp.Regexp // NONE may match in context (AND NOT logic)
	raw          string
}

// ParseSentryQL parses a SentryQL query string and returns a compiled query.
func ParseSentryQL(query string) (*SentryQLQuery, error) {
	if query == "" {
		return nil, fmt.Errorf("sentryql: empty query")
	}

	q := &SentryQLQuery{raw: query}
	rest := strings.TrimSpace(strings.ReplaceAll(query, "\n", " "))

	// Must start with FIND
	upper := strings.ToUpper(rest)
	if !strings.HasPrefix(upper, "FIND ") {
		return nil, fmt.Errorf("sentryql: query must start with FIND, got: %q", query)
	}
	rest = rest[5:] // skip "FIND "

	// ── Extract all AND NOT clauses (greedy from right to left) ──────────────
	// We repeatedly strip " AND NOT <pattern>" from the end so that chained
	// AND NOTs like "... AND NOT a AND NOT b" are all captured.
	for {
		notIdx := indexCaseInsensitive(rest, " AND NOT ")
		if notIdx < 0 {
			break
		}
		notPat := strings.TrimSpace(rest[notIdx+9:])
		rest = strings.TrimSpace(rest[:notIdx])
		// Only add if notPat does not itself contain AND NOT (handled in next loop iter)
		if !strings.Contains(strings.ToUpper(notPat), " AND NOT ") {
			re, err := regexp.Compile("(?i)" + notPat)
			if err != nil {
				return nil, fmt.Errorf("sentryql: invalid AND NOT pattern %q: %w", notPat, err)
			}
			q.NotPatterns = append(q.NotPatterns, re)
		}
	}

	// ── Extract optional "WHERE p1 AND p2 AND p3" ────────────────────────────
	whereIdx := indexCaseInsensitive(rest, " WHERE ")
	if whereIdx >= 0 {
		wherePart := strings.TrimSpace(rest[whereIdx+7:])
		rest = strings.TrimSpace(rest[:whereIdx])

		// Split the WHERE part on " AND " (not "AND NOT" — already stripped above)
		andParts := splitCaseInsensitive(wherePart, " AND ")
		for _, part := range andParts {
			pat := strings.TrimSpace(part)
			if pat == "" {
				continue
			}
			re, err := regexp.Compile("(?i)" + pat)
			if err != nil {
				return nil, fmt.Errorf("sentryql: invalid WHERE/AND pattern %q: %w", pat, err)
			}
			q.WherePatterns = append(q.WherePatterns, re)
		}
	}

	// ── Extract optional "IN <scope>" ────────────────────────────────────────
	inIdx := indexCaseInsensitive(rest, " IN ")
	if inIdx >= 0 {
		scope := strings.TrimSpace(rest[inIdx+4:])
		rest = strings.TrimSpace(rest[:inIdx])
		q.Scope = strings.ToLower(scope)
	} else {
		q.Scope = "source"
	}

	// ── Remaining text is the FIND pattern ───────────────────────────────────
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
// the (1-based) line numbers of matching lines.
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

		// Build context window once for this line (used by WHERE and AND NOT)
		ctx := contextWindow(lines, i, 5)

		// Apply WHERE conditions — ALL must match (AND logic)
		allMatch := true
		for _, wp := range q.WherePatterns {
			if !wp.MatchString(ctx) {
				allMatch = false
				break
			}
		}
		if !allMatch {
			continue
		}

		// Apply AND NOT negations — NONE may match
		suppressed := false
		for _, np := range q.NotPatterns {
			if np.MatchString(ctx) {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}

		matchingLines = append(matchingLines, lineNum)
	}

	return matchingLines
}

// splitCaseInsensitive splits s on sep (case-insensitive) and returns the parts.
func splitCaseInsensitive(s, sep string) []string {
	sepUp := strings.ToUpper(sep)
	sUp := strings.ToUpper(s)
	var parts []string
	for {
		idx := strings.Index(sUp, sepUp)
		if idx < 0 {
			parts = append(parts, s)
			break
		}
		parts = append(parts, s[:idx])
		s = s[idx+len(sep):]
		sUp = sUp[idx+len(sep):]
	}
	return parts
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
