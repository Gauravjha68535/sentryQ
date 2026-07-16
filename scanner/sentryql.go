package scanner

// SentryQL — a minimal declarative query language for expressing vulnerability patterns.
//
// Syntax:
//   FIND <target> WHERE <condition> [AND <condition>...] [REPORT AS <severity>] [MESSAGE <text>]
//
// Targets:
//   function_call(<name>)   — any call to the named function
//   variable(<name>)        — any variable with this name pattern
//   string_literal          — any string literal
//   file(<ext>)             — restrict to files with this extension
//
// Conditions:
//   tainted_by(<source>)            — argument flows from HTTP/user input
//   not_sanitized_by(<func>)        — argument did NOT pass through sanitizer func
//   matches(<regex>)                — snippet matches the regex
//   in_file(<ext>)                  — file has this extension
//   severity(<level>)               — only when finding severity >= level
//
// Example:
//   FIND function_call(execute) WHERE tainted_by(request) AND not_sanitized_by(escape)
//       REPORT AS critical MESSAGE "Unsanitized SQL execution"

import (
	"fmt"
	"regexp"
	"strings"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// SentryQLQuery is a parsed SentryQL query.
type SentryQLQuery struct {
	Target     SentryQLTarget
	Conditions []SentryQLCondition
	ReportAs   string
	Message    string
	ID         string
}

type SentryQLTarget struct {
	Kind string // "function_call", "variable", "string_literal", "file"
	Name string // function/variable name pattern (may be a regex)
}

type SentryQLCondition struct {
	Type  string // "tainted_by", "not_sanitized_by", "matches", "in_file"
	Value string
}

// sentryqlTokenRe matches keyword:value pairs.
var (
	sentryqlFindRe    = regexp.MustCompile(`(?i)^FIND\s+(\w+)\(([^)]*)\)`)
	sentryqlWhereRe   = regexp.MustCompile(`(?i)WHERE\s+(.+?)(?:REPORT|MESSAGE|$)`)
	sentryqlReportRe  = regexp.MustCompile(`(?i)REPORT\s+AS\s+(\w+)`)
	sentryqlMessageRe = regexp.MustCompile(`(?i)MESSAGE\s+"([^"]+)"`)
	sentryqlCondRe    = regexp.MustCompile(`(?i)(tainted_by|not_sanitized_by|matches|in_file)\(([^)]+)\)`)
)

// ParseSentryQL parses a SentryQL query string into a structured query.
func ParseSentryQL(id, query string) (*SentryQLQuery, error) {
	q := &SentryQLQuery{ID: id, ReportAs: "medium"}

	findM := sentryqlFindRe.FindStringSubmatch(query)
	if findM == nil {
		return nil, fmt.Errorf("SentryQL: missing FIND clause in query %q", id)
	}
	q.Target = SentryQLTarget{
		Kind: strings.ToLower(findM[1]),
		Name: strings.TrimSpace(findM[2]),
	}

	whereM := sentryqlWhereRe.FindStringSubmatch(query)
	if whereM != nil {
		condMatches := sentryqlCondRe.FindAllStringSubmatch(whereM[1], -1)
		for _, cm := range condMatches {
			q.Conditions = append(q.Conditions, SentryQLCondition{
				Type:  strings.ToLower(cm[1]),
				Value: strings.TrimSpace(cm[2]),
			})
		}
	}

	if m := sentryqlReportRe.FindStringSubmatch(query); m != nil {
		q.ReportAs = strings.ToLower(m[1])
	}
	if m := sentryqlMessageRe.FindStringSubmatch(query); m != nil {
		q.Message = m[1]
	}

	return q, nil
}

// RunSentryQL executes a parsed SentryQL query against the contents of a file
// and returns any findings.
func RunSentryQL(q *SentryQLQuery, filePath string, lines []string, crossFileIdx *CrossFileIndex) []reporter.Finding {
	// Check file extension condition first
	for _, c := range q.Conditions {
		if c.Type == "in_file" {
			ext := strings.ToLower(strings.TrimPrefix(c.Value, "."))
			fileExt := strings.ToLower(strings.TrimPrefix(getFileExt(filePath), "."))
			if fileExt != ext {
				return nil
			}
		}
	}

	// Determine target pattern
	targetRe, err := buildTargetRegex(q.Target)
	if err != nil {
		utils.LogWarn(fmt.Sprintf("SentryQL %s: invalid target pattern: %v", q.ID, err))
		return nil
	}

	// Build sanitizer patterns from not_sanitized_by conditions
	var sanitizerRes []*regexp.Regexp
	for _, c := range q.Conditions {
		if c.Type == "not_sanitized_by" {
			if re, err := regexp.Compile(`(?i)` + regexp.QuoteMeta(c.Value) + `\s*\(`); err == nil {
				sanitizerRes = append(sanitizerRes, re)
			}
		}
	}

	// Build taint sources from tainted_by conditions
	var taintSources []string
	for _, c := range q.Conditions {
		if c.Type == "tainted_by" {
			taintSources = append(taintSources, strings.ToLower(c.Value))
		}
	}

	// Build extra regex from matches conditions
	var matchRes []*regexp.Regexp
	for _, c := range q.Conditions {
		if c.Type == "matches" {
			if re, err := regexp.Compile(`(?i)` + c.Value); err == nil {
				matchRes = append(matchRes, re)
			}
		}
	}

	var findings []reporter.Finding
	reachableTaint := make(map[string]bool)

	for lineNum, line := range lines {
		// Check if this line has a taint source assignment
		for _, src := range taintSources {
			if strings.Contains(strings.ToLower(line), src) {
				// Extract variable being assigned
				if varName := extractAssignedVar(line); varName != "" {
					reachableTaint[varName] = true
				}
			}
		}

		// Check if cross-file tainted functions appear on this line
		if crossFileIdx != nil {
			for fn := range crossFileIdx.TaintedFunctions {
				if strings.Contains(line, fn+"(") {
					if varName := extractAssignedVar(line); varName != "" {
						reachableTaint[varName] = true
					}
				}
			}
		}

		// Check if the target pattern matches
		if !targetRe.MatchString(line) {
			continue
		}

		// Check matches conditions
		allMatchesPass := true
		for _, re := range matchRes {
			if !re.MatchString(line) {
				allMatchesPass = false
				break
			}
		}
		if !allMatchesPass {
			continue
		}

		// Check taint condition: at least one tainted variable appears in line
		if len(taintSources) > 0 {
			hasTaint := false
			// Direct taint source in the same line
			for _, src := range taintSources {
				if strings.Contains(strings.ToLower(line), src) {
					hasTaint = true
					break
				}
			}
			// Previously tainted variable appears in line
			if !hasTaint {
				for varName := range reachableTaint {
					if strings.Contains(line, varName) {
						hasTaint = true
						break
					}
				}
			}
			if !hasTaint {
				continue
			}
		}

		// Check not_sanitized_by: if any sanitizer appears in ±5 line context, skip
		if len(sanitizerRes) > 0 {
			contextStart := lineNum - 5
			if contextStart < 0 {
				contextStart = 0
			}
			contextEnd := lineNum + 5
			if contextEnd > len(lines) {
				contextEnd = len(lines)
			}
			context := strings.Join(lines[contextStart:contextEnd], "\n")
			sanitized := false
			for _, re := range sanitizerRes {
				if re.MatchString(context) {
					sanitized = true
					break
				}
			}
			if sanitized {
				continue
			}
		}

		msg := q.Message
		if msg == "" {
			msg = fmt.Sprintf("SentryQL rule %s matched", q.ID)
		}

		findings = append(findings, reporter.Finding{
			IssueName:   q.ID,
			RuleID:      "sentryql-" + q.ID,
			FilePath:    filePath,
			LineNumber:  fmt.Sprintf("%d", lineNum+1),
			Severity:    normalizeSentryQLSeverity(q.ReportAs),
			Description: msg,
			Source:      "sentryql",
			Confidence:  0.75,
			CodeSnippet: strings.TrimSpace(line),
		})
	}

	return findings
}

// ── helpers ───────────────────────────────────────────────────────────────────

func buildTargetRegex(t SentryQLTarget) (*regexp.Regexp, error) {
	pattern := ""
	switch t.Kind {
	case "function_call":
		pattern = `(?i)` + regexp.QuoteMeta(t.Name) + `\s*\(`
	case "variable":
		pattern = `(?i)\b` + regexp.QuoteMeta(t.Name) + `\b`
	case "string_literal":
		pattern = `(?i)["']` + regexp.QuoteMeta(t.Name) + `["']`
	case "file":
		pattern = `.*` // file-level: always match, rely on in_file condition
	default:
		pattern = `(?i)` + t.Name
	}
	return regexp.Compile(pattern)
}

func extractAssignedVar(line string) string {
	// Matches: var = ..., var := ..., let var = ..., const var = ...
	re := regexp.MustCompile(`(?:var\s+|let\s+|const\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::=|=)\s*`)
	if m := re.FindStringSubmatch(strings.TrimSpace(line)); len(m) > 1 {
		return m[1]
	}
	return ""
}

func normalizeSentryQLSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(s)
	default:
		return "medium"
	}
}

func getFileExt(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx < 0 {
		return ""
	}
	return path[idx:]
}
