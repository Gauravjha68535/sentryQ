package reporter

import "strings"

// Finding represents a detected vulnerability
type Finding struct {
	SrNo        int      `json:"sr_no"`
	IssueName   string   `json:"issue_name"`
	FilePath    string   `json:"file_path"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	LineNumber  string   `json:"line_number"`
	AiValidated string   `json:"ai_validated"`
	Remediation string   `json:"remediation"`
	RuleID      string   `json:"rule_id"`
	Source      string   `json:"source"`       // "custom", "semgrep", "ai-discovery", "taint-analyzer", "ast", "secret"
	CWE         string   `json:"cwe"`          // CWE ID (e.g., "CWE-79")
	OWASP       string   `json:"owasp"`        // OWASP category (e.g., "A03:2021")
	Confidence  float64  `json:"confidence"`   // 0.0-1.0 confidence score
	CodeSnippet string   `json:"code_snippet"` // Source code around the vulnerable line
	AiReasoning string   `json:"ai_reasoning"` // AI's detailed reasoning for the finding
	ExploitPath []string `json:"exploit_path"` // Step-by-step data flow path (for taint)
	TrustScore  float64  `json:"trust_score"`  // Multi-engine confidence score (0-100)
	ExploitPoC  string   `json:"exploit_poc"`  // AI-generated proof of concept exploit
	FixedCode   string   `json:"fixed_code"`   // AI-generated fixed code snippet
}

// IsFalsePositive returns true if the AI validator marked this finding as a false positive
func (f Finding) IsFalsePositive() bool {
	lower := strings.ToLower(f.AiValidated)
	return strings.Contains(lower, "false positive") || strings.Contains(lower, "no ")
}

// IsUnreachable returns true if the finding is in a test file or has very low confidence
func (f Finding) IsUnreachable() bool {
	lowerPath := strings.ToLower(f.FilePath)
	testIndicators := []string{"_test.", ".test.", ".spec.", "/test/", "/tests/", "/__tests__/", "/mock/", "/fixture/", "testdata/"}
	for _, indicator := range testIndicators {
		if strings.Contains(lowerPath, indicator) {
			return true
		}
	}
	// Also mark as unreachable if trust score is very low (likely noise)
	return f.TrustScore < 20 && f.TrustScore > 0
}

// SplitFindingsThreeWay separates findings into reachable, unreachable, and false positives
func SplitFindingsThreeWay(findings []Finding) (reachable, unreachable, falsePositives []Finding) {
	for _, f := range findings {
		if f.IsFalsePositive() {
			falsePositives = append(falsePositives, f)
		} else if f.IsUnreachable() {
			unreachable = append(unreachable, f)
		} else {
			reachable = append(reachable, f)
		}
	}
	return
}
