package reporter

import "strings"

// Finding represents a detected vulnerability
type Finding struct {
	ID                int      `json:"db_id"`             // Internal database ID
	SrNo              int      `json:"sr_no"`
	IssueName         string   `json:"issue_name"`
	FilePath          string   `json:"file_path"`
	Description       string   `json:"description"`
	Severity          string   `json:"severity"`
	LineNumber        string   `json:"line_number"`
	AiValidated       string   `json:"ai_validated"`
	Remediation       string   `json:"remediation"`
	RuleID            string   `json:"rule_id"`
	Source            string   `json:"source"`            // "custom", "semgrep", "ai-discovery", "taint-analyzer", "ast", "secret"
	CWE               string   `json:"cwe"`               // CWE ID (e.g., "CWE-79")
	OWASP             string   `json:"owasp"`             // OWASP category (e.g., "A03:2021")
	Confidence        float64  `json:"confidence"`        // 0.0-1.0 confidence score
	CodeSnippet       string   `json:"code_snippet"`      // Source code around the vulnerable line
	AiReasoning       string   `json:"ai_reasoning"`      // AI's detailed reasoning for the finding
	ExploitPath       []string `json:"exploit_path"`      // Step-by-step data flow path (for taint)
	TrustScore        float64  `json:"trust_score"`       // Multi-engine confidence score (0-100)
	ExploitPoC        string   `json:"exploit_poc"`       // AI-generated proof of concept exploit
	FixedCode         string   `json:"fixed_code"`        // AI-generated fixed code snippet
	VulnerablePattern string   `json:"vulnerable_pattern"` // Exact code fragment used to anchor the snippet to the real line
	Status            string   `json:"status"`            // Triage status: "open", "resolved", "ignored", "false_positive"
}

// IsFalsePositive returns true when the finding has been marked as a false positive
// either by the AI validator or by manual triage via the UI.
// Plain "No" in AiValidated means "not yet validated" (the default for all static
// scanner findings) and must NOT be treated as false positive — doing so would hide
// all static findings from reports when AI is disabled.
func (f Finding) IsFalsePositive() bool {
	// Manual triage via the UI sets f.Status = "false_positive".
	// This was previously ignored, causing manually-triaged findings to still
	// appear as live vulnerabilities in every downloaded report.
	if f.Status == "false_positive" {
		return true
	}
	lower := strings.ToLower(f.AiValidated)
	return strings.Contains(lower, "false positive")
}

// IsInTestFile returns true if the finding lives in a test/mock/fixture file.
// These findings are lower priority but may still be valid (e.g. test infra with real secrets).
func (f Finding) IsInTestFile() bool {
	lowerPath := strings.ToLower(strings.ReplaceAll(f.FilePath, "\\", "/"))
	testIndicators := []string{"_test.", ".test.", ".spec.", "/test/", "/tests/", "/__tests__/", "/mock/", "/fixture/", "testdata/"}
	for _, indicator := range testIndicators {
		if strings.Contains(lowerPath, indicator) {
			return true
		}
	}
	return false
}

// IsLowConfidence returns true if the finding has a genuinely low trust score.
// Threshold is 14 (below the 15-point multi-engine bonus) so that unvalidated
// two-engine findings (TrustScore=15) are NOT penalised vs unvalidated single-engine
// findings (TrustScore=0). Previously the threshold was 20, which flagged two-engine
// findings as "low confidence" while single-engine findings were not — backwards.
func (f Finding) IsLowConfidence() bool {
	return f.TrustScore > 0 && f.TrustScore < 14
}

// IsLowPriority returns true for findings that are deprioritised in reports —
// either located in test/mock files or carrying a very low trust score.
// Callers that previously used IsUnreachable should migrate to this method.
func (f Finding) IsLowPriority() bool {
	return f.IsInTestFile() || f.IsLowConfidence()
}

// SplitFindingsThreeWay separates findings into reachable, low-priority, and false positives.
// "low-priority" covers test-file findings and very-low-confidence noise.
func SplitFindingsThreeWay(findings []Finding) (reachable, lowPriority, falsePositives []Finding) {
	for _, f := range findings {
		if f.IsFalsePositive() {
			falsePositives = append(falsePositives, f)
		} else if f.IsLowPriority() {
			lowPriority = append(lowPriority, f)
		} else {
			reachable = append(reachable, f)
		}
	}
	return
}
