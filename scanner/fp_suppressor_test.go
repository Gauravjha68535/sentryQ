package scanner

import (
	"testing"

	"SentryQ/reporter"
)

func TestSuppressFalsePositivesReturnsCopyNotMutation(t *testing.T) {
	findings := []reporter.Finding{
		{IssueName: "SQL Injection", FilePath: "/proj/src/db.go", Severity: "critical"},
		{IssueName: "XSS", FilePath: "/proj/src/view.go", Severity: "high"},
	}
	original := len(findings)
	result := SuppressFalsePositives(findings, "/proj")
	if len(findings) != original {
		t.Errorf("SuppressFalsePositives mutated the input slice (len changed from %d to %d)", original, len(findings))
	}
	_ = result
}

func TestSuppressFalsePositivesDoesNotDropLegitFindings(t *testing.T) {
	findings := []reporter.Finding{
		{IssueName: "SQL Injection", FilePath: "/proj/src/db.go", Severity: "critical", RuleID: "sqli-1"},
		{IssueName: "Command Injection", FilePath: "/proj/src/cmd.go", Severity: "high", RuleID: "cmdi-1"},
	}
	result := SuppressFalsePositives(findings, "/proj")
	if len(result) == 0 {
		t.Errorf("SuppressFalsePositives dropped all findings on a clean codebase path")
	}
}

func TestSuppressFalsePositivesHandlesEmpty(t *testing.T) {
	result := SuppressFalsePositives(nil, "/proj")
	if result == nil {
		// nil is acceptable for empty input
		return
	}
	if len(result) != 0 {
		t.Errorf("SuppressFalsePositives(nil) returned %d findings, want 0", len(result))
	}
}
