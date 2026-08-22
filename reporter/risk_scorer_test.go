package reporter

import "testing"

func TestGetPriorityMatrixCriticalAlwaysP0(t *testing.T) {
	findings := []Finding{
		{Severity: "critical", AiValidated: ""},    // static-only scan, no AI
		{Severity: "critical", AiValidated: "Yes"}, // AI confirmed
	}
	matrix := GetPriorityMatrix(findings)
	if len(matrix.P0) != 2 {
		t.Errorf("expected 2 critical findings in P0 (regardless of AI validation), got %d", len(matrix.P0))
	}
	if len(matrix.P1) != 0 {
		t.Errorf("no critical finding should be in P1, got %d", len(matrix.P1))
	}
}

func TestGetPriorityMatrixHighAIBoost(t *testing.T) {
	findings := []Finding{
		{Severity: "high", AiValidated: "Yes"}, // boosted to P0
		{Severity: "high", AiValidated: ""},    // stays P1
	}
	matrix := GetPriorityMatrix(findings)
	if len(matrix.P0) != 1 {
		t.Errorf("AI-confirmed high should be P0, got P0=%d", len(matrix.P0))
	}
	if len(matrix.P1) != 1 {
		t.Errorf("unconfirmed high should be P1, got P1=%d", len(matrix.P1))
	}
}

func TestGetPriorityMatrixSkipsFalsePositives(t *testing.T) {
	findings := []Finding{
		{Severity: "critical", AiValidated: "No (False Positive)"},
		{Severity: "high", AiValidated: "No (False Positive)"},
	}
	matrix := GetPriorityMatrix(findings)
	total := len(matrix.P0) + len(matrix.P1) + len(matrix.P2) + len(matrix.P3)
	if total != 0 {
		t.Errorf("false positives should not appear in any priority bucket, got %d", total)
	}
}

func TestGetPriorityMatrixEmptyInput(t *testing.T) {
	matrix := GetPriorityMatrix(nil)
	total := len(matrix.P0) + len(matrix.P1) + len(matrix.P2) + len(matrix.P3)
	if total != 0 {
		t.Errorf("empty input should produce empty matrix, got total=%d", total)
	}
}

func TestCalculateRiskScoreZeroFindings(t *testing.T) {
	score := CalculateRiskScore(nil)
	if score.Score != 0 {
		t.Errorf("zero findings should give score 0, got %f", score.Score)
	}
}

func TestCalculateRiskScoreCriticalDominates(t *testing.T) {
	findings := []Finding{
		{Severity: "critical"},
		{Severity: "critical"},
	}
	score := CalculateRiskScore(findings)
	if score.Score <= 0 {
		t.Errorf("critical findings should produce positive risk score, got %f", score.Score)
	}
	if score.Level == "" {
		t.Error("risk level string should not be empty")
	}
}
