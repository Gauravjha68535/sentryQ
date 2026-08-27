package ai

import (
	"strings"
	"testing"
)

func TestSanitizeJudgeFieldStripsLLaMATokens(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"normal text", "normal text"},
		{"<|INST|>", "< |INST| >"},
		{"<|im_start|>system", "< |im_start| >system"},
		{"</code_context>", `<\/code_context>`}, // XML closing-tag breakout is escaped
		{"  spaces  ", "spaces"},
	}
	for _, tc := range cases {
		got := sanitizeJudgeField(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeJudgeField(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSanitizeJudgeFieldDoesNotModifySafeText(t *testing.T) {
	inputs := []string{
		"SQL Injection",
		"exec.Command injection via shell",
		"CWE-89",
		"src/main.go",
	}
	for _, s := range inputs {
		got := sanitizeJudgeField(s)
		if strings.TrimSpace(s) != got {
			t.Errorf("sanitizeJudgeField(%q) unexpectedly changed safe input to %q", s, got)
		}
	}
}

func TestBatchJudgeFindingsSingleBatch(t *testing.T) {
	findings := make([]JudgeFinding, 5)
	for i := range findings {
		findings[i] = JudgeFinding{ID: i + 1, Source: "static"}
	}
	batches := batchJudgeFindings(findings, maxJudgeBatchSize)
	if len(batches) != 1 {
		t.Errorf("expected 1 batch for %d findings (max %d), got %d", len(findings), maxJudgeBatchSize, len(batches))
	}
}

func TestBatchJudgeFindingsMultipleBatches(t *testing.T) {
	count := maxJudgeBatchSize*2 + 5
	findings := make([]JudgeFinding, count)
	for i := range findings {
		findings[i] = JudgeFinding{ID: i + 1}
	}
	batches := batchJudgeFindings(findings, maxJudgeBatchSize)
	if len(batches) != 3 {
		t.Errorf("expected 3 batches for %d findings (max %d), got %d", count, maxJudgeBatchSize, len(batches))
	}
	total := 0
	for _, b := range batches {
		total += len(b)
		if len(b) > maxJudgeBatchSize {
			t.Errorf("batch size %d exceeds maxJudgeBatchSize %d", len(b), maxJudgeBatchSize)
		}
	}
	if total != count {
		t.Errorf("total findings across batches = %d, want %d", total, count)
	}
}
