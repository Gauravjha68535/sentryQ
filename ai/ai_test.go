package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"SentryQ/reporter"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// ollamaServer stands up a fake Ollama /api/generate endpoint that returns
// the provided response JSON verbatim. It also stores every request body it
// receives so tests can assert on what was sent.
func ollamaServer(t *testing.T, responseBody string, statusCode int) (*httptest.Server, *[][]byte) {
	t.Helper()
	var received [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf []byte
		if r.Body != nil {
			buf = make([]byte, r.ContentLength)
			r.Body.Read(buf) //nolint:errcheck
		}
		received = append(received, buf)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		fmt.Fprint(w, responseBody)
	}))
	t.Cleanup(srv.Close)
	return srv, &received
}

// setTestOllamaHost points the package-level Ollama client at srv and
// restores the original URL when the test ends.
func setTestOllamaHost(t *testing.T, srv *httptest.Server) {
	t.Helper()
	original := GetOllamaBaseURL()
	// Strip "http://" for SetOllamaHost which adds it back.
	SetOllamaHost(strings.TrimPrefix(srv.URL, "http://"))
	t.Cleanup(func() {
		SetOllamaHost(strings.TrimPrefix(original, "http://"))
	})
}

// makeFindings is a convenience constructor for test findings.
func makeFindings(specs ...struct {
	severity    string
	aiValidated string
	filePath    string
	confidence  float64
}) []reporter.Finding {
	out := make([]reporter.Finding, len(specs))
	for i, s := range specs {
		out[i] = reporter.Finding{
			SrNo:        i + 1,
			IssueName:   fmt.Sprintf("issue-%d", i+1),
			FilePath:    s.filePath,
			Severity:    s.severity,
			AiValidated: s.aiValidated,
			Confidence:  s.confidence,
			LineNumber:  "10",
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// batchJudgeFindings — pure function, no I/O
// ─────────────────────────────────────────────────────────────────────────────

func TestBatchJudgeFindings_EmptyInput(t *testing.T) {
	batches := batchJudgeFindings(nil, 5)
	if len(batches) != 1 || len(batches[0]) != 0 {
		t.Fatalf("expected one empty batch, got %v", batches)
	}
}

func TestBatchJudgeFindings_SmallerThanMax(t *testing.T) {
	findings := make([]JudgeFinding, 3)
	batches := batchJudgeFindings(findings, 5)
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch for 3 findings with max=5, got %d", len(batches))
	}
	if len(batches[0]) != 3 {
		t.Fatalf("expected batch len 3, got %d", len(batches[0]))
	}
}

func TestBatchJudgeFindings_ExactlyMax(t *testing.T) {
	findings := make([]JudgeFinding, 5)
	batches := batchJudgeFindings(findings, 5)
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(batches))
	}
}

func TestBatchJudgeFindings_MultipleFullBatches(t *testing.T) {
	findings := make([]JudgeFinding, 12)
	batches := batchJudgeFindings(findings, 5)
	// 12 items / 5 = 2 full + 1 remainder → 3 batches
	if len(batches) != 3 {
		t.Fatalf("expected 3 batches for 12 findings with max=5, got %d", len(batches))
	}
	if len(batches[0]) != 5 || len(batches[1]) != 5 || len(batches[2]) != 2 {
		t.Fatalf("unexpected batch sizes: %d %d %d", len(batches[0]), len(batches[1]), len(batches[2]))
	}
}

func TestBatchJudgeFindings_PreservesOrder(t *testing.T) {
	findings := []JudgeFinding{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}, {ID: 5}, {ID: 6}}
	batches := batchJudgeFindings(findings, 4)
	if batches[0][0].ID != 1 || batches[0][3].ID != 4 {
		t.Fatalf("first batch IDs wrong: %+v", batches[0])
	}
	if batches[1][0].ID != 5 || batches[1][1].ID != 6 {
		t.Fatalf("second batch IDs wrong: %+v", batches[1])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// countCriticalHighMedium — pure function
// ─────────────────────────────────────────────────────────────────────────────

func TestCountCriticalHighMedium(t *testing.T) {
	cases := []struct {
		name     string
		findings []reporter.Finding
		want     int
	}{
		{"empty", nil, 0},
		{"all low/info", []reporter.Finding{
			{Severity: "low"}, {Severity: "info"},
		}, 0},
		{"mixed", []reporter.Finding{
			{Severity: "critical"}, {Severity: "high"}, {Severity: "medium"},
			{Severity: "low"}, {Severity: "info"},
		}, 3},
		{"missing severity counts as non-low", []reporter.Finding{
			{Severity: ""},
		}, 1},
		{"all critical", []reporter.Finding{
			{Severity: "critical"}, {Severity: "critical"}, {Severity: "critical"},
		}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := countCriticalHighMedium(c.findings)
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// getCodeSnippet — pure function
// ─────────────────────────────────────────────────────────────────────────────

func TestGetCodeSnippet_MissingFile(t *testing.T) {
	contents := map[string]string{}
	got := getCodeSnippet(contents, "no/such/file.go", "5")
	if got != "" {
		t.Errorf("expected empty string for missing file, got %q", got)
	}
}

func TestGetCodeSnippet_SmallFile_ReturnsFull(t *testing.T) {
	lines := make([]string, 10)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d", i+1)
	}
	content := strings.Join(lines, "\n")
	contents := map[string]string{"file.go": content}

	got := getCodeSnippet(contents, "file.go", "5")
	// Small file (≤500 lines) → full content with line numbers
	for i := 1; i <= 10; i++ {
		if !strings.Contains(got, fmt.Sprintf("%d: line %d", i, i)) {
			t.Errorf("expected line %d in snippet, got:\n%s", i, got)
		}
	}
}

func TestGetCodeSnippet_LargeFile_ReturnsWindow(t *testing.T) {
	// Build a 600-line file
	var sb strings.Builder
	for i := 1; i <= 600; i++ {
		sb.WriteString(fmt.Sprintf("code line %d\n", i))
	}
	content := strings.TrimRight(sb.String(), "\n")
	contents := map[string]string{"big.go": content}

	// Ask for line 300 — should get ±150 window starting at line 151 (index 150)
	got := getCodeSnippet(contents, "big.go", "300")
	if !strings.Contains(got, "151:") {
		t.Errorf("expected line 151 in window (contextStart = 300-150 = 150 index = line 151), snippet:\n%s", got[:200])
	}
	if strings.Contains(got, "\n1:") || strings.HasPrefix(got, "1:") {
		t.Errorf("line 1 should not appear in a ±150 window around line 300")
	}
}

func TestGetCodeSnippet_RangeLineNumber(t *testing.T) {
	var sb strings.Builder
	for i := 1; i <= 600; i++ {
		sb.WriteString(fmt.Sprintf("line %d\n", i))
	}
	contents := map[string]string{"f.go": strings.TrimRight(sb.String(), "\n")}
	// Range format: "300-305"
	got := getCodeSnippet(contents, "f.go", "300-305")
	if got == "" {
		t.Error("expected non-empty snippet for range line number")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// formatDuration — pure function
// ─────────────────────────────────────────────────────────────────────────────

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{30 * time.Second, "30s"},
		{59 * time.Second, "59s"},
		{time.Minute, "1m00s"},
		{90 * time.Second, "1m30s"},
		{time.Hour, "1h00m"},
		{time.Hour + 30*time.Minute, "1h30m"},
	}
	for _, c := range cases {
		got := formatDuration(c.d)
		if got != c.want {
			t.Errorf("formatDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfidenceCalibrator — stateful but pure math
// ─────────────────────────────────────────────────────────────────────────────

func newTestCalibrator(t *testing.T) *ConfidenceCalibrator {
	t.Helper()
	dir := t.TempDir()
	c := &ConfidenceCalibrator{
		statsFile: dir + "/stats.json",
		stats:     make(map[string]*VulnerabilityStats),
	}
	return c
}

func TestCalibrateConfidence_NotEnoughData(t *testing.T) {
	c := newTestCalibrator(t)
	// 4 validations — below the 5-sample threshold
	for i := 0; i < 4; i++ {
		c.RecordValidation("high", true)
	}
	raw := 0.8
	got := c.CalibrateConfidence("high", raw)
	if got != raw {
		t.Errorf("expected raw confidence %.2f with <5 samples, got %.2f", raw, got)
	}
}

func TestCalibrateConfidence_HighAccuracy_BoostsConfidence(t *testing.T) {
	c := newTestCalibrator(t)
	for i := 0; i < 10; i++ {
		c.RecordValidation("critical", true) // 100% accuracy
	}
	raw := 0.70
	got := c.CalibrateConfidence("critical", raw)
	// calibrated = 0.70*0.7 + 1.0*0.3 = 0.49 + 0.30 = 0.79 > raw
	if got <= raw {
		t.Errorf("expected calibrated (%.2f) > raw (%.2f) for perfect accuracy", got, raw)
	}
}

func TestCalibrateConfidence_LowAccuracy_ReducesConfidence(t *testing.T) {
	c := newTestCalibrator(t)
	for i := 0; i < 10; i++ {
		c.RecordValidation("medium", false) // 0% accuracy
	}
	raw := 0.80
	got := c.CalibrateConfidence("medium", raw)
	// calibrated = 0.80*0.7 + 0.0*0.3 = 0.56 < raw
	if got >= raw {
		t.Errorf("expected calibrated (%.2f) < raw (%.2f) for zero accuracy", got, raw)
	}
}

func TestCalibrateConfidence_Bounds(t *testing.T) {
	c := newTestCalibrator(t)
	// Force extremely low accuracy → calibrated should not go below 0.1
	for i := 0; i < 20; i++ {
		c.RecordValidation("low", false)
	}
	got := c.CalibrateConfidence("low", 0.01)
	if got < 0.1 {
		t.Errorf("confidence should not go below 0.1, got %.4f", got)
	}
}

func TestRecordValidation_IncrementsCorrectly(t *testing.T) {
	c := newTestCalibrator(t)
	c.RecordValidation("high", true)
	c.RecordValidation("high", true)
	c.RecordValidation("high", false)

	stats := c.stats["high"]
	if stats.AssessedFindings != 3 {
		t.Errorf("AssessedFindings: got %d, want 3", stats.AssessedFindings)
	}
	if stats.TruePositives != 2 {
		t.Errorf("TruePositives: got %d, want 2", stats.TruePositives)
	}
	if stats.FalsePositives != 1 {
		t.Errorf("FalsePositives: got %d, want 1", stats.FalsePositives)
	}
	wantRate := 2.0 / 3.0
	if stats.AccuracyRate < wantRate-0.01 || stats.AccuracyRate > wantRate+0.01 {
		t.Errorf("AccuracyRate: got %.4f, want ~%.4f", stats.AccuracyRate, wantRate)
	}
}

func TestSaveAndLoadStats(t *testing.T) {
	c := newTestCalibrator(t)
	c.RecordValidation("critical", true)
	c.RecordValidation("critical", false)
	c.SaveStats()

	c2 := &ConfidenceCalibrator{
		statsFile: c.statsFile,
		stats:     make(map[string]*VulnerabilityStats),
	}
	c2.LoadStats()

	s := c2.stats["critical"]
	if s == nil || s.AssessedFindings != 2 {
		t.Fatalf("loaded stats don't match saved stats: %+v", s)
	}
}

func TestApplyCalibrationToFindings_SkipsNonAI(t *testing.T) {
	c := newTestCalibrator(t)
	for i := 0; i < 10; i++ {
		c.RecordValidation("high", false) // 0% accuracy, would lower confidence
	}
	findings := []reporter.Finding{
		{Severity: "high", Confidence: 0.9, Source: "pattern-engine", AiValidated: "No"},
	}
	out := c.ApplyCalibrationToFindings(findings)
	if out[0].Confidence != 0.9 {
		t.Errorf("non-AI finding confidence should be unchanged, got %.2f", out[0].Confidence)
	}
}

func TestApplyCalibrationToFindings_AdjustsAIFindings(t *testing.T) {
	c := newTestCalibrator(t)
	for i := 0; i < 10; i++ {
		c.RecordValidation("high", false) // 0% accuracy
	}
	findings := []reporter.Finding{
		{Severity: "high", Confidence: 0.9, Source: "ai-discovery", AiValidated: "Yes"},
	}
	out := c.ApplyCalibrationToFindings(findings)
	// With 0% accuracy: calibrated = 0.9*0.7 + 0.0*0.3 = 0.63 < 0.9
	if out[0].Confidence >= 0.9 {
		t.Errorf("AI finding confidence should have been lowered, got %.2f", out[0].Confidence)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateFinding — HTTP-level test via fake Ollama server
// ─────────────────────────────────────────────────────────────────────────────

func ollamaResponse(response string) string {
	b, _ := json.Marshal(map[string]interface{}{"response": response, "done": true})
	return string(b)
}

func TestValidateFinding_TruePositive(t *testing.T) {
	validJSON := `{
		"taint_source_identified": true,
		"sanitizer_or_mitigation_found": false,
		"sink_is_reachable": true,
		"is_true_positive": true,
		"confidence": 0.95,
		"explanation": "SQL injection confirmed",
		"suggested_fix": "Use parameterized queries",
		"fixed_code_snippet": "db.Query(\"SELECT * FROM users WHERE id=?\", id)",
		"severity_adjustment": "critical",
		"exploit_poc": "' OR 1=1 --"
	}`
	srv, _ := ollamaServer(t, ollamaResponse(validJSON), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	finding := reporter.Finding{
		IssueName:   "sql-injection",
		FilePath:    "main.go",
		LineNumber:  "42",
		Severity:    "high",
		Description: "Raw SQL query with user input",
		Remediation: "Use prepared statements",
	}

	result, err := ValidateFinding(context.Background(), "test-model", finding, "code content", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsTruePositive {
		t.Error("expected IsTruePositive=true")
	}
	if result.Confidence != 0.95 {
		t.Errorf("confidence: got %.2f, want 0.95", result.Confidence)
	}
	if result.SeverityAdjustment != "critical" {
		t.Errorf("severity_adjustment: got %q, want %q", result.SeverityAdjustment, "critical")
	}
}

func TestValidateFinding_FalsePositive(t *testing.T) {
	validJSON := `{
		"taint_source_identified": false,
		"sanitizer_or_mitigation_found": true,
		"sink_is_reachable": false,
		"is_true_positive": false,
		"confidence": 0.85,
		"explanation": "Input is properly sanitized",
		"suggested_fix": "N/A",
		"fixed_code_snippet": "N/A",
		"severity_adjustment": "same",
		"exploit_poc": "N/A"
	}`
	srv, _ := ollamaServer(t, ollamaResponse(validJSON), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	finding := reporter.Finding{
		IssueName:  "xss",
		FilePath:   "handler.go",
		LineNumber: "10",
		Severity:   "medium",
	}

	result, err := ValidateFinding(context.Background(), "test-model", finding, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsTruePositive {
		t.Error("expected IsTruePositive=false")
	}
}

func TestValidateFinding_MalformedJSON_FallsBackGracefully(t *testing.T) {
	// Server returns garbage — should not crash; returns fallback result
	srv, _ := ollamaServer(t, ollamaResponse("this is not json at all"), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	finding := reporter.Finding{
		IssueName:   "hardcoded-secret",
		FilePath:    "config.go",
		LineNumber:  "1",
		Severity:    "critical",
		Remediation: "Use env vars",
	}

	result, err := ValidateFinding(context.Background(), "test-model", finding, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fallback: keep finding (precautionary)
	if !result.IsTruePositive {
		t.Error("fallback should default to IsTruePositive=true (precautionary)")
	}
	if !strings.Contains(result.Explanation, "PARSE_FAILURE") {
		t.Errorf("expected PARSE_FAILURE marker in fallback explanation, got: %s", result.Explanation)
	}
}

func TestValidateFinding_ServerError_ReturnsError(t *testing.T) {
	srv, _ := ollamaServer(t, `{"error":"model not found"}`, http.StatusInternalServerError)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	finding := reporter.Finding{IssueName: "test", FilePath: "f.go", LineNumber: "1", Severity: "high"}
	_, err := ValidateFinding(context.Background(), "test-model", finding, "", "")
	if err == nil {
		t.Error("expected error for HTTP 500 response")
	}
}

func TestValidateFinding_ContextCancellation(t *testing.T) {
	// Server that blocks until the test times out — context should cancel it
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked // block forever
	}))
	t.Cleanup(func() { close(blocked); srv.Close() })
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	finding := reporter.Finding{IssueName: "test", FilePath: "f.go", LineNumber: "1", Severity: "high"}
	_, err := ValidateFinding(ctx, "test-model", finding, "", "")
	if err == nil {
		t.Error("expected error on context cancellation")
	}
}

func TestValidateFinding_ZeroConfidenceSanityFix(t *testing.T) {
	// Parsed response has confidence=0 but is_true_positive=true — should be bumped to 0.5
	validJSON := `{
		"is_true_positive": true,
		"confidence": 0,
		"explanation": "real bug",
		"suggested_fix": "fix it",
		"fixed_code_snippet": "N/A",
		"severity_adjustment": "same",
		"exploit_poc": "N/A"
	}`
	srv, _ := ollamaServer(t, ollamaResponse(validJSON), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	finding := reporter.Finding{IssueName: "test", FilePath: "f.go", LineNumber: "1", Severity: "high"}
	result, err := ValidateFinding(context.Background(), "test-model", finding, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Confidence != 0.5 {
		t.Errorf("zero confidence with true positive should be bumped to 0.5, got %.2f", result.Confidence)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// runJudgeBatch — HTTP-level test
// ─────────────────────────────────────────────────────────────────────────────

func judgeResponse(verdicts []JudgeVerdictItem) string {
	v := JudgeVerdict{Findings: verdicts}
	b, _ := json.Marshal(v)
	resp := map[string]interface{}{"response": string(b), "done": true}
	out, _ := json.Marshal(resp)
	return string(out)
}

func TestRunJudgeBatch_KeepVerdict(t *testing.T) {
	verdicts := []JudgeVerdictItem{
		{MasterID: 1, DuplicateIDs: []int{}, Verdict: "keep", Reason: "real bug", SimplifiedName: "SQL Injection"},
		{MasterID: 2, DuplicateIDs: []int{}, Verdict: "keep", Reason: "real bug 2", SimplifiedName: "XSS"},
	}
	srv, _ := ollamaServer(t, judgeResponse(verdicts), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	findings := []JudgeFinding{{ID: 1, IssueName: "sql"}, {ID: 2, IssueName: "xss"}}
	result, err := runJudgeBatch(context.Background(), findings, "test-model", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 verdicts, got %d", len(result))
	}
	if result[0].Verdict != "keep" || result[1].Verdict != "keep" {
		t.Errorf("unexpected verdicts: %+v", result)
	}
}

func TestRunJudgeBatch_DropVerdict(t *testing.T) {
	verdicts := []JudgeVerdictItem{
		{MasterID: 1, Verdict: "drop", Reason: "false positive"},
	}
	srv, _ := ollamaServer(t, judgeResponse(verdicts), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	findings := []JudgeFinding{{ID: 1}}
	result, err := runJudgeBatch(context.Background(), findings, "test-model", srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 || result[0].Verdict != "drop" {
		t.Errorf("expected drop verdict, got %+v", result)
	}
}

func TestRunJudgeBatch_MalformedResponse_ReturnsError(t *testing.T) {
	srv, _ := ollamaServer(t, ollamaResponse("not json"), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	findings := []JudgeFinding{{ID: 1}}
	_, err := runJudgeBatch(context.Background(), findings, "test-model", srv.URL)
	if err == nil {
		t.Error("expected error for malformed judge response")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// JudgeFindings — integration-level logic test
// ─────────────────────────────────────────────────────────────────────────────

func TestJudgeFindings_Empty(t *testing.T) {
	result, err := JudgeFindings(context.Background(), nil, nil, "model", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d findings", len(result))
	}
}

func TestJudgeFindings_DropRemovesFinding(t *testing.T) {
	staticF := []reporter.Finding{
		{SrNo: 1, IssueName: "sqli", FilePath: "main.go", LineNumber: "10", Severity: "high"},
	}
	verdicts := []JudgeVerdictItem{
		{MasterID: 1, Verdict: "drop", Reason: "false positive"},
	}
	srv, _ := ollamaServer(t, judgeResponse(verdicts), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	result, err := JudgeFindings(context.Background(), staticF, nil, "model", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("dropped finding should not appear in result, got %d findings", len(result))
	}
}

func TestJudgeFindings_MergeDeduplicates(t *testing.T) {
	staticF := []reporter.Finding{
		{SrNo: 1, IssueName: "sqli-static", FilePath: "main.go", LineNumber: "10", Severity: "high"},
	}
	aiF := []reporter.Finding{
		{SrNo: 2, IssueName: "sqli-ai", FilePath: "main.go", LineNumber: "10", Severity: "critical", AiValidated: "Yes"},
	}
	verdicts := []JudgeVerdictItem{
		{MasterID: 1, DuplicateIDs: []int{2}, Verdict: "keep",
			Reason: "duplicate", SimplifiedName: "SQL Injection", Severity: "critical"},
	}
	srv, _ := ollamaServer(t, judgeResponse(verdicts), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	result, err := JudgeFindings(context.Background(), staticF, aiF, "model", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Duplicate merged → only 1 finding
	if len(result) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(result))
	}
	if result[0].Severity != "critical" {
		t.Errorf("severity should be judge-adjusted to critical, got %q", result[0].Severity)
	}
	if result[0].IssueName != "SQL Injection" {
		t.Errorf("simplified name should be applied, got %q", result[0].IssueName)
	}
}

func TestJudgeFindings_ServerFailure_KeepsAllFindings(t *testing.T) {
	// Server returns 500 → batch fails → all findings kept as-is
	srv, _ := ollamaServer(t, `{"error":"internal"}`, http.StatusInternalServerError)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	staticF := []reporter.Finding{
		{SrNo: 1, IssueName: "issue-1", FilePath: "a.go", LineNumber: "1", Severity: "high"},
		{SrNo: 2, IssueName: "issue-2", FilePath: "b.go", LineNumber: "2", Severity: "medium"},
	}

	result, err := JudgeFindings(context.Background(), staticF, nil, "model", "")
	if err != nil {
		t.Fatalf("unexpected error (failures should be logged, not returned): %v", err)
	}
	if len(result) != 2 {
		t.Errorf("all findings should be kept on judge failure, got %d", len(result))
	}
}

func TestJudgeFindings_CustomOllamaHost(t *testing.T) {
	verdicts := []JudgeVerdictItem{
		{MasterID: 1, Verdict: "keep", SimplifiedName: "XSS"},
	}
	srv, received := ollamaServer(t, judgeResponse(verdicts), http.StatusOK)
	SetActiveProvider(ProviderOllama)

	staticF := []reporter.Finding{
		{SrNo: 1, IssueName: "xss", FilePath: "x.go", LineNumber: "5", Severity: "medium"},
	}
	// Pass the custom host as the judgeOllamaHost arg — should NOT mutate the global
	host := strings.TrimPrefix(srv.URL, "http://")
	result, err := JudgeFindings(context.Background(), staticF, nil, "model", host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*received) == 0 {
		t.Error("expected the custom host server to receive a request")
	}
	if len(result) != 1 {
		t.Errorf("expected 1 result, got %d", len(result))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateFindingsBatch — circuit breaker and skip logic
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateFindingsBatch_EmptyFindings(t *testing.T) {
	out := ValidateFindingsBatch(context.Background(), "model", nil, nil)
	if len(out) != 0 {
		t.Errorf("expected empty output for empty input, got %d", len(out))
	}
}

func TestValidateFindingsBatch_SkipsLowAndInfo(t *testing.T) {
	// No server needed — low/info findings are skipped before any HTTP call
	findings := []reporter.Finding{
		{SrNo: 1, IssueName: "low-issue", FilePath: "f.go", LineNumber: "1", Severity: "low"},
		{SrNo: 2, IssueName: "info-issue", FilePath: "f.go", LineNumber: "2", Severity: "info"},
	}
	out := ValidateFindingsBatch(context.Background(), "model", findings, nil)
	for _, f := range out {
		if f.AiValidated != "Skipped (Low/Info)" {
			t.Errorf("expected skipped marking, got %q for %s", f.AiValidated, f.IssueName)
		}
	}
}

func TestValidateFindingsBatch_CircuitBreaker(t *testing.T) {
	// Server always errors — circuit breaker should fire after maxConsecutiveErrors
	srv, _ := ollamaServer(t, `{"error":"down"}`, http.StatusInternalServerError)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	// 6 high-severity findings — first 3 hit the error, then circuit breaks
	findings := make([]reporter.Finding, 6)
	for i := range findings {
		findings[i] = reporter.Finding{
			SrNo:      i + 1,
			IssueName: fmt.Sprintf("issue-%d", i+1),
			FilePath:  "f.go",
			LineNumber: "1",
			Severity:  "high",
		}
	}
	out := ValidateFindingsBatch(context.Background(), "model", findings, nil)
	if len(out) != 6 {
		t.Fatalf("expected all 6 findings returned (some skipped), got %d", len(out))
	}

	skipped := 0
	errored := 0
	for _, f := range out {
		switch f.AiValidated {
		case "Skipped (AI Unavailable)":
			skipped++
		case "Error":
			errored++
		}
	}
	if errored == 0 {
		t.Error("expected at least 1 error before circuit breaker fired")
	}
	if skipped == 0 {
		t.Error("expected at least 1 finding skipped by circuit breaker")
	}
}

func TestValidateFindingsBatch_PreservesOrder(t *testing.T) {
	validJSON := `{"is_true_positive":true,"confidence":0.9,"explanation":"ok","suggested_fix":"fix","fixed_code_snippet":"N/A","severity_adjustment":"same","exploit_poc":"N/A"}`
	srv, _ := ollamaServer(t, ollamaResponse(validJSON), http.StatusOK)
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	findings := make([]reporter.Finding, 5)
	for i := range findings {
		findings[i] = reporter.Finding{
			SrNo:      i + 1,
			IssueName: fmt.Sprintf("issue-%d", i+1),
			FilePath:  fmt.Sprintf("file%d.go", i+1),
			LineNumber: "1",
			Severity:  "high",
		}
	}
	out := ValidateFindingsBatch(context.Background(), "model", findings, nil)
	if len(out) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(out))
	}
	for i, f := range out {
		want := fmt.Sprintf("file%d.go", i+1)
		if f.FilePath != want {
			t.Errorf("finding %d out of order: got FilePath %q, want %q", i, f.FilePath, want)
		}
	}
}

func TestValidateFindingsBatch_ContextCancellation(t *testing.T) {
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked
	}))
	t.Cleanup(func() { close(blocked); srv.Close() })
	setTestOllamaHost(t, srv)
	SetActiveProvider(ProviderOllama)

	findings := []reporter.Finding{
		{SrNo: 1, IssueName: "sqli", FilePath: "f.go", LineNumber: "1", Severity: "critical"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	// Should return (possibly with error marker) rather than hanging
	out := ValidateFindingsBatch(ctx, "model", findings, nil)
	if len(out) != 1 {
		t.Errorf("expected 1 finding returned even on cancellation, got %d", len(out))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// MLFPReducer
// ─────────────────────────────────────────────────────────────────────────────

func newTestReducer(t *testing.T) *MLFPReducer {
	t.Helper()
	return NewMLFPReducer(t.TempDir())
}

func TestMLFPReducer_FilterWithNoHistory_KeepsAll(t *testing.T) {
	reducer := newTestReducer(t)
	findings := []reporter.Finding{
		{SrNo: 1, RuleID: "sqli", FilePath: "main.go", Severity: "high"},
		{SrNo: 2, RuleID: "xss", FilePath: "view.go", Severity: "medium"},
	}
	out := reducer.FilterFindingsByFPProbability(findings, 0.8)
	if len(out) != 2 {
		t.Errorf("expected all 2 findings kept (no FP history), got %d", len(out))
	}
}

func TestMLFPReducer_FilterHighFPRule(t *testing.T) {
	reducer := newTestReducer(t)
	// Record 9 FPs and 1 TP for "sqli" → 90% FP rate → should be filtered
	for i := 0; i < 9; i++ {
		reducer.AddFeedback("sqli", "main.go", "high", true, "")
	}
	reducer.AddFeedback("sqli", "main.go", "high", false, "")

	findings := []reporter.Finding{
		{SrNo: 1, RuleID: "sqli", FilePath: "main.go", Severity: "high"},
	}
	out := reducer.FilterFindingsByFPProbability(findings, 0.8) // threshold = 80% FP → drop above
	if len(out) != 0 {
		t.Errorf("expected sqli finding to be filtered (90%% FP rate), got %d findings", len(out))
	}
}

func TestMLFPReducer_KeepsLowFPRule(t *testing.T) {
	reducer := newTestReducer(t)
	// 1 FP out of 10 → 10% FP rate → should be kept
	reducer.AddFeedback("rce", "cmd.go", "critical", true, "")
	for i := 0; i < 9; i++ {
		reducer.AddFeedback("rce", "cmd.go", "critical", false, "")
	}

	findings := []reporter.Finding{
		{SrNo: 1, RuleID: "rce", FilePath: "cmd.go", Severity: "critical"},
	}
	out := reducer.FilterFindingsByFPProbability(findings, 0.8)
	if len(out) != 1 {
		t.Errorf("expected rce finding to be kept (10%% FP rate), got %d", len(out))
	}
}

func TestMLFPReducer_SaveAndLoadHistory(t *testing.T) {
	reducer := newTestReducer(t)
	reducer.AddFeedback("ssrf", "client.go", "high", true, "")
	if err := reducer.SaveHistory(); err != nil {
		t.Fatalf("SaveHistory: %v", err)
	}

	reducer2 := NewMLFPReducer(reducer.historyFile[:strings.LastIndex(reducer.historyFile, string(os.PathSeparator))])
	if err := reducer2.LoadHistory(); err != nil {
		t.Fatalf("LoadHistory: %v", err)
	}

	reducer2.mu.Lock()
	total := reducer2.history.TotalFeedback
	reducer2.mu.Unlock()
	if total != 1 {
		t.Errorf("expected 1 feedback loaded, got %d", total)
	}
}
