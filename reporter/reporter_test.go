package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Helpers ────────────────────────────────────────────────────────────────

func sampleFindings() []Finding {
	return []Finding{
		{
			SrNo: 1, RuleID: "sqli-001", IssueName: "SQL Injection",
			FilePath: "app/db.go", LineNumber: "42",
			Severity: "critical", Confidence: 0.95,
			Description: "Unsanitised user input in query", Remediation: "Use parameterised queries",
			CWE: "CWE-89", OWASP: "A03:2021",
		},
		{
			SrNo: 2, RuleID: "xss-001", IssueName: "XSS",
			FilePath: "web/handler.go", LineNumber: "18",
			Severity: "high", Confidence: 0.80,
			Description: "Reflected XSS via response writer", Remediation: "HTML-escape output",
			CWE: "CWE-79", OWASP: "A03:2021",
			Status: "false_positive", // should be excluded from compliance/SBOM counts
		},
		{
			SrNo: 3, RuleID: "secret-001", IssueName: "Hardcoded Secret",
			FilePath: "config/settings.go", LineNumber: "5",
			Severity: "medium", Confidence: 0.70,
			CWE: "CWE-798", OWASP: "A07:2021",
		},
	}
}

func tempFile(t *testing.T, ext string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "sentryq-test-*"+ext)
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	f.Close()
	return f.Name()
}

// ─── Finding helpers ─────────────────────────────────────────────────────────

func TestIsFalsePositive(t *testing.T) {
	cases := []struct {
		aiValidated string
		want        bool
	}{
		{"Yes", false},
		{"No", false},
		{"No (False Positive - Safe Pattern)", true},
		{"False Positive", true},
		{"false positive", true},
	}
	for _, c := range cases {
		f := Finding{AiValidated: c.aiValidated}
		if got := f.IsFalsePositive(); got != c.want {
			t.Errorf("IsFalsePositive(%q) = %v, want %v", c.aiValidated, got, c.want)
		}
	}
}

func TestIsUnreachable(t *testing.T) {
	cases := []struct {
		filePath   string
		trustScore float64
		want       bool
	}{
		{"app/handler_test.go", 0, true},
		{"src/__tests__/helper.js", 0, true},
		{"app/handler.go", 0, false},
		{"app/handler.go", 10.0, true},  // low trust score
		{"app/handler.go", 50.0, false}, // normal trust score
	}
	for _, c := range cases {
		f := Finding{FilePath: c.filePath, TrustScore: c.trustScore}
		if got := f.IsUnreachable(); got != c.want {
			t.Errorf("IsUnreachable({path:%q, trust:%.0f}) = %v, want %v", c.filePath, c.trustScore, got, c.want)
		}
	}
}

func TestSplitFindingsThreeWay(t *testing.T) {
	findings := []Finding{
		{FilePath: "main.go", AiValidated: "Yes"},
		{FilePath: "main_test.go", AiValidated: "Yes"},
		{FilePath: "main.go", AiValidated: "No (False Positive - Safe Pattern)"},
	}
	reachable, unreachable, fps := SplitFindingsThreeWay(findings)
	if len(reachable) != 1 {
		t.Errorf("reachable: got %d, want 1", len(reachable))
	}
	if len(unreachable) != 1 {
		t.Errorf("unreachable: got %d, want 1", len(unreachable))
	}
	if len(fps) != 1 {
		t.Errorf("falsePositives: got %d, want 1", len(fps))
	}
}

// ─── SBOM ────────────────────────────────────────────────────────────────────

func TestGenerateSBOM(t *testing.T) {
	out := tempFile(t, ".json")
	findings := sampleFindings()

	if err := GenerateSBOM(out, findings, "my-project"); err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		t.Fatalf("unmarshal SBOM: %v", err)
	}
	if sbom["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", sbom["bomFormat"])
	}
	if sbom["specVersion"] == nil {
		t.Error("specVersion missing from SBOM")
	}
	// SBOM is valid even with no dependency findings — vulnerabilities are added from CWE-tagged findings
	if sbom["metadata"] == nil {
		t.Error("metadata missing from SBOM")
	}
}

func TestGenerateSBOM_EmptyFindings(t *testing.T) {
	out := tempFile(t, ".json")
	if err := GenerateSBOM(out, nil, "empty-project"); err != nil {
		t.Fatalf("GenerateSBOM with nil findings: %v", err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "CycloneDX") {
		t.Error("SBOM should still have valid CycloneDX header with empty findings")
	}
}

// ─── Compliance ───────────────────────────────────────────────────────────────

func TestGenerateComplianceReport_OWASP(t *testing.T) {
	out := tempFile(t, ".json")
	findings := sampleFindings()

	report, err := GenerateComplianceReport(out, "scan-123", findings, FrameworkOWASP10)
	if err != nil {
		t.Fatalf("GenerateComplianceReport: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
	if string(report.Framework) != string(FrameworkOWASP10) {
		t.Errorf("Framework = %q", report.Framework)
	}
	if report.ScanID != "scan-123" {
		t.Errorf("ScanID = %q", report.ScanID)
	}
	if len(report.Controls) != len(owaspControls) {
		t.Errorf("Controls count = %d, want %d", len(report.Controls), len(owaspControls))
	}
	// A03:2021 should have findings (sqli + xss in sample, but xss is false_positive so skipped)
	var a03 *ControlResult
	for i := range report.Controls {
		if report.Controls[i].ControlID == "A03:2021" {
			a03 = &report.Controls[i]
			break
		}
	}
	if a03 == nil {
		t.Fatal("A03:2021 control not found")
	}
	if len(a03.Findings) == 0 {
		t.Error("A03:2021 should have findings (SQL Injection maps to A03:2021)")
	}

	// JSON file should be valid
	data, _ := os.ReadFile(out)
	var check ComplianceReport
	if err := json.Unmarshal(data, &check); err != nil {
		t.Errorf("JSON output invalid: %v", err)
	}
}

func TestGenerateComplianceReport_PCI(t *testing.T) {
	out := tempFile(t, ".json")
	report, err := GenerateComplianceReport(out, "scan-pci", sampleFindings(), FrameworkPCIDSS)
	if err != nil {
		t.Fatalf("GenerateComplianceReport PCI: %v", err)
	}
	if len(report.Controls) != len(pciControls) {
		t.Errorf("PCI Controls count = %d, want %d", len(report.Controls), len(pciControls))
	}
}

func TestGenerateComplianceHTML(t *testing.T) {
	out := tempFile(t, ".html")
	findings := sampleFindings()

	// Generate JSON first (HTML is derived from the report struct)
	jsonOut := tempFile(t, ".json")
	report, err := GenerateComplianceReport(jsonOut, "scan-html", findings, FrameworkOWASP10)
	if err != nil {
		t.Fatalf("GenerateComplianceReport: %v", err)
	}

	if err := GenerateComplianceHTML(out, "scan-html", report); err != nil {
		t.Fatalf("GenerateComplianceHTML: %v", err)
	}

	data, _ := os.ReadFile(out)
	html := string(data)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE")
	}
	if !strings.Contains(html, "SentryQ") {
		t.Error("HTML should contain SentryQ branding")
	}
	if !strings.Contains(html, "A03:2021") {
		t.Error("HTML should contain OWASP control A03:2021")
	}
}

// ─── CSV ─────────────────────────────────────────────────────────────────────

func TestWriteCSV(t *testing.T) {
	out := tempFile(t, ".csv")
	if err := WriteCSV(out, sampleFindings()); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	data, _ := os.ReadFile(out)
	csv := string(data)
	if !strings.Contains(csv, "SQL Injection") {
		t.Error("CSV should contain finding name")
	}
	if !strings.Contains(csv, "CWE-89") {
		t.Error("CSV should contain CWE")
	}
}

func TestWriteCSV_Empty(t *testing.T) {
	out := tempFile(t, ".csv")
	if err := WriteCSV(out, nil); err != nil {
		t.Fatalf("WriteCSV empty: %v", err)
	}
	info, _ := os.Stat(out)
	if info.Size() == 0 {
		t.Error("CSV with no findings should still have header row")
	}
}

// ─── SARIF ───────────────────────────────────────────────────────────────────

func TestGenerateSARIF(t *testing.T) {
	out := tempFile(t, ".sarif")
	if err := GenerateSARIF(out, sampleFindings()); err != nil {
		t.Fatalf("GenerateSARIF: %v", err)
	}
	data, _ := os.ReadFile(out)
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if doc["version"] == nil {
		t.Error("SARIF missing 'version' field")
	}
	if doc["$schema"] == nil {
		t.Error("SARIF missing '$schema' field")
	}
}

// ─── Risk Scorer ─────────────────────────────────────────────────────────────

func TestCalculateRiskScore(t *testing.T) {
	findings := sampleFindings()
	score := CalculateRiskScore(findings)
	if score.Score < 0 || score.Score > 100 {
		t.Errorf("RiskScore.Score = %d, expected 0–100", score.Score)
	}
	if score.Level == "" {
		t.Error("RiskScore.Level should not be empty")
	}
}

func TestCalculateRiskScore_Empty(t *testing.T) {
	score := CalculateRiskScore(nil)
	if score.Score != 0 {
		t.Errorf("empty findings score = %d, want 0", score.Score)
	}
}

// ─── ReportSummary ───────────────────────────────────────────────────────────

func TestGenerateReportSummary(t *testing.T) {
	findings := sampleFindings()
	summary := GenerateReportSummary(findings, "/tmp/myproject")
	if summary.TotalFindings != len(findings) {
		t.Errorf("TotalFindings = %d, want %d", summary.TotalFindings, len(findings))
	}
	if summary.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", summary.CriticalCount)
	}
	if summary.HighCount != 1 {
		t.Errorf("HighCount = %d, want 1", summary.HighCount)
	}
}

// ─── HTML ────────────────────────────────────────────────────────────────────

func TestGenerateHTMLReport(t *testing.T) {
	out := tempFile(t, ".html")
	findings := sampleFindings()
	summary := GenerateReportSummary(findings, "/tmp/proj")

	if err := GenerateHTMLReport(out, findings, summary); err != nil {
		t.Fatalf("GenerateHTMLReport: %v", err)
	}
	data, _ := os.ReadFile(out)
	html := string(data)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTML report missing DOCTYPE")
	}
	if !strings.Contains(html, "Security Scan Report") {
		t.Error("HTML report missing report title")
	}
	if !strings.Contains(html, "SQL Injection") {
		t.Error("HTML report missing finding name")
	}
}

// ─── PDF ─────────────────────────────────────────────────────────────────────

func TestGeneratePDF_Smoke(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.pdf")
	findings := sampleFindings()
	summary := GenerateReportSummary(findings, "/tmp/proj")
	riskScore := CalculateRiskScore(findings)

	if err := GeneratePDF(out, findings, summary, riskScore); err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("PDF not created: %v", err)
	}
	if info.Size() < 1000 {
		t.Errorf("PDF seems too small (%d bytes)", info.Size())
	}
	// Verify PDF magic bytes
	data, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(data), "%PDF") {
		t.Error("Output does not start with PDF magic bytes")
	}
}
