package reporter

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

// ComplianceFramework defines a compliance standard with its controls.
type ComplianceFramework string

const (
	FrameworkOWASP10 ComplianceFramework = "OWASP Top 10 2021"
	FrameworkPCIDSS  ComplianceFramework = "PCI DSS 3.2.1"
	FrameworkNIST800 ComplianceFramework = "NIST SP 800-53"
	FrameworkHIPAA   ComplianceFramework = "HIPAA"
)

// ControlResult shows how many findings map to a compliance control.
type ControlResult struct {
	ControlID   string    `json:"control_id"`
	ControlName string    `json:"control_name"`
	Findings    []Finding `json:"findings"`
	Status      string    `json:"status"`   // "pass" | "fail" | "partial"
	Severity    string    `json:"highest_severity"`
}

// ComplianceReport is the full output of a compliance evaluation.
type ComplianceReport struct {
	Framework     ComplianceFramework `json:"framework"`
	GeneratedAt   string              `json:"generated_at"`
	ScanID        string              `json:"scan_id"`
	OverallStatus string              `json:"overall_status"` // "compliant" | "non-compliant"
	Controls      []ControlResult     `json:"controls"`
	Summary       ComplianceSummary   `json:"summary"`
}

type ComplianceSummary struct {
	TotalControls   int `json:"total_controls"`
	PassingControls int `json:"passing_controls"`
	FailingControls int `json:"failing_controls"`
	TotalFindings   int `json:"total_findings"`
}

// ── OWASP Top 10 2021 mapping ─────────────────────────────────────────────────

var owaspControls = []struct{ id, name string }{
	{"A01:2021", "Broken Access Control"},
	{"A02:2021", "Cryptographic Failures"},
	{"A03:2021", "Injection"},
	{"A04:2021", "Insecure Design"},
	{"A05:2021", "Security Misconfiguration"},
	{"A06:2021", "Vulnerable and Outdated Components"},
	{"A07:2021", "Identification and Authentication Failures"},
	{"A08:2021", "Software and Data Integrity Failures"},
	{"A09:2021", "Security Logging and Monitoring Failures"},
	{"A10:2021", "Server-Side Request Forgery"},
}

// ── PCI DSS requirement mapping via CWE ──────────────────────────────────────

var pciControls = []struct{ id, name, cwes string }{
	{"6.2", "Protect system components from known vulnerabilities", "CWE-89,CWE-78,CWE-79,CWE-94"},
	{"6.3", "Security vulnerabilities in bespoke and custom software", "CWE-798,CWE-327,CWE-330"},
	{"6.4", "Public-facing web applications are protected", "CWE-79,CWE-89,CWE-352"},
	{"8.2", "User identification and authentication management", "CWE-287,CWE-307,CWE-798"},
	{"8.6", "All user and system account usage is monitored", "CWE-778,CWE-223"},
	{"4.2", "Protect cardholder data with strong cryptography", "CWE-326,CWE-327,CWE-311"},
}

// ── NIST 800-53 mapping via CWE ───────────────────────────────────────────────

var nistControls = []struct{ id, name, cwes string }{
	{"AC-3", "Access Enforcement", "CWE-284,CWE-285,CWE-639"},
	{"AU-9", "Protection of Audit Information", "CWE-778,CWE-223"},
	{"CM-6", "Configuration Settings", "CWE-16,CWE-732"},
	{"IA-5", "Authenticator Management", "CWE-798,CWE-257,CWE-307"},
	{"SC-8", "Transmission Confidentiality and Integrity", "CWE-311,CWE-319"},
	{"SC-28", "Protection of Information at Rest", "CWE-312,CWE-326"},
	{"SI-10", "Information Input Validation", "CWE-89,CWE-78,CWE-79,CWE-20"},
}

// GenerateComplianceReport maps findings to the given compliance framework
// and writes a JSON report to filename.
func GenerateComplianceReport(filename, scanID string, findings []Finding, framework ComplianceFramework) (*ComplianceReport, error) {
	var controls []ControlResult

	switch framework {
	case FrameworkOWASP10:
		controls = mapOWASP(findings)
	case FrameworkPCIDSS:
		controls = mapPCI(findings)
	case FrameworkNIST800:
		controls = mapNIST(findings)
	default:
		controls = mapOWASP(findings)
	}

	passing, failing := 0, 0
	totalFindings := 0
	for _, c := range controls {
		totalFindings += len(c.Findings)
		if c.Status == "pass" {
			passing++
		} else {
			failing++
		}
	}

	overall := "compliant"
	for _, c := range controls {
		if c.Status == "fail" && (c.Severity == "critical" || c.Severity == "high") {
			overall = "non-compliant"
			break
		}
	}

	report := &ComplianceReport{
		Framework:     framework,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		ScanID:        scanID,
		OverallStatus: overall,
		Controls:      controls,
		Summary: ComplianceSummary{
			TotalControls:   len(controls),
			PassingControls: passing,
			FailingControls: failing,
			TotalFindings:   totalFindings,
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return report, fmt.Errorf("compliance: marshal failed: %w", err)
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return report, fmt.Errorf("compliance: write failed: %w", err)
	}
	return report, nil
}

// GenerateComplianceHTML writes a clean HTML compliance report to filename.
func GenerateComplianceHTML(filename, scanID string, report *ComplianceReport) error {
	overallColor := "#22c55e"
	overallText := "COMPLIANT"
	if report.OverallStatus == "non-compliant" {
		overallColor = "#ef4444"
		overallText = "NON-COMPLIANT"
	}

	var rows strings.Builder
	for _, ctrl := range report.Controls {
		statusColor := "#22c55e"
		statusText := "PASS"
		if ctrl.Status == "fail" {
			statusColor = "#ef4444"
			statusText = "FAIL"
		}
		sevColor := "#6b7280"
		switch ctrl.Severity {
		case "critical":
			sevColor = "#ef4444"
		case "high":
			sevColor = "#f97316"
		case "medium":
			sevColor = "#f59e0b"
		case "low":
			sevColor = "#3b82f6"
		}
		sevText := ctrl.Severity
		if sevText == "" {
			sevText = "—"
		}
		rows.WriteString(fmt.Sprintf(`
			<tr>
				<td style="font-family:monospace;font-weight:600">%s</td>
				<td>%s</td>
				<td><span style="background:%s;color:#fff;padding:2px 10px;border-radius:12px;font-size:0.78rem;font-weight:700">%s</span></td>
				<td style="text-align:center;font-weight:600">%d</td>
				<td style="color:%s;font-weight:600;text-transform:capitalize">%s</td>
			</tr>`,
			html.EscapeString(ctrl.ControlID),
			html.EscapeString(ctrl.ControlName),
			statusColor, statusText,
			len(ctrl.Findings),
			sevColor, html.EscapeString(sevText),
		))
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentryQ Compliance Report — %s</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:32px}
h1{color:#6366f1;margin-bottom:4px}
.badge{display:inline-block;padding:4px 16px;border-radius:20px;font-weight:700;font-size:1rem;color:#fff;background:%s}
.summary{display:flex;gap:24px;margin:24px 0}
.stat{background:#1e293b;border-radius:12px;padding:16px 24px;min-width:120px;text-align:center}
.stat-n{font-size:2rem;font-weight:800;color:#6366f1}
.stat-l{font-size:0.75rem;color:#94a3b8;margin-top:4px}
table{width:100%%;border-collapse:collapse;background:#1e293b;border-radius:12px;overflow:hidden}
th{background:#334155;padding:12px 16px;text-align:left;font-size:0.78rem;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8}
td{padding:12px 16px;border-bottom:1px solid #334155;font-size:0.88rem}
tr:last-child td{border-bottom:none}
tr:hover td{background:#253044}
.footer{margin-top:32px;font-size:0.75rem;color:#64748b}
</style>
</head>
<body>
<h1>SentryQ Compliance Report</h1>
<p style="color:#94a3b8">Framework: <strong style="color:#e2e8f0">%s</strong> &nbsp;|&nbsp; Scan ID: <code>%s</code> &nbsp;|&nbsp; Generated: %s</p>
<div>Overall Status: <span class="badge">%s</span></div>
<div class="summary">
  <div class="stat"><div class="stat-n">%d</div><div class="stat-l">Controls</div></div>
  <div class="stat"><div class="stat-n" style="color:#22c55e">%d</div><div class="stat-l">Passing</div></div>
  <div class="stat"><div class="stat-n" style="color:#ef4444">%d</div><div class="stat-l">Failing</div></div>
  <div class="stat"><div class="stat-n">%d</div><div class="stat-l">Findings</div></div>
</div>
<table>
<thead><tr>
  <th>Control ID</th><th>Control Name</th><th>Status</th><th>Findings</th><th>Highest Severity</th>
</tr></thead>
<tbody>%s</tbody>
</table>
<div class="footer">Generated by SentryQ &nbsp;|&nbsp; %s</div>
</body>
</html>`,
		html.EscapeString(scanID),
		overallColor,
		html.EscapeString(string(report.Framework)),
		html.EscapeString(scanID),
		report.GeneratedAt,
		overallText,
		report.Summary.TotalControls,
		report.Summary.PassingControls,
		report.Summary.FailingControls,
		report.Summary.TotalFindings,
		rows.String(),
		time.Now().UTC().Format("2006-01-02 15:04 UTC"),
	)

	return os.WriteFile(filename, []byte(htmlContent), 0644)
}

func mapOWASP(findings []Finding) []ControlResult {
	byControl := make(map[string][]Finding)
	for _, f := range findings {
		if f.Status == "false_positive" || f.Status == "ignored" {
			continue
		}
		cat := normaliseOWASPCat(f.OWASP)
		if cat != "" {
			byControl[cat] = append(byControl[cat], f)
		}
	}

	var results []ControlResult
	for _, ctrl := range owaspControls {
		fs := byControl[ctrl.id]
		results = append(results, ControlResult{
			ControlID:   ctrl.id,
			ControlName: ctrl.name,
			Findings:    fs,
			Status:      statusFromFindings(fs),
			Severity:    highestSeverity(fs),
		})
	}
	return results
}

func mapPCI(findings []Finding) []ControlResult {
	var results []ControlResult
	for _, ctrl := range pciControls {
		cwes := strings.Split(ctrl.cwes, ",")
		fs := filterByCWE(findings, cwes)
		results = append(results, ControlResult{
			ControlID:   ctrl.id,
			ControlName: ctrl.name,
			Findings:    fs,
			Status:      statusFromFindings(fs),
			Severity:    highestSeverity(fs),
		})
	}
	return results
}

func mapNIST(findings []Finding) []ControlResult {
	var results []ControlResult
	for _, ctrl := range nistControls {
		cwes := strings.Split(ctrl.cwes, ",")
		fs := filterByCWE(findings, cwes)
		results = append(results, ControlResult{
			ControlID:   ctrl.id,
			ControlName: ctrl.name,
			Findings:    fs,
			Status:      statusFromFindings(fs),
			Severity:    highestSeverity(fs),
		})
	}
	return results
}

// ── helpers ───────────────────────────────────────────────────────────────────

func filterByCWE(findings []Finding, cwes []string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Status == "false_positive" || f.Status == "ignored" {
			continue
		}
		for _, cwe := range cwes {
			if strings.Contains(strings.ToUpper(f.CWE), strings.TrimSpace(cwe)) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func statusFromFindings(fs []Finding) string {
	if len(fs) == 0 {
		return "pass"
	}
	return "fail"
}

func highestSeverity(fs []Finding) string {
	order := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
	best := ""
	bestScore := -1
	for _, f := range fs {
		sev := strings.ToLower(f.Severity)
		if score, ok := order[sev]; ok && score > bestScore {
			bestScore = score
			best = sev
		}
	}
	return best
}

func normaliseOWASPCat(s string) string {
	if s == "" {
		return ""
	}
	upper := strings.ToUpper(s)
	for _, ctrl := range owaspControls {
		if strings.Contains(upper, strings.ToUpper(ctrl.id)) {
			return ctrl.id
		}
	}
	return ""
}
