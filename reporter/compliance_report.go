package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ComplianceFramework defines a compliance standard with its controls.
type ComplianceFramework string

const (
	FrameworkOWASP10  ComplianceFramework = "OWASP Top 10 2021"
	FrameworkPCIDSS   ComplianceFramework = "PCI DSS 3.2.1"
	FrameworkNIST800  ComplianceFramework = "NIST SP 800-53"
	FrameworkHIPAA    ComplianceFramework = "HIPAA"
)

// ControlResult shows how many findings map to a compliance control.
type ControlResult struct {
	ControlID   string           `json:"control_id"`
	ControlName string           `json:"control_name"`
	Findings    []Finding        `json:"findings"`
	Status      string           `json:"status"` // "pass" | "fail" | "partial"
	Severity    string           `json:"highest_severity"`
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
	TotalControls  int `json:"total_controls"`
	PassingControls int `json:"passing_controls"`
	FailingControls int `json:"failing_controls"`
	TotalFindings  int `json:"total_findings"`
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
	{"AC-3",  "Access Enforcement", "CWE-284,CWE-285,CWE-639"},
	{"AU-9",  "Protection of Audit Information", "CWE-778,CWE-223"},
	{"CM-6",  "Configuration Settings", "CWE-16,CWE-732"},
	{"IA-5",  "Authenticator Management", "CWE-798,CWE-257,CWE-307"},
	{"SC-8",  "Transmission Confidentiality and Integrity", "CWE-311,CWE-319"},
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

func mapOWASP(findings []Finding) []ControlResult {
	// Group findings by OWASP category (A0x:2021 prefix)
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
