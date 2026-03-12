package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ComplianceFramework represents a compliance framework
type ComplianceFramework struct {
	Name        string
	Version     string
	Controls    []Control
	FindingsMap map[string][]Finding
}

// Control represents a compliance control
type Control struct {
	ID          string
	Name        string
	Description string
	Category    string
	Severity    string
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	Framework            string
	Version              string
	GeneratedAt          string
	TotalControls        int
	CompliantControls    int
	NonCompliantControls int
	ComplianceScore      float64
	Findings             []Finding
	Recommendations      []string
}

// ComplianceReporter generates compliance reports
type ComplianceReporter struct {
	frameworks map[string]*ComplianceFramework
}

// NewComplianceReporter creates a new compliance reporter
func NewComplianceReporter() *ComplianceReporter {
	return &ComplianceReporter{
		frameworks: make(map[string]*ComplianceFramework),
	}
}

// LoadFramework loads a compliance framework
func (cr *ComplianceReporter) LoadFramework(frameworkName string) error {
	switch strings.ToUpper(frameworkName) {
	case "PCI-DSS":
		cr.frameworks["PCI-DSS"] = loadPCIDSS()
	case "HIPAA":
		cr.frameworks["HIPAA"] = loadHIPAA()
	case "SOC2":
		cr.frameworks["SOC2"] = loadSOC2()
	case "ISO27001":
		cr.frameworks["ISO27001"] = loadISO27001()
	case "GDPR":
		cr.frameworks["GDPR"] = loadGDPR()
	default:
		return fmt.Errorf("unknown compliance framework: %s", frameworkName)
	}
	return nil
}

// MapFindingsToControls maps security findings to compliance controls
func (cr *ComplianceReporter) MapFindingsToControls(findings []Finding, frameworkName string) {
	framework, exists := cr.frameworks[frameworkName]
	if !exists {
		return
	}

	framework.FindingsMap = make(map[string][]Finding)

	for _, finding := range findings {
		controlID := mapFindingToControl(finding, frameworkName)
		if controlID != "" {
			framework.FindingsMap[controlID] = append(framework.FindingsMap[controlID], finding)
		}
	}
}

// GenerateComplianceReport generates a compliance report for a framework
func (cr *ComplianceReporter) GenerateComplianceReport(frameworkName string) (*ComplianceReport, error) {
	framework, exists := cr.frameworks[frameworkName]
	if !exists {
		return nil, fmt.Errorf("framework not loaded: %s", frameworkName)
	}

	report := &ComplianceReport{
		Framework:   framework.Name,
		Version:     framework.Version,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	// Sort controls by ID for deterministic output
	sort.Slice(framework.Controls, func(i, j int) bool {
		return framework.Controls[i].ID < framework.Controls[j].ID
	})

	totalControls := len(framework.Controls)
	nonCompliantControls := 0
	var recommendations []string

	for _, control := range framework.Controls {
		findings, hasFindings := framework.FindingsMap[control.ID]

		if hasFindings && len(findings) > 0 {
			nonCompliantControls++
			report.Findings = append(report.Findings, findings...)

			// Generate recommendation
			recommendations = append(recommendations,
				fmt.Sprintf("%s: %s - Found %d violations",
					control.ID, control.Name, len(findings)))
		}
	}

	report.TotalControls = totalControls
	report.NonCompliantControls = nonCompliantControls
	report.CompliantControls = totalControls - nonCompliantControls
	report.ComplianceScore = float64(report.CompliantControls) / float64(totalControls) * 100
	report.Recommendations = recommendations

	return report, nil
}

// ExportComplianceReport exports compliance report to file
func (cr *ComplianceReporter) ExportComplianceReport(report *ComplianceReport, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

// GetComplianceSummary returns a summary of all loaded frameworks
func (cr *ComplianceReporter) GetComplianceSummary() map[string]interface{} {
	summary := make(map[string]interface{})

	for name, framework := range cr.frameworks {
		nonCompliant := 0
		for _, findings := range framework.FindingsMap {
			if len(findings) > 0 {
				nonCompliant++
			}
		}

		summary[name] = map[string]interface{}{
			"total_controls":   len(framework.Controls),
			"non_compliant":    nonCompliant,
			"compliant":        len(framework.Controls) - nonCompliant,
			"compliance_score": float64(len(framework.Controls)-nonCompliant) / float64(len(framework.Controls)) * 100,
		}
	}

	return summary
}

// Helper functions to load frameworks
func loadPCIDSS() *ComplianceFramework {
	return &ComplianceFramework{
		Name:    "PCI-DSS",
		Version: "4.0",
		Controls: []Control{
			{ID: "PCI-1", Name: "Install and maintain network security controls", Category: "Network Security"},
			{ID: "PCI-2", Name: "Apply secure configurations to all system components", Category: "Configuration"},
			{ID: "PCI-3", Name: "Protect stored account data", Category: "Data Protection"},
			{ID: "PCI-4", Name: "Protect cardholder data with strong cryptography during transmission", Category: "Encryption"},
			{ID: "PCI-5", Name: "Protect all systems and networks from malicious software", Category: "Malware Protection"},
			{ID: "PCI-6", Name: "Develop and maintain secure systems and software", Category: "Secure Development"},
			{ID: "PCI-7", Name: "Restrict access to system components and cardholder data", Category: "Access Control"},
			{ID: "PCI-8", Name: "Identify users and authenticate access to system components", Category: "Authentication"},
			{ID: "PCI-9", Name: "Restrict physical access to cardholder data", Category: "Physical Security"},
			{ID: "PCI-10", Name: "Log and monitor all access to system components and cardholder data", Category: "Logging"},
			{ID: "PCI-11", Name: "Test security of systems and networks regularly", Category: "Testing"},
			{ID: "PCI-12", Name: "Support information security with organizational policies and programs", Category: "Policies"},
		},
		FindingsMap: make(map[string][]Finding),
	}
}

func loadHIPAA() *ComplianceFramework {
	return &ComplianceFramework{
		Name:    "HIPAA",
		Version: "2023",
		Controls: []Control{
			{ID: "HIPAA-164.308", Name: "Administrative Safeguards", Category: "Administrative"},
			{ID: "HIPAA-164.310", Name: "Physical Safeguards", Category: "Physical"},
			{ID: "HIPAA-164.312", Name: "Technical Safeguards", Category: "Technical"},
			{ID: "HIPAA-164.314", Name: "Organizational Requirements", Category: "Organizational"},
			{ID: "HIPAA-164.316", Name: "Policies and Procedures", Category: "Policies"},
		},
		FindingsMap: make(map[string][]Finding),
	}
}

func loadSOC2() *ComplianceFramework {
	return &ComplianceFramework{
		Name:    "SOC2",
		Version: "2017",
		Controls: []Control{
			{ID: "SOC2-CC1", Name: "Control Environment", Category: "Control Environment"},
			{ID: "SOC2-CC2", Name: "Communication and Information", Category: "Communication"},
			{ID: "SOC2-CC3", Name: "Risk Assessment", Category: "Risk Management"},
			{ID: "SOC2-CC4", Name: "Monitoring Activities", Category: "Monitoring"},
			{ID: "SOC2-CC5", Name: "Control Activities", Category: "Control Activities"},
			{ID: "SOC2-CC6", Name: "Logical and Physical Access Controls", Category: "Access Control"},
			{ID: "SOC2-CC7", Name: "System Operations", Category: "Operations"},
			{ID: "SOC2-CC8", Name: "Change Management", Category: "Change Management"},
			{ID: "SOC2-CC9", Name: "Risk Mitigation", Category: "Risk Mitigation"},
		},
		FindingsMap: make(map[string][]Finding),
	}
}

func loadISO27001() *ComplianceFramework {
	return &ComplianceFramework{
		Name:    "ISO27001",
		Version: "2022",
		Controls: []Control{
			{ID: "ISO-A5", Name: "Organizational controls", Category: "Organizational"},
			{ID: "ISO-A6", Name: "People controls", Category: "People"},
			{ID: "ISO-A7", Name: "Physical controls", Category: "Physical"},
			{ID: "ISO-A8", Name: "Technological controls", Category: "Technological"},
		},
		FindingsMap: make(map[string][]Finding),
	}
}

func loadGDPR() *ComplianceFramework {
	return &ComplianceFramework{
		Name:    "GDPR",
		Version: "2018",
		Controls: []Control{
			{ID: "GDPR-Art5", Name: "Principles relating to processing of personal data", Category: "Principles"},
			{ID: "GDPR-Art6", Name: "Lawfulness of processing", Category: "Lawfulness"},
			{ID: "GDPR-Art25", Name: "Data protection by design and by default", Category: "Design"},
			{ID: "GDPR-Art32", Name: "Security of processing", Category: "Security"},
			{ID: "GDPR-Art33", Name: "Notification of a personal data breach", Category: "Breach Notification"},
		},
		FindingsMap: make(map[string][]Finding),
	}
}

func mapFindingToControl(finding Finding, frameworkName string) string {
	// Map findings to compliance controls based on finding type
	// This is a simplified mapping - in production, use more sophisticated logic

	switch frameworkName {
	case "PCI-DSS":
		if strings.Contains(strings.ToLower(finding.IssueName), "hardcoded") ||
			strings.Contains(strings.ToLower(finding.IssueName), "secret") {
			return "PCI-3" // Protect stored account data
		}
		if strings.Contains(strings.ToLower(finding.IssueName), "sql injection") ||
			strings.Contains(strings.ToLower(finding.IssueName), "xss") {
			return "PCI-6" // Secure systems and software
		}
		if strings.Contains(strings.ToLower(finding.IssueName), "encryption") ||
			strings.Contains(strings.ToLower(finding.IssueName), "crypto") {
			return "PCI-4" // Strong cryptography
		}

	case "HIPAA":
		if strings.Contains(strings.ToLower(finding.IssueName), "password") ||
			strings.Contains(strings.ToLower(finding.IssueName), "auth") {
			return "HIPAA-164.312" // Technical safeguards
		}
		if strings.Contains(strings.ToLower(finding.IssueName), "encryption") {
			return "HIPAA-164.312" // Technical safeguards
		}

	case "SOC2":
		if strings.Contains(strings.ToLower(finding.IssueName), "access") ||
			strings.Contains(strings.ToLower(finding.IssueName), "auth") {
			return "SOC2-CC6" // Access controls
		}
		if strings.Contains(strings.ToLower(finding.IssueName), "log") ||
			strings.Contains(strings.ToLower(finding.IssueName), "audit") {
			return "SOC2-CC4" // Monitoring
		}

	case "ISO27001":
		if strings.Contains(strings.ToLower(finding.IssueName), "crypto") ||
			strings.Contains(strings.ToLower(finding.IssueName), "encryption") {
			return "ISO-A8" // Technological controls
		}

	case "GDPR":
		if strings.Contains(strings.ToLower(finding.IssueName), "personal") ||
			strings.Contains(strings.ToLower(finding.IssueName), "data") {
			return "GDPR-Art32" // Security of processing
		}
	}

	return ""
}
