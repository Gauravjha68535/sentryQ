package reporter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jung-kurt/gofpdf"
)

// GeneratePDF generates a professional PDF report with cover page, colors, and all findings
func GeneratePDF(filename string, findings []Finding, summary ReportSummary, riskScore RiskScore) error {
	pdf := gofpdf.New("L", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 15)

	// Simple deduplication
	uniqueFindings := make([]Finding, 0)
	seen := make(map[string]bool)
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%s", f.FilePath, f.LineNumber, f.IssueName)
		if !seen[key] {
			seen[key] = true
			uniqueFindings = append(uniqueFindings, f)
		}
	}
	findings = uniqueFindings

	// ——— Cover Page ———
	pdf.AddPage()
	pdf.SetFillColor(55, 48, 163) // Indigo
	pdf.Rect(0, 0, 297, 210, "F")

	// Title block
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 36)
	pdf.SetY(50)
	pdf.CellFormat(297, 15, "Security Scan Report", "", 1, "C", false, 0, "")
	pdf.Ln(5)

	pdf.SetFont("Helvetica", "", 14)
	pdf.CellFormat(297, 8, fmt.Sprintf("Target: %s", summary.TargetDirectory), "", 1, "C", false, 0, "")
	pdf.CellFormat(297, 8, fmt.Sprintf("Generated: %s", summary.ScanDate), "", 1, "C", false, 0, "")
	pdf.CellFormat(297, 8, fmt.Sprintf("Scanner Version: v%s", summary.ScannerVersion), "", 1, "C", false, 0, "")
	pdf.Ln(15)

	// Risk Score Box
	scoreColor := getScoreColor(riskScore.Level)
	pdf.SetFillColor(scoreColor[0], scoreColor[1], scoreColor[2])
	boxW, boxH := 80.0, 40.0
	boxX := (297 - boxW) / 2
	pdf.RoundedRect(boxX, pdf.GetY(), boxW, boxH, 5, "1234", "F")
	pdf.SetFont("Helvetica", "B", 32)
	pdf.SetY(pdf.GetY() + 5)
	pdf.CellFormat(297, 14, fmt.Sprintf("%d / 100", riskScore.Score), "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "", 12)
	pdf.CellFormat(297, 8, riskScore.Level, "", 1, "C", false, 0, "")

	// Footer text on cover
	pdf.SetY(180)
	pdf.SetFont("Helvetica", "I", 10)
	pdf.SetTextColor(200, 200, 255)
	pdf.CellFormat(297, 6, "AI-Powered Source Code Security Scanner", "", 1, "C", false, 0, "")

	// ——— Executive Summary Page ———
	pdf.AddPage()
	addPageHeader(pdf, "Executive Summary")

	// Summary Stats Table
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetFillColor(55, 48, 163)
	pdf.SetTextColor(255, 255, 255)
	colWidths := []float64{55, 55, 55, 55, 55}
	headers := []string{"Total Findings", "Critical", "High", "Medium", "Low"}
	for i, h := range headers {
		pdf.CellFormat(colWidths[i], 10, h, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	// Values row with severity colors
	pdf.SetFont("Helvetica", "B", 14)
	values := []int{summary.TotalFindings, summary.CriticalCount, summary.HighCount, summary.MediumCount, summary.LowCount}
	colors := [][3]int{{240, 240, 245}, {254, 226, 226}, {255, 237, 213}, {254, 252, 232}, {236, 254, 255}}
	textColors := [][3]int{{30, 30, 60}, {220, 38, 38}, {234, 88, 12}, {161, 98, 7}, {8, 145, 178}}

	for i, v := range values {
		pdf.SetFillColor(colors[i][0], colors[i][1], colors[i][2])
		pdf.SetTextColor(textColors[i][0], textColors[i][1], textColors[i][2])
		pdf.CellFormat(colWidths[i], 14, fmt.Sprintf("%d", v), "1", 0, "C", true, 0, "")
	}
	pdf.Ln(20)

	// AI Summary
	pdf.SetTextColor(30, 30, 60)
	pdf.SetFont("Helvetica", "", 11)
	pdf.MultiCell(0, 6, fmt.Sprintf(
		"This scan analyzed the directory '%s' and discovered %d potential security issues. "+
			"Of these, %d are classified as Critical and require immediate attention, "+
			"%d are High severity, %d are Medium, and %d are Low priority. "+
			"%d findings were validated or discovered by AI analysis.",
		summary.TargetDirectory, summary.TotalFindings,
		summary.CriticalCount, summary.HighCount, summary.MediumCount, summary.LowCount,
		summary.AIValidatedCount), "", "L", false)

	// ——— Findings Table ———
	confirmed, falsePositives := SplitFindings(findings)

	pdf.AddPage()
	addPageHeader(pdf, "Confirmed Findings")

	// Table header — optimized column widths for A4 landscape (277mm usable)
	// #(5) Issue(40) File(45) Sev(15) Line(10) CWE(20) Src(12) Desc(130) = 277
	fColWidths := []float64{5, 40, 45, 15, 10, 20, 12, 130}
	fHeaders := []string{"#", "Issue", "File", "Severity", "Line", "CWE", "Source", "Description"}

	drawPDFTableHeader := func() {
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetFillColor(55, 48, 163)
		pdf.SetTextColor(255, 255, 255)
		for i, h := range fHeaders {
			pdf.CellFormat(fColWidths[i], 8, h, "1", 0, "C", true, 0, "")
		}
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", 6.5)
	}

	drawPDFTableHeader()

	drawFindingRow := func(idx int, f Finding) {
		// Alternate row colors
		if idx%2 == 0 {
			pdf.SetFillColor(248, 250, 252)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetTextColor(30, 30, 60)

		pdf.CellFormat(fColWidths[0], 7, fmt.Sprintf("%d", f.SrNo), "1", 0, "C", true, 0, "")
		pdf.CellFormat(fColWidths[1], 7, truncateString(f.IssueName, 30), "1", 0, "L", true, 0, "")
		pdf.CellFormat(fColWidths[2], 7, truncateString(f.FilePath, 32), "1", 0, "L", true, 0, "")

		// Color the severity cell
		sevColor := getSeverityColor(f.Severity)
		pdf.SetFillColor(sevColor[0], sevColor[1], sevColor[2])
		pdf.SetTextColor(255, 255, 255)
		pdf.CellFormat(fColWidths[3], 7, strings.ToUpper(f.Severity[:min(len(f.Severity), 4)]), "1", 0, "C", true, 0, "")

		// Reset colors
		if idx%2 == 0 {
			pdf.SetFillColor(248, 250, 252)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetTextColor(30, 30, 60)

		pdf.CellFormat(fColWidths[4], 7, f.LineNumber, "1", 0, "C", true, 0, "")
		pdf.CellFormat(fColWidths[5], 7, extractCWEID(f.CWE), "1", 0, "C", true, 0, "")
		pdf.CellFormat(fColWidths[6], 7, truncateSource(f.Source), "1", 0, "C", true, 0, "")
		pdf.CellFormat(fColWidths[7], 7, truncateString(f.Description, 120), "1", 0, "L", true, 0, "")
		pdf.Ln(-1)

		// Auto page break with repeated header
		if pdf.GetY() > 190 {
			pdf.AddPage()
			addPageHeader(pdf, fmt.Sprintf("Confirmed Findings (continued - page %d)", pdf.PageNo()-2))
			drawPDFTableHeader()
		}
	}

	for idx, f := range confirmed {
		drawFindingRow(idx, f)
	}

	// ——— Compliance Matrix Page ———
	generateComplianceMatrix(pdf, confirmed)

	// ——— False Positives (Manual Review) Section ———
	if len(falsePositives) > 0 {
		pdf.AddPage()
		addPageHeader(pdf, "Manual Review — Potential False Positives")

		// Info text
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(120, 120, 140)
		pdf.MultiCell(0, 5, "The following findings were flagged as potential false positives by the AI validator. "+
			"They are listed separately for manual review by a security engineer.", "", "L", false)
		pdf.Ln(6)

		drawPDFTableHeader()

		for idx, f := range falsePositives {
			drawFindingRow(idx, f)
		}
	}

	// ——— Footer on each page ———
	lastContentPage := pdf.PageNo()
	totalPages := lastContentPage
	for i := 1; i <= totalPages; i++ {
		pdf.SetPage(i)
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(150, 150, 150)
		pdf.CellFormat(0, 5, fmt.Sprintf("AI-Powered Security Scanner | Page %d of %d", i, totalPages), "", 0, "C", false, 0, "")
	}

	return pdf.OutputFileAndClose(filename)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func truncateSource(s string) string {
	switch {
	case strings.Contains(s, "ai"):
		return "AI"
	case strings.Contains(s, "semgrep"):
		return "Semgrep"
	case strings.Contains(s, "secret"):
		return "Secret"
	default:
		return "Rules"
	}
}

// extractCWEID extracts just the CWE-NNN ID from a full CWE string.
// e.g. "CWE-312: Use of a Hard-coded Cryptographic Key" -> "CWE-312"
func extractCWEID(cwe string) string {
	if cwe == "" {
		return ""
	}
	if idx := strings.Index(cwe, ":"); idx > 0 {
		return strings.TrimSpace(cwe[:idx])
	}
	// Already just an ID like "CWE-89"
	return truncateString(cwe, 18)
}

func addPageHeader(pdf *gofpdf.Fpdf, title string) {
	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetTextColor(55, 48, 163)
	pdf.CellFormat(0, 10, title, "", 1, "L", false, 0, "")
	pdf.SetDrawColor(55, 48, 163)
	pdf.SetLineWidth(0.5)
	pdf.Line(10, pdf.GetY(), 287, pdf.GetY())
	pdf.Ln(8)
}

func getScoreColor(level string) [3]int {
	switch level {
	case "Critical Risk":
		return [3]int{220, 38, 38}
	case "High Risk":
		return [3]int{234, 88, 12}
	case "Medium Risk":
		return [3]int{202, 138, 4}
	default:
		return [3]int{22, 163, 74}
	}
}

func getSeverityColor(sev string) [3]int {
	switch strings.ToLower(sev) {
	case "critical":
		return [3]int{220, 38, 38}
	case "high":
		return [3]int{234, 88, 12}
	case "medium":
		return [3]int{180, 140, 20}
	case "low":
		return [3]int{8, 145, 178}
	default:
		return [3]int{107, 114, 128}
	}
}

// generateComplianceMatrix maps technical findings to ISO-27001 / SOC-2 Controls for auditors
func generateComplianceMatrix(pdf *gofpdf.Fpdf, findings []Finding) {
	pdf.AddPage()
	addPageHeader(pdf, "Compliance Matrix (ISO-27001 / SOC-2)")

	pdf.SetFont("Helvetica", "I", 9)
	pdf.SetTextColor(120, 120, 140)
	pdf.MultiCell(0, 5, "This compliance matrix maps discovered vulnerabilities to common enterprise security frameworks. This helps auditors and compliance officers understand the organizational impact of the technical findings.", "", "L", false)
	pdf.Ln(6)

	type ControlStatus struct {
		Name       string
		Violations int
		Severity   string // Highest severity found for this control
	}

	controls := map[string]*ControlStatus{
		"ISO-27001: A.14.2.1": {Name: "Secure Development Policy (Inject/XSS)", Violations: 0, Severity: "Low"},
		"ISO-27001: A.9.4.1":  {Name: "Secure Log-on Procedures (Auth)", Violations: 0, Severity: "Low"},
		"ISO-27001: A.10.1.1": {Name: "Policy on the Use of Cryptographic Controls", Violations: 0, Severity: "Low"},
		"ISO-27001: A.12.6.1": {Name: "Management of Technical Vulnerabilities (SCA/Patching)", Violations: 0, Severity: "Low"},
		"ISO-27001: A.13.1.1": {Name: "Network Controls (Cleartext/Insecure Transport)", Violations: 0, Severity: "Low"},
		"ISO-27001: A.8.2.3":  {Name: "Handling of Assets (Secrets & Keys)", Violations: 0, Severity: "Low"},
	}

	for _, f := range findings {
		desc := strings.ToLower(f.IssueName + " " + f.CWE + " " + f.RuleID)

		var targetControl string
		if strings.Contains(desc, "sql") || strings.Contains(desc, "xss") || strings.Contains(desc, "injection") || strings.Contains(desc, "template") {
			targetControl = "ISO-27001: A.14.2.1"
		} else if strings.Contains(desc, "auth") || strings.Contains(desc, "jwt") || strings.Contains(desc, "session") {
			targetControl = "ISO-27001: A.9.4.1"
		} else if strings.Contains(desc, "crypto") || strings.Contains(desc, "md5") || strings.Contains(desc, "sha1") {
			targetControl = "ISO-27001: A.10.1.1"
		} else if strings.Contains(desc, "cve") || strings.Contains(desc, "sca") || strings.Contains(desc, "dependency") || strings.Contains(desc, "outdated") {
			targetControl = "ISO-27001: A.12.6.1"
		} else if strings.Contains(desc, "http:") || strings.Contains(desc, "cleartext") || strings.Contains(desc, "transport") {
			targetControl = "ISO-27001: A.13.1.1"
		} else if strings.Contains(desc, "secret") || strings.Contains(desc, "key") || strings.Contains(desc, "token") || strings.Contains(desc, "password") {
			targetControl = "ISO-27001: A.8.2.3"
		} else {
			targetControl = "ISO-27001: A.14.2.1" // Fallback to general secure dev
		}

		status := controls[targetControl]
		status.Violations++

		// Update highest severity
		fSev := strings.ToLower(f.Severity)
		if fSev == "critical" {
			status.Severity = "Critical"
		} else if fSev == "high" && status.Severity != "Critical" {
			status.Severity = "High"
		} else if fSev == "medium" && status.Severity == "Low" {
			status.Severity = "Medium"
		}
	}

	// Draw Compliance Table Header
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetFillColor(55, 48, 163)
	pdf.SetTextColor(255, 255, 255)
	cColWidths := []float64{50, 150, 40, 37}
	cHeaders := []string{"Control ID", "Control Objective Description", "Violations", "Max Severity"}
	for i, h := range cHeaders {
		pdf.CellFormat(cColWidths[i], 10, h, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	// Draw Rows
	idx := 0

	// Create a sorted list of control IDs for deterministic PDF output
	var controlIDs []string
	for id := range controls {
		controlIDs = append(controlIDs, id)
	}
	sort.Strings(controlIDs)

	for _, id := range controlIDs {
		status := controls[id]
		if status.Violations == 0 {
			continue // Only show failed controls to keep report clean
		}

		if idx%2 == 0 {
			pdf.SetFillColor(248, 250, 252)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetTextColor(30, 30, 60)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(cColWidths[0], 9, id, "1", 0, "C", true, 0, "")

		pdf.SetFont("Helvetica", "", 9)
		pdf.CellFormat(cColWidths[1], 9, " "+status.Name, "1", 0, "L", true, 0, "")

		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(cColWidths[2], 9, fmt.Sprintf("%d", status.Violations), "1", 0, "C", true, 0, "")

		sevColor := getSeverityColor(status.Severity)
		pdf.SetFillColor(sevColor[0], sevColor[1], sevColor[2])
		pdf.SetTextColor(255, 255, 255)
		pdf.CellFormat(cColWidths[3], 9, strings.ToUpper(status.Severity), "1", 0, "C", true, 0, "")

		pdf.Ln(-1)
		idx++
	}

	if idx == 0 {
		pdf.SetFont("Helvetica", "I", 10)
		pdf.SetTextColor(22, 163, 74) // Green
		pdf.CellFormat(277, 15, "Excellent! No compliance violations detected for mapped controls.", "1", 1, "C", false, 0, "")
	}
}
