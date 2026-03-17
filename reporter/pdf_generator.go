package reporter

import (
	"fmt"
	"strings"

	"github.com/jung-kurt/gofpdf"
)

// GeneratePDF generates a professional PDF report with cover page, colors, and all findings
func GeneratePDF(filename string, findings []Finding, summary ReportSummary, riskScore RiskScore) error {
	pdf := gofpdf.New("L", "mm", "A4", "")

	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(150, 150, 150)
		// Alias {nb} gets replaced with the total number of pages automatically
		pdf.CellFormat(0, 5, fmt.Sprintf("AI-Powered Security Scanner | Page %d of {nb}", pdf.PageNo()), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("") // Enables {nb} substitution

	pdf.SetAutoPageBreak(true, 15)

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
	reachable, _, falsePositives := SplitFindingsThreeWay(findings)

	// Table header — optimized column widths for A4 landscape (277mm usable)
	// #(5) Issue(40) File(45) Sev(15) Line(10) CWE(20) Src(12) Desc(130) = 277
	fColWidths := []float64{5, 40, 45, 15, 10, 20, 12, 130}
	fHeaders := []string{"#", "Issue", "File", "Severity", "Line", "CWE", "Source", "Description"}

	// 1. Confirmed Findings
	pdf.AddPage()
	addPageHeader(pdf, "Confirmed Findings")

	drawHeader := func() {
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetFillColor(55, 48, 163)
		pdf.SetTextColor(255, 255, 255)
		for i, h := range fHeaders {
			pdf.CellFormat(fColWidths[i], 8, h, "1", 0, "C", true, 0, "")
		}
		pdf.Ln(-1)
	}

	drawHeader()
	pdf.SetFont("Helvetica", "", 6.5)

	drawRow := func(idx int, f Finding, isContinuation bool, title string) {
		x, y := pdf.GetXY()

		descTxt := truncateString(f.Description, 200)
		issueTxt := truncateString(f.IssueName, 60)
		fileTxt := truncateString(f.FilePath, 60)

		descLines := pdf.SplitText(descTxt, fColWidths[7]-2)
		issueLines := pdf.SplitText(issueTxt, fColWidths[1]-2)
		fileLines := pdf.SplitText(fileTxt, fColWidths[2]-2)

		maxLines := len(descLines)
		if len(issueLines) > maxLines {
			maxLines = len(issueLines)
		}
		if len(fileLines) > maxLines {
			maxLines = len(fileLines)
		}
		if maxLines < 1 {
			maxLines = 1
		}
		if maxLines > 6 {
			maxLines = 6
		}

		h := float64(maxLines)*3.5 + 2.0
		if h < 7.0 {
			h = 7.0
		}

		if y+h > 185 {
			pdf.AddPage()
			addPageHeader(pdf, title)
			drawHeader()
			pdf.SetFont("Helvetica", "", 6.5)
			x, y = pdf.GetXY()
		}

		if idx%2 == 0 {
			pdf.SetFillColor(248, 250, 252)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetDrawColor(200, 200, 200)
		pdf.SetTextColor(30, 30, 60)

		cx := x

		// Helper to draw cell
		renderCell := func(w float64, textLines []string, align string, isSev bool, sev string) {
			pdf.Rect(cx, y, w, h, "DF")
			if isSev {
				sColor := getSeverityColor(sev)
				pdf.SetFillColor(sColor[0], sColor[1], sColor[2])
				pdf.SetTextColor(255, 255, 255)
				pdf.Rect(cx+1, y+1, w-2, h-2, "F")
			}
			pdf.SetXY(cx+1, y+1)
			if align == "C" {
				pdf.SetXY(cx, y+(h-3.5)/2)
				pdf.CellFormat(w, 3.5, textLines[0], "", 0, "C", false, 0, "")
			} else {
				lim := len(textLines)
				if lim > maxLines {
					lim = maxLines
				}
				pdf.MultiCell(w-2, 3.5, strings.Join(textLines[:lim], "\n"), "", align, false)
			}
			if isSev {
				if idx%2 == 0 {
					pdf.SetFillColor(248, 250, 252)
				} else {
					pdf.SetFillColor(255, 255, 255)
				}
				pdf.SetTextColor(30, 30, 60)
			}
			cx += w
		}

		renderCell(fColWidths[0], []string{fmt.Sprintf("%d", f.SrNo)}, "C", false, "")
		renderCell(fColWidths[1], issueLines, "L", false, "")
		renderCell(fColWidths[2], fileLines, "L", false, "")
		renderCell(fColWidths[3], []string{strings.ToUpper(f.Severity)}, "C", true, f.Severity)
		renderCell(fColWidths[4], []string{f.LineNumber}, "C", false, "")
		renderCell(fColWidths[5], []string{extractCWEID(f.CWE)}, "C", false, "")
		renderCell(fColWidths[6], []string{truncateSource(f.Source)}, "C", false, "")
		renderCell(fColWidths[7], descLines, "L", false, "")

		pdf.SetXY(x, y+h)
	}

	for idx, f := range reachable {
		drawRow(idx, f, true, "Confirmed Findings (continued)")
	}

	// 2. False Positives
	if len(falsePositives) > 0 {
		pdf.AddPage()
		addPageHeader(pdf, "Manual Review — Potential False Positives")
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(120, 120, 140)
		pdf.MultiCell(0, 5, "Flagged as potential false positives by AI/ML models.", "", "L", false)
		pdf.Ln(4)
		drawHeader()
		pdf.SetFont("Helvetica", "", 6.5)

		for idx, f := range falsePositives {
			drawRow(idx, f, true, "Manual Review (continued)")
		}
	}

	return pdf.OutputFileAndClose(filename)
}

func truncateString(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
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

// sanitizePDFText prepares text for the PDF library, which mostly supports ISO-8859-1.
// It replaces common Unicode characters with ASCII equivalents and others with '?'.
func sanitizePDFText(text string) string {
	// 1. Remove control characters except tab, newline, carriage return
	var sb strings.Builder
	for _, r := range text {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			continue
		}
		sb.WriteRune(r)
	}
	text = sb.String()

	// 2. Map common Unicode punctuation to ASCII
	replacer := strings.NewReplacer(
		"\u2014", "-", // em dash
		"\u2013", "-", // en dash
		"\u2026", "...", // ellipsis
		"\u2022", "*", // bullet
		"\u00A0", " ", // non-breaking space
		"\u2018", "'", // smart single quote
		"\u2019", "'", // smart single quote
		"\u201C", "\"", // smart double quote
		"\u201D", "\"", // smart double quote
	)
	text = replacer.Replace(text)

	// 3. For any remaining non-ASCII characters, replace with '?'
	// because gofpdf default fonts (Helvetica) don't support multi-byte Unicode.
	var finalSb strings.Builder
	for _, r := range text {
		if r > 126 {
			finalSb.WriteRune('?')
		} else {
			finalSb.WriteRune(r)
		}
	}

	return finalSb.String()
}
