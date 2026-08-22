package reporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// WriteCSV generates the CSV report with required columns
func WriteCSV(filename string, findings []Finding) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Sr. No.", "Issue name", "File name / file path",
		"Description of the issue", "Severity", "Line number",
		"CWE", "OWASP", "Confidence", "Trust Score", "Source",
		"AI validated (yes/no)", "AI Reasoning", "Remediation",
		"Code Snippet", "Secure Fix", "Exploit PoC", "Taint Flow",
	}

	if err := writer.Write(header); err != nil {
		return err
	}

	reachable, lowPriority, falsePositives := SplitFindingsThreeWay(findings)

	// Write reachable findings
	for _, f := range reachable {
		if err := writer.Write(findingToRow(f)); err != nil {
			return err
		}
	}

	// Write lowPriority findings (optional, but keep them separate)
	if len(lowPriority) > 0 {
		blankRow := make([]string, len(header))
		if err := writer.Write(blankRow); err != nil {
			return err
		}
		sepRow := make([]string, len(header))
		sepRow[0] = "=== POTENTIALLY UNREACHABLE (TEST FILES / LOW CONFIDENCE) ==="
		if err := writer.Write(sepRow); err != nil {
			return err
		}
		if err := writer.Write(header); err != nil {
			return err
		}

		for _, f := range lowPriority {
			if err := writer.Write(findingToRow(f)); err != nil {
				return err
			}
		}
	}

	// Separator + FP section
	if len(falsePositives) > 0 {
		blankRow := make([]string, len(header))
		if err := writer.Write(blankRow); err != nil {
			return err
		}
		sepRow := make([]string, len(header))
		sepRow[0] = "=== MANUAL REVIEW — POTENTIAL FALSE POSITIVES ==="
		if err := writer.Write(sepRow); err != nil {
			return err
		}
		if err := writer.Write(header); err != nil { // repeat header for the FP section
			return err
		}

		for _, f := range falsePositives {
			if err := writer.Write(findingToRow(f)); err != nil {
				return err
			}
		}
	}

	return nil
}

// csvSafe prevents CSV formula injection by prefixing cells that start with
// formula trigger characters (=, +, -, @, TAB, CR) with a single quote.
// Spreadsheet applications strip the quote visually but will not evaluate the cell as a formula.
func csvSafe(s string) string {
	if len(s) == 0 {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func findingToRow(f Finding) []string {
	confidenceStr := "N/A"
	if f.Confidence > 0 {
		confidenceStr = fmt.Sprintf("%.0f%%", f.Confidence*100)
	}
	taintFlow := strings.Join(f.ExploitPath, " → ")
	return []string{
		strconv.Itoa(f.SrNo),
		csvSafe(f.IssueName),
		csvSafe(f.FilePath),
		csvSafe(f.Description),
		csvSafe(f.Severity),
		csvSafe(f.LineNumber),
		csvSafe(f.CWE),
		csvSafe(f.OWASP),
		csvSafe(confidenceStr),
		csvSafe(fmt.Sprintf("%.0f", f.TrustScore)),
		csvSafe(f.Source),
		csvSafe(f.AiValidated),
		csvSafe(f.AiReasoning),
		csvSafe(f.Remediation),
		csvSafe(f.CodeSnippet),
		csvSafe(f.FixedCode),
		csvSafe(f.ExploitPoC),
		csvSafe(taintFlow),
	}
}
