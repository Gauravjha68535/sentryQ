package reporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
)

// WriteCSV generates the CSV report with required columns
func WriteCSV(filename string, findings []Finding) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"Sr. No.", "Issue name", "File name / file path",
		"Description of the issue", "Severity", "Line number",
		"CWE", "OWASP", "Confidence", "Source",
		"AI validated (yes/no)", "Remediation",
		"Code Snippet", "Exploit PoC",
	}

	// Simple deduplication: Key = FilePath + LineNumber + IssueName
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

	if err := writer.Write(header); err != nil {
		return err
	}

	confirmed, falsePositives := SplitFindings(findings)

	// Write confirmed findings
	for _, f := range confirmed {
		if err := writer.Write(findingToRow(f)); err != nil {
			return err
		}
	}

	// Separator + FP section
	if len(falsePositives) > 0 {
		blankRow := make([]string, len(header))
		writer.Write(blankRow)
		sepRow := make([]string, len(header))
		sepRow[0] = "=== MANUAL REVIEW — POTENTIAL FALSE POSITIVES ==="
		writer.Write(sepRow)
		writer.Write(header) // repeat header for the FP section

		for _, f := range falsePositives {
			if err := writer.Write(findingToRow(f)); err != nil {
				return err
			}
		}
	}

	return nil
}

func findingToRow(f Finding) []string {
	confidence := f.Confidence
	if confidence <= 0 {
		confidence = 1.0
	}
	return []string{
		strconv.Itoa(f.SrNo),
		f.IssueName,
		f.FilePath,
		f.Description,
		f.Severity,
		f.LineNumber,
		f.CWE,
		f.OWASP,
		fmt.Sprintf("%.0f%%", confidence*100),
		f.Source,
		f.AiValidated,
		f.Remediation,
		f.CodeSnippet,
		f.ExploitPoC,
	}
}
