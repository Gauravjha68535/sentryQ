package reporter

import (
	"path/filepath"
	"strings"
	"time"
)

// RiskScore represents the overall security risk score
type RiskScore struct {
	Score            int
	Level            string
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	InfoCount        int
	AIValidatedCount int
	TotalFindings    int
	CalculatedAt     string
}

// PriorityMatrix represents remediation priority categorization
type PriorityMatrix struct {
	P0 []Finding // Critical impact, Low effort - Fix Immediately
	P1 []Finding // Critical impact, Medium effort - Fix This Sprint
	P2 []Finding // Medium impact, Low effort - Fix Next Sprint
	P3 []Finding // Low impact, Low effort - Fix When Possible
}

// CalculateRiskScore calculates overall security risk score (0-100)
func CalculateRiskScore(findings []Finding) RiskScore {
	score := 0.0

	// Weight configuration (adjust based on your risk tolerance)
	criticalWt := 10.0
	highWt := 5.0
	mediumWt := 2.0
	lowWt := 0.5

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0
	aiValidatedCount := 0

	for _, f := range findings {
		switch strings.ToLower(strings.TrimSpace(f.Severity)) {
		case "critical":
			criticalCount++
			score += criticalWt
		case "high":
			highCount++
			score += highWt
		case "medium":
			mediumCount++
			score += mediumWt
		case "low":
			lowCount++
			score += lowWt
		default:
			infoCount++
		}

		if f.AiValidated == "Yes" {
			aiValidatedCount++
		}
	}

	// Cap score at 100
	if score > 100 {
		score = 100
	}

	// Determine risk level (higher score = worse)
	level := "Low Risk"
	if score >= 75 {
		level = "Critical Risk"
	} else if score >= 50 {
		level = "High Risk"
	} else if score >= 25 {
		level = "Medium Risk"
	}

	return RiskScore{
		Score:            int(score),
		Level:            level,
		CriticalCount:    criticalCount,
		HighCount:        highCount,
		MediumCount:      mediumCount,
		LowCount:         lowCount,
		InfoCount:        infoCount,
		AIValidatedCount: aiValidatedCount,
		TotalFindings:    len(findings),
		CalculatedAt:     time.Now().Format("January 2, 2006 at 3:04 PM MST"),
	}
}

// GetPriorityMatrix categorizes findings by remediation priority
func GetPriorityMatrix(findings []Finding) PriorityMatrix {
	matrix := PriorityMatrix{
		P0: []Finding{},
		P1: []Finding{},
		P2: []Finding{},
		P3: []Finding{},
	}

	for _, f := range findings {
		// Skip AI-validated false positives
		if f.AiValidated == "No (False Positive)" {
			continue
		}

		// Priority based on severity + AI validation status
		switch f.Severity {
		case "critical":
			if f.AiValidated == "Yes" {
				matrix.P0 = append(matrix.P0, f) // Critical + AI confirmed = P0
			} else {
				matrix.P1 = append(matrix.P1, f) // Critical but not AI validated = P1
			}
		case "high":
			if f.AiValidated == "Yes" {
				matrix.P1 = append(matrix.P1, f) // High + AI confirmed = P1
			} else {
				matrix.P2 = append(matrix.P2, f) // High but not AI validated = P2
			}
		case "medium":
			if f.AiValidated == "Yes" {
				matrix.P2 = append(matrix.P2, f) // Medium + AI confirmed = P2
			} else {
				matrix.P3 = append(matrix.P3, f) // Medium but not AI validated = P3
			}
		default:
			matrix.P3 = append(matrix.P3, f) // Low/Info = P3
		}
	}

	return matrix
}



// GenerateReportSummary creates summary statistics from findings
func GenerateReportSummary(findings []Finding, targetDir string) ReportSummary {
	absDir, err := filepath.Abs(targetDir)
	if err == nil {
		targetDir = absDir
	}
	
	summary := ReportSummary{
		TotalFindings:   len(findings),
		TargetDirectory: targetDir,
		ScanDate:        time.Now().Format("January 2, 2006 at 3:04 PM MST"),
		ScannerVersion:  "2.0.0",
	}

	for _, f := range findings {
		switch strings.ToLower(strings.TrimSpace(f.Severity)) {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		default:
			summary.InfoCount++
		}

		if f.AiValidated == "Yes" {
			summary.AIValidatedCount++
		}
	}

	return summary
}

// ReportSummary holds report statistics
type ReportSummary struct {
	TotalFindings    int
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	InfoCount        int
	AIValidatedCount int
	ScanDate         string
	TargetDirectory  string
	ScannerVersion   string
}
