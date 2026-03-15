package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
)

// FPHistory stores historical false positive data
type FPHistory struct {
	Findings      []FindingFeedback `json:"findings"`
	LastUpdated   string            `json:"last_updated"`
	TotalFeedback int               `json:"total_feedback"`
}

// FindingFeedback stores user feedback on a finding
type FindingFeedback struct {
	FindingID       string    `json:"finding_id"`
	RuleID          string    `json:"rule_id"`
	FilePath        string    `json:"file_path"`
	Severity        string    `json:"severity"`
	IsFalsePositive bool      `json:"is_false_positive"`
	FeedbackDate    time.Time `json:"feedback_date"`
	Comments        string    `json:"comments"`
}

// MLFPReducer performs machine learning-based false positive reduction
type MLFPReducer struct {
	history     *FPHistory
	historyFile string
}

// NewMLFPReducer creates a new ML false positive reducer
func NewMLFPReducer(cacheDir string) *MLFPReducer {
	return &MLFPReducer{
		history: &FPHistory{
			Findings:    make([]FindingFeedback, 0),
			LastUpdated: time.Now().Format(time.RFC3339),
		},
		historyFile: filepath.Join(cacheDir, ".fp-history.json"),
	}
}

// LoadHistory loads historical feedback data
func (ml *MLFPReducer) LoadHistory() error {
	data, err := os.ReadFile(ml.historyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No history file yet
		}
		return err
	}

	return json.Unmarshal(data, &ml.history)
}

// SaveHistory saves historical feedback data
func (ml *MLFPReducer) SaveHistory() error {
	ml.history.LastUpdated = time.Now().Format(time.RFC3339)
	ml.history.TotalFeedback = len(ml.history.Findings)

	data, err := json.MarshalIndent(ml.history, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ml.historyFile, data, 0644)
}

// CalculateFPProbability calculates the probability that a finding is a false positive
func (ml *MLFPReducer) CalculateFPProbability(finding reporter.Finding) float64 {
	if len(ml.history.Findings) == 0 {
		return 0.0 // No history, default to 0% FP (assume true positive)
	}

	// Find similar historical findings
	similarFindings := ml.findSimilarFindings(finding)

	if len(similarFindings) < 3 {
		return 0.0 // Not enough similar findings for a confident prediction
	}

	// Calculate FP rate from similar findings
	fpCount := 0
	for _, f := range similarFindings {
		if f.IsFalsePositive {
			fpCount++
		}
	}

	return float64(fpCount) / float64(len(similarFindings))
}

// findSimilarFindings finds historically similar findings
func (ml *MLFPReducer) findSimilarFindings(current reporter.Finding) []FindingFeedback {
	var similar []FindingFeedback

	for _, feedback := range ml.history.Findings {
		score := ml.calculateSimilarityScore(current, feedback)
		if score > 0.8 { // 80% similarity threshold
			similar = append(similar, feedback)
		}
	}

	return similar
}

// calculateSimilarityScore calculates similarity between current and historical finding
func (ml *MLFPReducer) calculateSimilarityScore(current reporter.Finding, historical FindingFeedback) float64 {
	score := 0.0
	maxScore := 4.0

	// Rule ID match (most important)
	if current.RuleID == historical.RuleID {
		score += 2.0
	} else if strings.Contains(current.RuleID, historical.RuleID) ||
		strings.Contains(historical.RuleID, current.RuleID) {
		score += 1.0
	}

	// Severity match
	if current.Severity == historical.Severity {
		score += 1.0
	}

	// File extension match
	currentExt := getFileExtension(current.FilePath)
	historicalExt := getFileExtension(historical.FilePath)
	if currentExt == historicalExt {
		score += 1.0
	}

	return score / maxScore
}

// FilterFindingsByFPProbability filters findings based on FP probability
func (ml *MLFPReducer) FilterFindingsByFPProbability(findings []reporter.Finding, threshold float64) []reporter.Finding {
	var filtered []reporter.Finding

	for _, finding := range findings {
		fpProb := ml.CalculateFPProbability(finding)

		// If FP probability is below threshold, keep the finding
		if fpProb < threshold {
			if fpProb > 0.0 {
				finding.Description = fmt.Sprintf("%s [ML FP Probability: %.1f%%]",
					finding.Description, fpProb*100)
			}
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// GetFPStatistics returns false positive statistics
func (ml *MLFPReducer) GetFPStatistics() map[string]interface{} {
	stats := map[string]interface{}{
		"total_feedback":  len(ml.history.Findings),
		"false_positives": 0,
		"true_positives":  0,
		"fp_rate":         0.0,
		"fp_by_rule":      make(map[string]int),
		"fp_by_severity":  make(map[string]int),
		"fp_by_language":  make(map[string]int),
	}

	fpCount := 0
	tpCount := 0

	for _, feedback := range ml.history.Findings {
		if feedback.IsFalsePositive {
			fpCount++
			stats["fp_by_rule"].(map[string]int)[feedback.RuleID]++
			stats["fp_by_severity"].(map[string]int)[feedback.Severity]++
			stats["fp_by_language"].(map[string]int)[getFileExtension(feedback.FilePath)]++
		} else {
			tpCount++
		}
	}

	stats["false_positives"] = fpCount
	stats["true_positives"] = tpCount
	if fpCount+tpCount > 0 {
		stats["fp_rate"] = float64(fpCount) / float64(fpCount+tpCount)
	}

	return stats
}

// Helper functions
func getFileExtension(filePath string) string {
	ext := filepath.Ext(filePath)
	if ext == "" {
		return "unknown"
	}
	return strings.TrimPrefix(ext, ".")
}
