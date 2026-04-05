package ai

import (
	"SentryQ/reporter"
	"SentryQ/utils"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// VulnerabilityStats tracks how often AI is correct vs wrong for a specific severity/type
type VulnerabilityStats struct {
	AssessedFindings int     `json:"assessed_findings"` // New explicit count of how many were actually checked
	TruePositives    int     `json:"true_positives"`
	FalsePositives   int     `json:"false_positives"`
	AccuracyRate     float64 `json:"accuracy_rate"` // TruePositives / AssessedFindings
}

// ConfidenceCalibrator adjusts AI confidence based on historical accuracy
type ConfidenceCalibrator struct {
	StatsFile string
	Stats     map[string]*VulnerabilityStats // Severity -> Stats
	mu        sync.RWMutex
}

// NewConfidenceCalibrator initializes a calibrator
func NewConfidenceCalibrator() *ConfidenceCalibrator {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	dbDir := filepath.Join(homeDir, ".sentryq")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		utils.LogWarn(fmt.Sprintf("ConfidenceCalibrator: failed to create stats directory %s: %v", dbDir, err))
	}
	statsFile := filepath.Join(dbDir, ".scanner-ai-stats.json")

	c := &ConfidenceCalibrator{
		StatsFile: statsFile,
		Stats:     make(map[string]*VulnerabilityStats),
	}
	c.LoadStats()
	return c
}

// LoadStats loads historical validation stats
func (c *ConfidenceCalibrator) LoadStats() {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.StatsFile)
	if err == nil {
		if unmarshalErr := json.Unmarshal(data, &c.Stats); unmarshalErr != nil {
			utils.LogWarn("Confidence calibrator: failed to parse stats file, resetting: " + unmarshalErr.Error())
		}
	}
}

// SaveStats saves current stats to disk
func (c *ConfidenceCalibrator) SaveStats() {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c.Stats, "", "  ")
	if err != nil {
		utils.LogError("Failed to serialize calibrator stats", err)
		return
	}
	if err := os.WriteFile(c.StatsFile, data, 0600); err != nil {
		utils.LogError(fmt.Sprintf("Failed to write calibrator stats to %s", c.StatsFile), err)
	}
}

// RecordValidation updates stats after an AI validation round
func (c *ConfidenceCalibrator) RecordValidation(severity string, isTruePositive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats, exists := c.Stats[severity]
	if !exists {
		stats = &VulnerabilityStats{}
		c.Stats[severity] = stats
	}

	stats.AssessedFindings++
	if isTruePositive {
		stats.TruePositives++
	} else {
		stats.FalsePositives++
	}

	// Guard against zero division; AssessedFindings is always >= 1 here because
	// we just incremented it, but defend explicitly for future-proofing.
	if stats.AssessedFindings > 0 {
		stats.AccuracyRate = float64(stats.TruePositives) / float64(stats.AssessedFindings)
	}
}

// CalibrateConfidence adjusts the raw confidence score based on historical accuracy for that severity
func (c *ConfidenceCalibrator) CalibrateConfidence(severity string, rawConfidence float64) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats, exists := c.Stats[severity]
	if !exists || stats.AssessedFindings < 5 {
		// Not enough data to calibrate, return raw
		return rawConfidence
	}

	// If the AI is highly accurate for this severity, boost confidence slightly
	// If it heavily false positives, downgrade confidence significantly

	// Weight: 70% raw confidence, 30% historical accuracy
	calibrated := (rawConfidence * 0.70) + (stats.AccuracyRate * 0.30)

	// Cap between 0.1 and 0.99
	if calibrated > 0.99 {
		return 0.99
	}
	if calibrated < 0.1 {
		return 0.1
	}

	return calibrated
}

// ApplyCalibrationToFindings takes a list of findings and adjusts their confidence scores
func (c *ConfidenceCalibrator) ApplyCalibrationToFindings(findings []reporter.Finding) []reporter.Finding {
	for i := range findings {
		// Only calibrate if it actually came from an AI source and has a confidence score
		if findings[i].Confidence > 0 && (findings[i].Source == "ai-discovery" || findings[i].AiValidated == "Yes") {
			oldConf := findings[i].Confidence
			newConf := c.CalibrateConfidence(findings[i].Severity, oldConf)
			findings[i].Confidence = newConf

			if oldConf != newConf {
				utils.LogInfo(fmt.Sprintf("Calibrated confidence for %s: %.2f → %.2f", findings[i].Severity, oldConf, newConf))
			}
		}
	}
	return findings
}
