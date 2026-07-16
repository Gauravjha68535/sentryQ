package ai

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"SentryQ/reporter"

	"github.com/fatih/color"
)

// ValidateFindingsBatch validates findings sequentially using AI.
// Sequential processing (not a pool) is preferred to avoid GPU VRAM thrashing
// on consumer hardware. The channel+goroutine pool that existed before was pure
// overhead since numWorkers was always 1.
func ValidateFindingsBatch(ctx context.Context, modelName string, findings []reporter.Finding, fileContents map[string]string, logCallback ...func(msg string, level string)) []reporter.Finding {
	totalToValidate := countCriticalHighMedium(findings)

	uiLog := func(msg, level string) {
		if len(logCallback) > 0 && logCallback[0] != nil {
			logCallback[0](msg, level)
		}
	}
	calibrator := NewConfidenceCalibrator()

	headerColor := color.New(color.FgCyan, color.Bold)
	headerColor.Println("\n┌─ 🤖 AI Validation Engine")
	headerColor.Println("└────────────────────────────────────────")
	fmt.Println()

	if len(findings) == 0 {
		return findings
	}

	uiLog(fmt.Sprintf("Starting AI validation with model: %s", modelName), "info")
	uiLog(fmt.Sprintf("Validating %d findings (Critical/High/Medium only)", totalToValidate), "info")
	fmt.Println()

	startTime := time.Now()

	var (
		validated         int
		truePositives     int
		falsePositives    int
		errorsCount       int
		skipped           int
		consecutiveErrors int
	)
	const maxConsecutiveErrors = 3

	var finalFindings []reporter.Finding

	for i := range findings {
		f := findings[i]

		if ctx.Err() != nil {
			f.AiValidated = "Skipped (Cancelled)"
			finalFindings = append(finalFindings, f)
			continue
		}

		if f.Severity == "low" || f.Severity == "info" {
			f.AiValidated = "Skipped (Low/Info)"
			skipped++
			finalFindings = append(finalFindings, f)
			continue
		}

		if consecutiveErrors >= maxConsecutiveErrors {
			f.AiValidated = "Skipped (AI Unavailable)"
			skipped++
			finalFindings = append(finalFindings, f)
			continue
		}

		validated++
		elapsed := time.Since(startTime)
		var etaStr string
		if validated > 1 {
			avgTime := elapsed / time.Duration(validated-1)
			remaining := totalToValidate - validated
			if remaining > 0 {
				etaStr = fmt.Sprintf("ETA %s", formatDuration(avgTime*time.Duration(remaining)))
			}
		}
		if etaStr == "" {
			etaStr = "calculating..."
		}

		shortFile := filepath.Base(f.FilePath)
		displayPath := filepath.Join(filepath.Base(filepath.Dir(f.FilePath)), shortFile)

		uiLog(fmt.Sprintf("Validating [%d/%d] %s => %s (%s)", validated, totalToValidate, displayPath, f.IssueName, etaStr), "info")
		fmt.Printf("\r\033[K")
		color.New(color.FgHiBlue).Printf("  [%s elapsed | %s] (%d/%d) ", formatDuration(elapsed), etaStr, validated, totalToValidate)
		color.New(color.FgHiCyan).Printf("📄 %s ", displayPath)
		fmt.Printf("L%s ", f.LineNumber)
		switch f.Severity {
		case "critical":
			color.New(color.FgRed, color.Bold).Printf("[CRIT] ")
		case "high":
			color.New(color.FgHiRed).Printf("[HIGH] ")
		case "medium":
			color.New(color.FgYellow).Printf("[MED]  ")
		}
		fmt.Printf("%s\n", f.IssueName)

		// Build related file context (up to 2 files mentioned in ExploitPath/Description)
		relatedFilesContext := ""
		relatedCount := 0
		for p, content := range fileContents {
			if p == f.FilePath || relatedCount >= 2 {
				continue
			}
			shortPath := filepath.Base(p)
			mentioned := strings.Contains(f.Description, shortPath)
			if !mentioned {
				for _, step := range f.ExploitPath {
					if strings.Contains(step, shortPath) {
						mentioned = true
						break
					}
				}
			}
			if mentioned {
				relatedFilesContext += fmt.Sprintf("=== Related Context: %s ===\n%s\n\n", shortPath, content)
				relatedCount++
			}
		}

		codeSnippet := getCodeSnippet(fileContents, f.FilePath, f.LineNumber)
		result, err := ValidateFinding(ctx, modelName, f, codeSnippet, relatedFilesContext)

		if err != nil {
			uiLog(fmt.Sprintf("AI validation failed for finding %s: %v", f.IssueName, err), "error")
			f.AiValidated = "Error"
			errorsCount++
			consecutiveErrors++
			color.Red("         ⚠ Error: AI validation failed")
			if consecutiveErrors >= maxConsecutiveErrors {
				color.Yellow("         ⚠ Circuit breaker triggered: skipping remaining AI validations")
			}
		} else {
			consecutiveErrors = 0
			if result.IsTruePositive {
				f.AiValidated = "Yes"
				if result.Explanation != "" {
					f.AiReasoning = result.Explanation
				}
				if result.SuggestedFix != "" {
					f.Remediation = result.SuggestedFix
				}
				if result.FixedCodeSnippet != "" && result.FixedCodeSnippet != "N/A" {
					f.FixedCode = result.FixedCodeSnippet
				}
				if result.SeverityAdjustment != "same" && result.SeverityAdjustment != "" {
					f.Severity = result.SeverityAdjustment
				}
				if result.ExploitPoC != "" {
					f.ExploitPoC = result.ExploitPoC
				}
				f.Confidence = result.Confidence
				truePositives++
				uiLog(fmt.Sprintf("  ✓ Confirmed (%s) %.0f%% confidence", f.IssueName, result.Confidence*100), "success")
				color.New(color.FgGreen).Printf("         ✓ Confirmed (%.0f%% confidence)\n", result.Confidence*100)
			} else {
				f.AiValidated = "No (False Positive)"
				f.Description = fmt.Sprintf("AI determined this is a false positive: %s", result.Explanation)
				f.Confidence = result.Confidence
				f.CWE = ""
				f.OWASP = ""
				falsePositives++
				uiLog(fmt.Sprintf("  ○ Filtered FP (%s) %.0f%% confidence", f.IssueName, result.Confidence*100), "warning")
				color.New(color.FgHiBlack).Printf("         ○ Filtered (False Positive) [%.0f%% confidence]\n", result.Confidence*100)
			}
			calibrator.RecordValidation(f.Severity, result.IsTruePositive)
			calibrator.SaveStats()
		}
		finalFindings = append(finalFindings, f)
	}

	// Summary
	totalTime := time.Since(startTime)
	fmt.Println()
	headerColor.Println("┌─ 📊 AI Validation Summary")
	headerColor.Println("└────────────────────────────────────────")
	fmt.Printf("  ⏱  Total Time:       %s\n", formatDuration(totalTime))
	if validated > 0 {
		avgPerFinding := totalTime / time.Duration(validated)
		fmt.Printf("  ⚡ Avg per Finding:   %s\n", formatDuration(avgPerFinding))
	}
	color.New(color.FgGreen).Printf("  ✓  True Positives:   %d\n", truePositives)
	color.New(color.FgHiBlack).Printf("  ✗  False Positives:  %d\n", falsePositives)
	if errorsCount > 0 {
		color.Red("  ⚠  Errors:           %d\n", errorsCount)
	}
	fmt.Printf("  ⏭  Skipped (Low):    %d\n", skipped)
	fmt.Printf("  📋 Total Processed:  %d\n", validated+skipped)
	fmt.Println()

	// Apply confidence calibration
	finalFindings = calibrator.ApplyCalibrationToFindings(finalFindings)

	return finalFindings
}

// formatDuration formats a duration into human-readable form
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		secs := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%02ds", mins, secs)
	}
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%02dm", hours, mins)
}
