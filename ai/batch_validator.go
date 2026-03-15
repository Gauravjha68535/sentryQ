package ai

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"

	"github.com/fatih/color"
)

// ValidateFindingsBatch validates multiple findings concurrently using a worker pool.
func ValidateFindingsBatch(modelName string, findings []reporter.Finding, fileContents map[string]string, batchSize int, targetDir string) []reporter.Finding {
	totalToValidate := countCriticalHighMedium(findings)
	calibrator := NewConfidenceCalibrator(targetDir)

	// Styled header
	headerColor := color.New(color.FgCyan, color.Bold)
	headerColor.Println("\n┌─ 🤖 AI Validation Engine (Concurrent)")
	headerColor.Println("└────────────────────────────────────────")
	fmt.Println()

	numWorkers := 2 // Default concurrency
	if len(findings) < numWorkers {
		numWorkers = len(findings)
	}
	if numWorkers == 0 {
		return findings
	}

	utils.LogInfo(fmt.Sprintf("Starting BATCH AI validation with model: %s", modelName))
	utils.LogInfo(fmt.Sprintf("Concurrency: %d parallel workers", numWorkers))
	utils.LogInfo(fmt.Sprintf("Validating %d findings (Critical/High/Medium only)", totalToValidate))
	fmt.Println()

	SetInterrupted(false)
	globalCtx, globalCancel = context.WithCancel(context.Background())

	startTime := time.Now()

	// Metrics & Synchronization
	var (
		mu                sync.Mutex
		validated         int
		truePositives     int
		falsePositives    int
		errorsCount       int
		skipped           int
		consecutiveErrors int
	)
	const maxConsecutiveErrors = 3

	// Channels for worker pool
	type findingJob struct {
		index   int
		finding reporter.Finding
	}

	jobs := make(chan findingJob, len(findings))
	results := make(chan findingJob, len(findings))

	var wg sync.WaitGroup

	// Worker Function
	worker := func() {
		defer wg.Done()
		for job := range jobs {
			// Pre-check for skip conditions
			if job.finding.Severity == "low" || job.finding.Severity == "info" {
				job.finding.AiValidated = "Skipped (Low/Info)"

				mu.Lock()
				skipped++
				mu.Unlock()

				results <- job
				continue
			}

			// Circuit breaker check
			mu.Lock()
			ce := consecutiveErrors
			mu.Unlock()
			if ce >= maxConsecutiveErrors {
				job.finding.AiValidated = "Skipped (AI Unavailable)"

				mu.Lock()
				skipped++
				mu.Unlock()

				results <- job
				continue
			}

			// Capture context for UI before unlocking
			mu.Lock()
			validated++
			currValidated := validated
			mu.Unlock()

			// Print UI Progress
			elapsed := time.Since(startTime)
			var eta time.Duration
			if currValidated > 1 {
				avgTime := elapsed / time.Duration(currValidated-1)
				remaining := totalToValidate - currValidated
				if remaining > 0 {
					eta = avgTime * time.Duration(remaining)
				}
			}

			shortFile := filepath.Base(job.finding.FilePath)
			parentDir := filepath.Base(filepath.Dir(job.finding.FilePath))
			displayPath := filepath.Join(parentDir, shortFile)

			issueName := job.finding.IssueName
			if len(issueName) > 35 {
				issueName = issueName[:32] + "..."
			}

			// We wrap terminal output in a mutex to prevent lines from clobbering each other
			mu.Lock()
			fmt.Printf("\r\033[K")
			color.New(color.FgHiBlue).Printf("  [%s elapsed", formatDuration(elapsed))
			if currValidated > 1 && eta > 0 {
				color.New(color.FgHiBlue).Printf(" | ~%s remaining", formatDuration(eta))
			}
			color.New(color.FgHiBlue).Printf("] ")
			fmt.Printf("(%d/%d) ", currValidated, totalToValidate)
			color.New(color.FgHiCyan).Printf("📄 %s ", displayPath)
			fmt.Printf("L%s ", job.finding.LineNumber)

			switch job.finding.Severity {
			case "critical":
				color.New(color.FgRed, color.Bold).Printf("[CRIT] ")
			case "high":
				color.New(color.FgHiRed).Printf("[HIGH] ")
			case "medium":
				color.New(color.FgYellow).Printf("[MED]  ")
			}
			fmt.Printf("%s\n", issueName)
			mu.Unlock()

			// Perform actual AI Validation (Heavy lifting, no mutex)
			codeSnippet := getCodeSnippet(fileContents, job.finding.FilePath, job.finding.LineNumber)
			result, err := ValidateFinding(modelName, job.finding, codeSnippet)

			mu.Lock()
			if err != nil {
				utils.LogError(fmt.Sprintf("AI validation failed for finding %s", job.finding.IssueName), err)
				job.finding.AiValidated = "Error"
				errorsCount++
				consecutiveErrors++
				color.Red("         ⚠ Error: AI validation failed")
				if consecutiveErrors >= maxConsecutiveErrors {
					color.Yellow("         ⚠ Circuit breaker triggered: skipping remaining AI validations")
				}
			} else {
				consecutiveErrors = 0
				if result.IsTruePositive {
					job.finding.AiValidated = "Yes"
					if result.Explanation != "" {
						job.finding.AiReasoning = result.Explanation
					}
					if result.SuggestedFix != "" {
						job.finding.Remediation = result.SuggestedFix
						job.finding.FixedCode = result.SuggestedFix
					}
					if result.SeverityAdjustment != "same" && result.SeverityAdjustment != "" {
						job.finding.Severity = result.SeverityAdjustment
					}
					if result.ExploitPoC != "" {
						job.finding.ExploitPoC = result.ExploitPoC
					}
					job.finding.Confidence = result.Confidence
					truePositives++
					color.New(color.FgGreen).Printf("         ✓ Confirmed (%.0f%% confidence)\n", result.Confidence*100)
				} else {
					job.finding.AiValidated = "No (False Positive)"
					job.finding.Description = fmt.Sprintf("AI determined this is a false positive: %s", result.Explanation)
					job.finding.Confidence = result.Confidence
					job.finding.CWE = ""
					job.finding.OWASP = ""
					falsePositives++
					color.New(color.FgHiBlack).Printf("         ✗ False Positive (%.0f%% confidence)\n", result.Confidence*100)
				}

				calibrator.RecordValidation(job.finding.Severity, result.IsTruePositive)
				calibrator.SaveStats()
			}
			mu.Unlock()

			results <- job
		}
	}

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go worker()
	}

	// Send jobs
	for i, f := range findings {
		jobs <- findingJob{index: i, finding: f}
	}
	close(jobs)

	// Wait for workers to finish
	wg.Wait()
	close(results)

	// Re-assemble results in original order
	finalFindings := make([]reporter.Finding, len(findings))
	for res := range results {
		finalFindings[res.index] = res.finding
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
