package ai

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SentryQ/reporter"

	"github.com/fatih/color"
)

// ValidateFindingsBatch validates multiple findings concurrently using a worker pool.
func ValidateFindingsBatch(ctx context.Context, modelName string, findings []reporter.Finding, fileContents map[string]string, batchSize int, logCallback ...func(msg string, level string)) []reporter.Finding {
	totalToValidate := countCriticalHighMedium(findings)

	// Helper to send logs to UI if a callback was provided
	uiLog := func(msg, level string) {
		if len(logCallback) > 0 && logCallback[0] != nil {
			logCallback[0](msg, level)
		}
	}
	calibrator := NewConfidenceCalibrator()

	// Styled header
	headerColor := color.New(color.FgCyan, color.Bold)
	headerColor.Println("\n┌─ 🤖 AI Validation Engine (Concurrent)")
	headerColor.Println("└────────────────────────────────────────")
	fmt.Println()

	numWorkers := 1 // Default concurrency (Sequential preferred to avoid GPU VRAM thrashing on consumer hardware)
	if len(findings) < numWorkers {
		numWorkers = len(findings)
	}
	if numWorkers == 0 {
		return findings
	}

	uiLog(fmt.Sprintf("Starting BATCH AI validation with model: %s", modelName), "info")
	uiLog(fmt.Sprintf("Concurrency: %d parallel workers", numWorkers), "info")
	uiLog(fmt.Sprintf("Validating %d findings (Critical/High/Medium only)", totalToValidate), "info")
	fmt.Println()



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
			etaStr := ""
			if currValidated > 1 && eta > 0 {
				etaStr = fmt.Sprintf("ETA %s", formatDuration(eta))
			} else {
				etaStr = "calculating..."
			}
			uiLog(fmt.Sprintf("Validating [%d/%d] %s => %s (%s)", currValidated, totalToValidate, displayPath, job.finding.IssueName, etaStr), "info")
			fmt.Printf("\r\033[K")
			color.New(color.FgHiBlue).Printf("  [%s elapsed | %s] (%d/%d) ", formatDuration(elapsed), etaStr, currValidated, totalToValidate)
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

			// Extract context for cross-file validation
			relatedFilesContext := ""
			relatedCount := 0
			// Look for file paths mentioned in ExploitPath or Description that aren't the main file
			for p, content := range fileContents {
				if p != job.finding.FilePath {
					shortPath := filepath.Base(p)
					mentioned := false
					for _, step := range job.finding.ExploitPath {
						if strings.Contains(step, shortPath) {
							mentioned = true
							break
						}
					}
					if !mentioned && strings.Contains(job.finding.Description, shortPath) {
						mentioned = true
					}
					
					if mentioned {
						relatedFilesContext += fmt.Sprintf("=== Related Context: %s ===\n%s\n\n", shortPath, content)
						relatedCount++
					}
				}
				if relatedCount >= 2 { // Limit to 2 related files to protect context window
					break
				}
			}

			// Perform actual AI Validation (Heavy lifting, no mutex)
			codeSnippet := getCodeSnippet(fileContents, job.finding.FilePath, job.finding.LineNumber)
			result, err := ValidateFinding(ctx, modelName, job.finding, codeSnippet, relatedFilesContext)

			mu.Lock()
			if err != nil {
				uiLog(fmt.Sprintf("AI validation failed for finding %s: %v", job.finding.IssueName, err), "error")
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
					uiLog(fmt.Sprintf("  ✓ Confirmed (%s) %.0f%% confidence", job.finding.IssueName, result.Confidence*100), "success")
					color.New(color.FgGreen).Printf("         ✓ Confirmed (%.0f%% confidence)\n", result.Confidence*100)
				} else {
					job.finding.AiValidated = "No (False Positive)"
					job.finding.Description = fmt.Sprintf("AI determined this is a false positive: %s", result.Explanation)
					job.finding.Confidence = result.Confidence
					job.finding.CWE = ""
					job.finding.OWASP = ""
					falsePositives++
					uiLog(fmt.Sprintf("  ○ Filtered FP (%s) %.0f%% confidence", job.finding.IssueName, result.Confidence*100), "warning")
					color.New(color.FgHiBlack).Printf("         ○ Filtered (False Positive) [%.0f%% confidence]\n", result.Confidence*100)
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

	// Re-assemble results in original order (safeguarding against missing results)
	orderedFindings := make([]reporter.Finding, len(findings))
	for res := range results {
		orderedFindings[res.index] = res.finding
	}

	var finalFindings []reporter.Finding
	for _, f := range orderedFindings {
		// Only append findings that were actually populated (not empty default structs)
		// We use FilePath as a decent indicator that this finding wasn't completely dropped
		if f.FilePath != "" {
			finalFindings = append(finalFindings, f)
		}
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
