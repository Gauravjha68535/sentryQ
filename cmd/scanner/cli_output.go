package main

import (
	"fmt"
	"os"
	"strings"

	"SentryQ/reporter"

	"github.com/fatih/color"
)

// PrintFindingsSummary prints a colorized, tabular summary of scan findings to
// stdout. Groups findings by severity (critical → info) with counts, then lists
// the top findings so the user can see the most important issues without opening
// the web UI.
func PrintFindingsSummary(findings []reporter.Finding, targetDir string) {
	if len(findings) == 0 {
		color.New(color.FgGreen, color.Bold).Println("\n✅  No findings — clean scan!")
		return
	}

	// Count by severity
	counts := map[string]int{}
	for _, f := range findings {
		counts[strings.ToLower(f.Severity)]++
	}

	fmt.Println()
	printDivider()
	color.New(color.FgHiWhite, color.Bold).Printf("  SCAN RESULTS — %s\n", targetDir)
	printDivider()

	// Severity summary bar
	sevColors := map[string]*color.Color{
		"critical": color.New(color.FgHiRed, color.Bold),
		"high":     color.New(color.FgRed),
		"medium":   color.New(color.FgYellow),
		"low":      color.New(color.FgGreen),
		"info":     color.New(color.FgCyan),
	}
	sevOrder := []string{"critical", "high", "medium", "low", "info"}
	fmt.Println()
	for _, sev := range sevOrder {
		cnt := counts[sev]
		if cnt == 0 {
			continue
		}
		c := sevColors[sev]
		label := strings.ToUpper(sev)
		bar := strings.Repeat("█", min(cnt, 40))
		c.Printf("  %-10s %3d  %s\n", label, cnt, bar)
	}
	fmt.Println()

	// Top findings table (up to 20, critical + high first)
	var prioritised []reporter.Finding
	for _, sev := range sevOrder {
		for _, f := range findings {
			if strings.ToLower(f.Severity) == sev {
				prioritised = append(prioritised, f)
			}
		}
	}

	limit := 20
	if len(prioritised) < limit {
		limit = len(prioritised)
	}

	color.New(color.FgHiWhite, color.Bold).Printf("  Top %d Findings:\n\n", limit)

	for i, f := range prioritised[:limit] {
		sev := strings.ToLower(f.Severity)
		c := sevColors[sev]

		// Severity badge
		badge := fmt.Sprintf("[%-8s]", strings.ToUpper(sev))
		c.Printf("  %2d. %s ", i+1, badge)

		// Issue name (truncated)
		name := f.IssueName
		if len(name) > 48 {
			name = name[:45] + "…"
		}
		color.New(color.FgHiWhite).Printf("%-50s", name)

		// File + line (muted)
		file := f.FilePath
		if len(file) > 40 {
			// Show last 40 chars
			file = "…" + file[len(file)-39:]
		}
		color.New(color.FgHiBlack).Printf("  %s:%s\n", file, f.LineNumber)
	}

	if len(findings) > 20 {
		color.New(color.FgHiBlack).Printf("\n  … and %d more. Run the web UI or check the HTML report for full details.\n", len(findings)-20)
	}

	printDivider()

	// Final tally
	total := len(findings)
	crit := counts["critical"]
	high := counts["high"]

	if crit > 0 {
		color.New(color.FgHiRed, color.Bold).Printf("  ⚠  %d CRITICAL  |  %d HIGH  |  %d total findings\n", crit, high, total)
	} else if high > 0 {
		color.New(color.FgRed).Printf("  ⚠  %d HIGH  |  %d total findings\n", high, total)
	} else {
		color.New(color.FgYellow).Printf("  %d total findings (no critical or high)\n", total)
	}

	printDivider()
	fmt.Println()
}

// PrintScanBanner prints the per-scan start banner with target and scan ID.
func PrintScanBanner(targetDir, scanID string) {
	fmt.Println()
	printDivider()
	color.New(color.FgHiCyan, color.Bold).Println("  🛡️  SentryQ Security Scan")
	color.New(color.FgHiBlack).Printf("  Target : %s\n", targetDir)
	color.New(color.FgHiBlack).Printf("  Scan ID: %s\n", scanID)
	printDivider()
	fmt.Println()
}

func printDivider() {
	color.New(color.FgHiBlack).Println("  " + strings.Repeat("─", 72))
}

// PrintPolicyResultColored prints a colored policy gate result.
func PrintPolicyResultColored(violations []PolicyViolation) int {
	fmt.Println()
	if len(violations) == 0 {
		color.New(color.FgGreen, color.Bold).Println("  ✅  POLICY GATE PASSED — all thresholds within limits")
		fmt.Println()
		return 0
	}
	color.New(color.FgHiRed, color.Bold).Println("  ❌  POLICY GATE FAILED:")
	for _, v := range violations {
		color.New(color.FgRed).Printf("     • %s\n", v.Message)
	}
	fmt.Fprintln(os.Stderr)
	return 1
}
