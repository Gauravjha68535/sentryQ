package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// recalibrateSeverities adjusts over-inflated and under-rated severities, and
// removes the [UNREACHABLE] tag from web framework route handlers.
func recalibrateSeverities(findings []reporter.Finding, targetDir string) []reporter.Finding {
	// Cache file contents
	fileCache := make(map[string]string)
	readFile := func(filePath string) string {
		if content, ok := fileCache[filePath]; ok {
			return content
		}
		absPath := filePath
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(targetDir, filePath)
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			return ""
		}
		content := string(data)
		fileCache[filePath] = content
		return content
	}

	// Web framework entry point markers (if these exist in the file, routes are reachable)
	webMarkers := []string{
		"$_get", "$_post", "$_request", "$_cookie", "$_server", // PHP
		"@app.route", "flask", "def index", "@app.get", "@app.post", // Python Flask
		"app.get(", "app.post(", "express()", "router.", // Node.js Express
		"@requestmapping", "@getmapping", "@postmapping", "httpservlet", // Java Spring/Servlet
	}

	for i := range findings {
		f := &findings[i]
		cwe := strings.ToUpper(strings.TrimSpace(f.CWE))
		lower := strings.ToLower(f.IssueName + " " + f.Description + " " + f.RuleID)

		// ── DOWNGRADE RULES ──

		// Math.random / weak random: Critical → High
		if (cwe == "CWE-338" || cwe == "CWE-330" || cwe == "CWE-331" ||
			strings.Contains(lower, "math.random") || strings.Contains(lower, "predictable random")) &&
			f.Severity == "critical" {
			f.Severity = "high"
		}

		// Reflected XSS (non-stored): Critical → High
		if cwe == "CWE-79" && f.Severity == "critical" &&
			!strings.Contains(lower, "stored") {
			f.Severity = "high"
		}

		// Missing body size limit / CWE-770: Medium → Low
		if cwe == "CWE-770" && (f.Severity == "medium" || f.Severity == "high") {
			f.Severity = "low"
		}

		// Generic input validation CWE-20: cap at Medium
		if cwe == "CWE-20" && f.Severity == "critical" {
			f.Severity = "medium"
		}

		// ── UPGRADE RULES ──

		// NoSQL Injection with req.body: High → Critical (auth bypass)
		if (cwe == "CWE-943" || strings.Contains(lower, "nosql")) &&
			f.Severity == "high" &&
			strings.Contains(lower, "req.body") {
			f.Severity = "critical"
		}

		// SSTI / Template Injection: anything below Critical → Critical (RCE)
		if (cwe == "CWE-1336" || cwe == "CWE-94" ||
			strings.Contains(lower, "template injection") || strings.Contains(lower, "ssti")) &&
			(f.Severity == "medium" || f.Severity == "high") {
			f.Severity = "critical"
		}

		// File Inclusion: INFO → High minimum
		if (cwe == "CWE-98" || strings.Contains(lower, "file inclusion") || strings.Contains(lower, "lfi")) &&
			(f.Severity == "info" || f.Severity == "low") {
			f.Severity = "high"
		}

		// ── FIX [UNREACHABLE] FOR WEB CODE ──
		if strings.Contains(f.Description, "[UNREACHABLE]") {
			content := strings.ToLower(readFile(f.FilePath))
			if content != "" {
				for _, marker := range webMarkers {
					if strings.Contains(content, marker) {
						// Remove [UNREACHABLE] tag — this IS reachable via HTTP
						f.Description = strings.Replace(f.Description, "[UNREACHABLE] ", "", 1)
						// Restore severity if downgraded
						if f.Severity == "info" || f.Severity == "low" {
							f.Severity = "high"
						}
						break
					}
				}
			}
		}
	}

	return findings
}

// isTrivialLine returns true for lines that are blank, pure comments, or lone braces/brackets.
// Used to detect when the AI pointed to a non-meaningful line so we can shift the marker.
func isTrivialLine(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return true
	}
	// Pure comment lines
	if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") ||
		strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") ||
		strings.HasPrefix(t, "<!--") {
		return true
	}
	// Lone structural tokens
	switch t {
	case "{", "}", "};", "){", ");", "];", "]", "[", "(", ")", "<?php", "?>":
		return true
	}
	return false
}

// bestLineInWindow finds the nearest non-trivial line within [start, end) (0-indexed) relative to
// preferredIdx (also 0-indexed). It searches outward: preferred → preferred+1 → preferred-1 → …
func bestLineInWindow(lines []string, start, end, preferredIdx int) int {
	if preferredIdx < 0 || preferredIdx >= len(lines) {
		return preferredIdx
	}
	if !isTrivialLine(lines[preferredIdx]) {
		return preferredIdx
	}
	for delta := 1; delta <= 2; delta++ {
		if fwd := preferredIdx + delta; fwd < end && !isTrivialLine(lines[fwd]) {
			return fwd
		}
		if bwd := preferredIdx - delta; bwd >= start && !isTrivialLine(lines[bwd]) {
			return bwd
		}
	}
	return preferredIdx // nothing better found, keep original
}

// findPatternLine searches lines[searchStart:searchEnd] for the line that best contains
// the given pattern (case-insensitive substring match). Returns the 0-indexed line index
// within lines[], or -1 if not found. Prefers lines closer to preferredIdx.
func findPatternLine(lines []string, pattern string, preferredIdx, searchStart, searchEnd int) int {
	if pattern == "" {
		return -1
	}
	lowerPat := strings.ToLower(strings.TrimSpace(pattern))
	if lowerPat == "" {
		return -1
	}
	// Clamp search range
	if searchStart < 0 {
		searchStart = 0
	}
	if searchEnd > len(lines) {
		searchEnd = len(lines)
	}

	// Expand the candidate: try the exact fragment first, then the first token of it
	// (handles cases where the AI adds/removes whitespace or trailing chars)
	shortPat := lowerPat
	if idx := strings.IndexAny(lowerPat, " \t(=;"); idx > 6 {
		shortPat = lowerPat[:idx]
	}

	best := -1
	bestDist := searchEnd - searchStart + 1
	for i := searchStart; i < searchEnd; i++ {
		lower := strings.ToLower(lines[i])
		if strings.Contains(lower, lowerPat) || (shortPat != lowerPat && strings.Contains(lower, shortPat)) {
			dist := i - preferredIdx
			if dist < 0 {
				dist = -dist
			}
			if dist < bestDist {
				bestDist = dist
				best = i
			}
		}
	}
	return best
}

// webPopulateCodeSnippets reads source files and extracts ~5 lines around each vulnerable line.
//
// Anchor strategy (in priority order):
//  1. If the finding has a VulnerablePattern (exact code fragment from the AI), search the
//     file within ±30 lines of the AI-reported line for that fragment. Use the matching line.
//  2. If the AI-reported line is trivial (blank/comment/brace), shift ±2 to nearest real code.
//  3. Otherwise use the AI-reported line as-is.
//
// In all cases the stored LineNumber is updated to match the final arrow position.
func webPopulateCodeSnippets(findings []reporter.Finding, targetDir string) {
	// Group findings by file to limit memory to one file at a time
	indicesByFile := make(map[string][]int)

	for i := range findings {
		lineNum := utils.ParseStartLine(findings[i].LineNumber)
		if lineNum <= 0 {
			continue
		}

		filePath := findings[i].FilePath
		if !filepath.IsAbs(filePath) {
			filePath = filepath.Join(targetDir, filePath)
		}
		indicesByFile[filePath] = append(indicesByFile[filePath], i)
	}

	for filePath, indices := range indicesByFile {
		content, err := os.ReadFile(filePath)
		if err != nil {
			utils.LogWarn(fmt.Sprintf("populateCodeSnippets: could not read %s: %v", filePath, err))
			continue
		}
		lines := strings.Split(utils.NormalizeNewlines(string(content)), "\n")

		for _, idx := range indices {
			lineNum := utils.ParseStartLine(findings[idx].LineNumber)

			preferredIdx := lineNum - 1 // 0-indexed

			// ── Strategy 1: pattern-based anchoring ──────────────────────
			if pat := findings[idx].VulnerablePattern; pat != "" {
				searchStart := preferredIdx - 30
				searchEnd := preferredIdx + 31
				if found := findPatternLine(lines, pat, preferredIdx, searchStart, searchEnd); found >= 0 {
					preferredIdx = found
					lineNum = found + 1
					findings[idx].LineNumber = fmt.Sprintf("%d", lineNum)
				}
			}

			// ── Strategy 2: trivial-line shifting (±2) ───────────────────
			if preferredIdx >= 0 && preferredIdx < len(lines) {
				// Build a temporary window just for the shift check
				shiftStart := preferredIdx - 2
				if shiftStart < 0 {
					shiftStart = 0
				}
				shiftEnd := preferredIdx + 3
				if shiftEnd > len(lines) {
					shiftEnd = len(lines)
				}
				if isTrivialLine(lines[preferredIdx]) {
					bestIdx := bestLineInWindow(lines, shiftStart, shiftEnd, preferredIdx)
					if bestIdx != preferredIdx {
						preferredIdx = bestIdx
						lineNum = bestIdx + 1
						findings[idx].LineNumber = fmt.Sprintf("%d", lineNum)
					}
				}
			}

			// ── Build the 5-line context snippet ─────────────────────────
			start := lineNum - 3
			if start < 0 {
				start = 0
			}
			end := lineNum + 2
			if end > len(lines) {
				end = len(lines)
			}

			var snippet strings.Builder
			for j := start; j < end; j++ {
				marker := "  "
				if j+1 == lineNum {
					marker = "→ "
				}
				snippet.WriteString(fmt.Sprintf("%s%4d | %s\n", marker, j+1, lines[j]))
			}
			findings[idx].CodeSnippet = snippet.String()
		}
	}
}

// ════════════════════════════════════════════════════════════
//  ENSEMBLE AUDIT MODE — 3-Phase Pipeline
// ════════════════════════════════════════════════════════════

