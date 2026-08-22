package scanner

import (
	"regexp"
	"strings"
	"testing"

	"SentryQ/config"
)

// ─── matchesAnyNegative ───────────────────────────────────────────────────────

func TestMatchesAnyNegativeHits(t *testing.T) {
	neg := []config.PatternEntry{
		{Regex: `crypto\.randomBytes`, CompiledRegex: regexp.MustCompile(`crypto\.randomBytes`)},
	}
	if !matchesAnyNegative("result = crypto.randomBytes(16)", neg) {
		t.Error("expected matchesAnyNegative to return true for safe crypto usage")
	}
}

func TestMatchesAnyNegativeMisses(t *testing.T) {
	neg := []config.PatternEntry{
		{Regex: `crypto\.randomBytes`, CompiledRegex: regexp.MustCompile(`crypto\.randomBytes`)},
	}
	if matchesAnyNegative("result = Math.random()", neg) {
		t.Error("expected matchesAnyNegative to return false for unsafe random")
	}
}

func TestMatchesAnyNegativeNilRegexSkipped(t *testing.T) {
	neg := []config.PatternEntry{
		{Regex: `crypto\.randomBytes`, CompiledRegex: nil}, // nil = skip
	}
	// Should not panic; nil compiled regex must be skipped
	if matchesAnyNegative("crypto.randomBytes(16)", neg) {
		t.Error("nil CompiledRegex should be skipped, not panic or match")
	}
}

func TestMatchesAnyNegativeEmpty(t *testing.T) {
	if matchesAnyNegative("anything", nil) {
		t.Error("empty negatives list should return false")
	}
}

// ─── shouldApplyFrameworkRule ─────────────────────────────────────────────────

func TestShouldApplyFrameworkRuleSvelte(t *testing.T) {
	if !shouldApplyFrameworkRule("svelte", "/app/src/App.svelte", "") {
		t.Error("svelte rule should apply to .svelte files")
	}
	if shouldApplyFrameworkRule("svelte", "/app/src/main.js", "") {
		t.Error("svelte rule should NOT apply to .js files")
	}
}

func TestShouldApplyFrameworkRuleReactJSX(t *testing.T) {
	if !shouldApplyFrameworkRule("react", "/app/src/Button.jsx", "") {
		t.Error("react rule should apply to .jsx files")
	}
	if !shouldApplyFrameworkRule("react", "/app/src/Button.tsx", "") {
		t.Error("react rule should apply to .tsx files")
	}
}

func TestShouldApplyFrameworkRuleReactJSWithImport(t *testing.T) {
	content := `import React from 'react'
import { useState } from 'react'`
	if !shouldApplyFrameworkRule("react", "/app/src/page.js", content) {
		t.Error("react rule should apply to .js file that imports react")
	}
}

func TestShouldApplyFrameworkRuleReactJSWithoutImport(t *testing.T) {
	content := `console.log("hello")`
	if shouldApplyFrameworkRule("react", "/app/src/util.js", content) {
		t.Error("react rule should NOT apply to .js file with no react import")
	}
}

func TestShouldApplyFrameworkRuleGoWeb(t *testing.T) {
	content := `import "github.com/gin-gonic/gin"`
	if !shouldApplyFrameworkRule("go_web", "/app/main.go", content) {
		t.Error("go_web rule should apply to Go files importing gin")
	}
}

func TestShouldApplyFrameworkRuleGoWebNoImport(t *testing.T) {
	content := `package main
func main() {}`
	if shouldApplyFrameworkRule("go_web", "/app/main.go", content) {
		t.Error("go_web rule should NOT apply to plain Go without web framework import")
	}
}

// ─── getDefaultConfidence ─────────────────────────────────────────────────────

func TestGetDefaultConfidenceCritical(t *testing.T) {
	c := getDefaultConfidence("critical")
	if c <= 0 || c > 1 {
		t.Errorf("getDefaultConfidence(critical) = %f, want in (0,1]", c)
	}
}

func TestGetDefaultConfidenceLowerForInfo(t *testing.T) {
	crit := getDefaultConfidence("critical")
	info := getDefaultConfidence("info")
	if info >= crit {
		t.Errorf("info confidence (%f) should be lower than critical (%f)", info, crit)
	}
}

// ─── extractContextWindow ─────────────────────────────────────────────────────

func TestExtractContextWindowBasic(t *testing.T) {
	src := "line1\nline2\nline3\nline4\nline5\n"
	// Build newline indices for the helper
	idx := buildNewlineIndices(src)
	// Match "line3" (offset 12..16)
	matchStart := strings.Index(src, "line3")
	matchEnd := matchStart + len("line3")
	window := extractContextWindow(src, idx, matchStart, matchEnd, 1)
	if !strings.Contains(window, "line3") {
		t.Errorf("extractContextWindow missing match line; got %q", window)
	}
}

func TestExtractContextWindowDoesNotPanic(t *testing.T) {
	// Edge case: match at start of file with window > file size
	src := "short\n"
	idx := buildNewlineIndices(src)
	_ = extractContextWindow(src, idx, 0, 5, 100)
}

// ─── normalizeSeverity ────────────────────────────────────────────────────────

func TestNormalizeSeverityValidSeverities(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		r := config.Rule{Severity: sev, Confidence: 0.8}
		got := normalizeSeverity(r)
		if got == "" {
			t.Errorf("normalizeSeverity(%q) returned empty", sev)
		}
	}
}

func TestNormalizeSeverityLowConfidenceCapped(t *testing.T) {
	r := config.Rule{Severity: "critical", Confidence: 0.1}
	got := normalizeSeverity(r)
	if got == "critical" {
		t.Errorf("low-confidence critical rule should be capped, got %q", got)
	}
}
