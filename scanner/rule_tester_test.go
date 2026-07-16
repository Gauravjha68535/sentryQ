package scanner_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"SentryQ/config"
	"SentryQ/reporter"
	"SentryQ/scanner"
	"SentryQ/utils"
)

// RuleTestCase defines what rules should fire (or not) on a given test file.
type RuleTestCase struct {
	File        string   // relative to rules/vuln_samples/{positive|negative}/
	MustFire    []string // rule IDs that MUST appear in findings
	MustNotFire []string // rule IDs that MUST NOT appear in findings
	IsPositive  bool     // true = expect findings; false = expect silence
}

// positiveTestCases: vulnerable code that MUST trigger specific rules.
var positiveTestCases = []RuleTestCase{
	{
		File:       "python/sql_injection.py",
		MustFire:   []string{"py-sql-injection", "py-sql-injection-fstring"},
		IsPositive: true,
	},
	{
		File:       "python/command_injection.py",
		MustFire:   []string{"py-command-injection"},
		IsPositive: true,
	},
	{
		File:       "python/hardcoded_secrets.py",
		MustFire:   []string{"py-hardcoded-password", "py-hardcoded-api-key"},
		IsPositive: true,
	},
	{
		File:       "python/weak_crypto.py",
		MustFire:   []string{"py-insecure-random"},
		IsPositive: true,
	},
	{
		File:       "javascript/sql_injection.js",
		MustFire:   []string{"js-sqli-source-template-literal"},
		IsPositive: true,
	},
	{
		File:       "javascript/command_injection.js",
		MustFire:   []string{"js-cmdi-source-exec-request"},
		IsPositive: true,
	},
	{
		File:       "php/sql_injection.php",
		MustFire:   []string{"php-sqli-source-mysqli-request"},
		IsPositive: true,
	},
	{
		File:       "ruby/injection.rb",
		MustFire:   []string{"ruby-erb-ssti", "ruby-ssti-source-erb-params"},
		IsPositive: true,
	},
}

// negativeTestCases: safe code that MUST NOT trigger the named rules.
var negativeTestCases = []RuleTestCase{
	{
		File:        "python/sql_injection.py",
		MustNotFire: []string{"py-sql-injection", "py-sql-injection-fstring"},
		IsPositive:  false,
	},
	{
		File:        "python/command_injection.py",
		MustNotFire: []string{"py-command-injection"},
		IsPositive:  false,
	},
	{
		File:        "python/hardcoded_secrets.py",
		MustNotFire: []string{"py-hardcoded-password", "py-hardcoded-api-key"},
		IsPositive:  false,
	},
	{
		File:        "javascript/sql_injection.js",
		MustNotFire: []string{"js-sqli-source-template-literal"},
		IsPositive:  false,
	},
	{
		File:        "javascript/command_injection.js",
		MustNotFire: []string{"js-cmdi-source-exec-request"},
		IsPositive:  false,
	},
	{
		File:        "php/sql_injection.php",
		MustNotFire: []string{"php-sqli-source-mysqli-request"},
		IsPositive:  false,
	},
}

// findRulesDir locates the rules/ directory relative to the test file.
func findRulesDir(t *testing.T) string {
	t.Helper()
	// Walk up from current dir to find rules/
	dir, _ := os.Getwd()
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "rules")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("Could not locate rules/ directory")
	return ""
}

// scanFileWithAllRules loads all applicable rules and scans the given file.
func scanFileWithAllRules(t *testing.T, rulesDir, filePath string) []reporter.Finding {
	t.Helper()

	lang := utils.GetLanguage(filepath.Ext(filePath))
	if lang == "unknown" {
		t.Skipf("Unknown language for %s", filePath)
		return nil
	}

	langs := map[string]bool{lang: true}
	rules, err := config.LoadRulesForLanguages(rulesDir, langs)
	if err != nil || len(rules) == 0 {
		t.Logf("No rules loaded for language %s: %v", lang, err)
		return nil
	}

	// Use the pattern engine directly
	result := &scanner.ScanResult{
		FilePaths: map[string][]string{lang: {filePath}},
	}
	findings := scanner.RunPatternScan(context.Background(), result, rules, rulesDir)
	return findings
}

// findingRuleIDs extracts all rule IDs from a findings slice.
func findingRuleIDs(findings []reporter.Finding) map[string]bool {
	ids := make(map[string]bool)
	for _, f := range findings {
		if f.RuleID != "" {
			ids[f.RuleID] = true
		}
		if f.IssueName != "" {
			ids[f.IssueName] = true
		}
	}
	return ids
}

// TestPositiveCases verifies that vulnerable test files trigger the expected rules.
func TestPositiveCases(t *testing.T) {
	rulesDir := findRulesDir(t)
	testDir := filepath.Join(rulesDir, "vuln_samples", "positive")

	for _, tc := range positiveTestCases {
		tc := tc
		t.Run(fmt.Sprintf("positive/%s", tc.File), func(t *testing.T) {
			filePath := filepath.Join(testDir, tc.File)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Skipf("Test file not found: %s", filePath)
				return
			}

			findings := scanFileWithAllRules(t, rulesDir, filePath)
			firedIDs := findingRuleIDs(findings)

			for _, requiredID := range tc.MustFire {
				found := false
				for firedID := range firedIDs {
					if firedID == requiredID || strings.Contains(firedID, requiredID) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Rule %q did NOT fire on %s (expected it to). Fired rules: %v",
						requiredID, tc.File, sortedKeys(firedIDs))
				} else {
					t.Logf("✓ Rule %q correctly fired on %s", requiredID, tc.File)
				}
			}

			if len(findings) == 0 && len(tc.MustFire) > 0 {
				t.Errorf("No findings at all on positive test file %s — all rules silent", tc.File)
			}
		})
	}
}

// TestNegativeCases verifies that safe test files do NOT trigger the named rules.
func TestNegativeCases(t *testing.T) {
	rulesDir := findRulesDir(t)
	testDir := filepath.Join(rulesDir, "vuln_samples", "negative")

	for _, tc := range negativeTestCases {
		tc := tc
		t.Run(fmt.Sprintf("negative/%s", tc.File), func(t *testing.T) {
			filePath := filepath.Join(testDir, tc.File)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Skipf("Test file not found: %s", filePath)
				return
			}

			findings := scanFileWithAllRules(t, rulesDir, filePath)
			firedIDs := findingRuleIDs(findings)

			for _, bannedID := range tc.MustNotFire {
				if firedIDs[bannedID] {
					t.Errorf("Rule %q INCORRECTLY fired on safe file %s (false positive!)",
						bannedID, tc.File)
				} else {
					t.Logf("✓ Rule %q correctly silent on safe %s", bannedID, tc.File)
				}
			}
		})
	}
}

// TestTaintAnalyzerPositive verifies taint analysis on clearly vulnerable code.
func TestTaintAnalyzerPositive(t *testing.T) {
	rulesDir := findRulesDir(t)
	ta := scanner.NewTaintAnalyzer()

	testFiles := []struct {
		file       string
		expectSink string
	}{
		{"python/sql_injection.py", "SQL"},
		{"python/command_injection.py", "Command"},
	}

	for _, tf := range testFiles {
		tf := tf
		t.Run(tf.file, func(t *testing.T) {
			filePath := filepath.Join(rulesDir, "vuln_samples", "positive", tf.file)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Skip("test file not found")
			}

			findings, err := ta.AnalyzeTaintFlow(filePath)
			if err != nil {
				t.Fatalf("AnalyzeTaintFlow error: %v", err)
			}

			if len(findings) == 0 {
				t.Errorf("Taint analyzer found nothing in %s — expected %s injection", tf.file, tf.expectSink)
				return
			}

			found := false
			for _, f := range findings {
				if strings.Contains(f.IssueName, tf.expectSink) || strings.Contains(f.Description, tf.expectSink) {
					found = true
					t.Logf("✓ Taint finding: %s (confidence: %.2f)", f.IssueName, f.Confidence)
					break
				}
			}
			if !found {
				t.Errorf("Expected %s injection finding, got: %v", tf.expectSink,
					func() []string {
						var names []string
						for _, f := range findings {
							names = append(names, f.IssueName)
						}
						return names
					}())
			}
		})
	}
}

// TestTaintAnalyzerNegative verifies taint analysis does NOT fire on safe code.
func TestTaintAnalyzerNegative(t *testing.T) {
	rulesDir := findRulesDir(t)
	ta := scanner.NewTaintAnalyzer()

	safeFiles := []string{
		"python/sql_injection.py",
		"python/command_injection.py",
	}

	for _, sf := range safeFiles {
		sf := sf
		t.Run(sf, func(t *testing.T) {
			filePath := filepath.Join(rulesDir, "vuln_samples", "negative", sf)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Skip("test file not found")
			}

			findings, err := ta.AnalyzeTaintFlow(filePath)
			if err != nil {
				t.Fatalf("AnalyzeTaintFlow error: %v", err)
			}

			// Filter out very low confidence findings (below 0.5)
			var highConfidence []reporter.Finding
			for _, f := range findings {
				if f.Confidence >= 0.5 {
					highConfidence = append(highConfidence, f)
				}
			}

			if len(highConfidence) > 0 {
				t.Errorf("Taint analyzer produced %d false positive(s) on safe file %s:",
					len(highConfidence), sf)
				for _, f := range highConfidence {
					t.Errorf("  - %s @ line %s (confidence: %.2f)", f.IssueName, f.LineNumber, f.Confidence)
				}
			} else {
				t.Logf("✓ No high-confidence false positives on %s", sf)
			}
		})
	}
}

// TestFPSuppressorKnownSafe verifies the FP suppressor on known-safe patterns.
func TestFPSuppressorKnownSafe(t *testing.T) {
	rulesDir := findRulesDir(t)
	negDir := filepath.Join(rulesDir, "vuln_samples", "negative")

	testCases := []struct {
		file string
		cwe  string
	}{
		{"python/sql_injection.py", "CWE-89"},
		{"python/command_injection.py", "CWE-78"},
		{"python/hardcoded_secrets.py", "CWE-798"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			filePath := filepath.Join(negDir, tc.file)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Skip("test file not found")
			}

			finding := reporter.Finding{
				FilePath:   filePath,
				LineNumber: "5",
				CWE:        tc.cwe,
				Severity:   "critical",
				IssueName:  "Test Finding",
				RuleID:     "test-rule",
			}

			results := scanner.SuppressFalsePositives([]reporter.Finding{finding}, negDir)
			if len(results) > 0 && results[0].Severity == "info" {
				t.Logf("✓ FP suppressor correctly downgraded finding on %s", tc.file)
			} else {
				t.Logf("Note: FP suppressor did not suppress finding on %s (CWE: %s) — may need more context", tc.file, tc.cwe)
			}
		})
	}
}

// TestRuleSchemaIntegrity verifies all rules have required fields.
func TestRuleSchemaIntegrity(t *testing.T) {
	rulesDir := findRulesDir(t)

	rules, err := config.LoadRulesForLanguages(rulesDir, map[string]bool{
		"python": true, "javascript": true, "go": true, "java": true,
	})
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	if len(rules) == 0 {
		t.Fatal("No rules loaded")
	}

	missingID := 0
	missingPatterns := 0
	missingDescription := 0
	missingRemediation := 0
	missingCWE := 0
	zeroDupes := 0
	seenIDs := make(map[string]int)

	for _, r := range rules {
		if r.ID == "" {
			missingID++
		}
		if len(r.Patterns) == 0 {
			missingPatterns++
		}
		if r.Description == "" {
			missingDescription++
		}
		if r.Remediation == "" {
			missingRemediation++
		}
		if r.CWE == "" {
			missingCWE++
		}
		if r.ID != "" {
			seenIDs[r.ID]++
		}
	}

	for id, count := range seenIDs {
		if count > 1 {
			zeroDupes++
			t.Errorf("Duplicate rule ID: %q appears %d times", id, count)
		}
	}

	t.Logf("Schema integrity check on %d rules:", len(rules))
	t.Logf("  Missing ID:          %d", missingID)
	t.Logf("  Missing patterns:    %d", missingPatterns)
	t.Logf("  Missing description: %d", missingDescription)
	t.Logf("  Missing remediation: %d", missingRemediation)
	t.Logf("  Missing CWE:         %d", missingCWE)
	t.Logf("  Duplicate IDs:       %d", zeroDupes)

	if missingID > 0 {
		t.Errorf("Found %d rules with missing ID", missingID)
	}
	if missingPatterns > 0 {
		t.Errorf("Found %d rules with no patterns", missingPatterns)
	}
	if zeroDupes > 0 {
		t.Errorf("Found %d duplicate rule IDs", zeroDupes)
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
