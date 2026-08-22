package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestRuleFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test rule file %s: %v", name, err)
	}
	return path
}

const minimalRule = `
- id: test-sqli
  languages:
  - python
  patterns:
  - regex: 'execute\s*\(\s*["\x60][^"]+%s'
  severity: critical
  description: SQL injection via string formatting
  cwe: CWE-89
  confidence: 0.9
`

const ruleWithNegative = `
- id: test-xss-negative
  languages:
  - javascript
  patterns:
  - regex: innerHTML\s*=
  negative_patterns:
  - regex: textContent
  severity: high
  description: XSS via innerHTML
  cwe: CWE-79
  confidence: 0.8
`

// ─── LoadRulesFile ────────────────────────────────────────────────────────────

func TestLoadRulesFileBasic(t *testing.T) {
	dir := t.TempDir()
	writeTestRuleFile(t, dir, "test.yaml", minimalRule)
	rules, err := LoadRulesFile(filepath.Join(dir, "test.yaml"))
	if err != nil {
		t.Fatalf("LoadRulesFile returned error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.ID != "test-sqli" {
		t.Errorf("rule ID = %q, want test-sqli", r.ID)
	}
	if r.Severity != "critical" {
		t.Errorf("rule Severity = %q, want critical", r.Severity)
	}
	if len(r.Patterns) == 0 {
		t.Error("rule has no patterns")
	}
}

func TestLoadRulesFileCompilesRegex(t *testing.T) {
	dir := t.TempDir()
	writeTestRuleFile(t, dir, "test.yaml", minimalRule)
	rules, err := LoadRulesFile(filepath.Join(dir, "test.yaml"))
	if err != nil {
		t.Fatalf("LoadRulesFile returned error: %v", err)
	}
	for _, r := range rules {
		for i, p := range r.Patterns {
			if p.Regex != "" && p.CompiledRegex == nil {
				t.Errorf("rule %s pattern[%d] regex not compiled", r.ID, i)
			}
		}
	}
}

func TestLoadRulesFileNegativePatterns(t *testing.T) {
	dir := t.TempDir()
	writeTestRuleFile(t, dir, "xss.yaml", ruleWithNegative)
	rules, err := LoadRulesFile(filepath.Join(dir, "xss.yaml"))
	if err != nil {
		t.Fatalf("LoadRulesFile returned error: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("expected at least 1 rule")
	}
	if len(rules[0].NegativePatterns) == 0 {
		t.Error("expected negative_patterns to be loaded")
	}
	if rules[0].NegativePatterns[0].CompiledRegex == nil {
		t.Error("negative pattern regex not compiled")
	}
}

func TestLoadRulesFileNonexistent(t *testing.T) {
	_, err := LoadRulesFile("/nonexistent/path/rules.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestLoadRulesFileInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	writeTestRuleFile(t, dir, "bad.yaml", "{{invalid yaml: [}")
	_, err := LoadRulesFile(filepath.Join(dir, "bad.yaml"))
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoadRulesFileBadRegex(t *testing.T) {
	dir := t.TempDir()
	// Invalid regex — LoadRulesFile should not crash, just skip compilation
	writeTestRuleFile(t, dir, "bad_regex.yaml", `
- id: bad-regex
  languages: [go]
  patterns:
  - regex: '(?P<invalid'
  severity: medium
  description: test
  confidence: 0.5
`)
	// Should not panic — bad regex is logged and skipped
	rules, _ := LoadRulesFile(filepath.Join(dir, "bad_regex.yaml"))
	_ = rules
}

// ─── LoadRulesForLanguages ────────────────────────────────────────────────────

func TestLoadRulesForLanguagesLoadsMatchingFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestRuleFile(t, dir, "python.yaml", minimalRule)

	rules, err := LoadRulesForLanguages(dir, map[string]bool{"python": true})
	if err != nil {
		t.Fatalf("LoadRulesForLanguages returned error: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.ID == "test-sqli" {
			found = true
			break
		}
	}
	if !found {
		t.Error("LoadRulesForLanguages did not load python.yaml rule for detected python language")
	}
}

func TestLoadRulesForLanguagesLoadsFrameworkSubdir(t *testing.T) {
	dir := t.TempDir()
	frameworksDir := filepath.Join(dir, "frameworks")
	if err := os.MkdirAll(frameworksDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestRuleFile(t, frameworksDir, "django.yaml", minimalRule)

	rules, err := LoadRulesForLanguages(dir, map[string]bool{})
	if err != nil {
		t.Fatalf("LoadRulesForLanguages returned error: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.ID == "test-sqli" {
			found = true
			break
		}
	}
	if !found {
		t.Error("LoadRulesForLanguages did not load rules from frameworks/ subdirectory")
	}
}

func TestLoadRulesForLanguagesEmptyDir(t *testing.T) {
	dir := t.TempDir()
	rules, err := LoadRulesForLanguages(dir, map[string]bool{"python": true})
	if err != nil {
		t.Fatalf("unexpected error for empty dir: %v", err)
	}
	if rules == nil {
		rules = []Rule{}
	}
	// Empty dir → empty (or nil) rules slice, no crash
	_ = rules
}

func TestLoadRulesForLanguagesAlwaysLoadFiles(t *testing.T) {
	dir := t.TempDir()
	// Write one of the always-load files
	writeTestRuleFile(t, dir, "general.yaml", minimalRule)

	// Even with no detected languages, general.yaml should be loaded
	rules, err := LoadRulesForLanguages(dir, map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.ID == "test-sqli" {
			found = true
		}
	}
	if !found {
		t.Error("alwaysLoadRuleFiles entry (general.yaml) not loaded when no languages detected")
	}
}
