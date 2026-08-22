package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"SentryQ/utils"

	"gopkg.in/yaml.v3"
)

type YAMLRulePattern struct {
	Regex string `json:"regex" yaml:"regex"`
}

type YAMLRule struct {
	ID               string            `json:"id" yaml:"id"`
	Languages        []string          `json:"languages" yaml:"languages"`
	Patterns         []YAMLRulePattern `json:"patterns" yaml:"patterns"`
	NegativePatterns []YAMLRulePattern `json:"negative_patterns" yaml:"negative_patterns"`
	Severity         string            `json:"severity" yaml:"severity"`
	Description      string            `json:"description" yaml:"description"`
	Remediation      string            `json:"remediation" yaml:"remediation"`
	CWE              string            `json:"cwe" yaml:"cwe"`
	OWASP            string            `json:"owasp" yaml:"owasp"`
}

func handleRulesList(w http.ResponseWriter, r *http.Request) {
	rulesDir := getDefaultRulesDir()
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			httpJSON(w, http.StatusOK, []interface{}{})
			return
		}
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "Cannot read rules directory"})
		return
	}
	type RuleFileSummary struct {
		Filename  string `json:"filename"`
		RuleCount int    `json:"rule_count"`
	}
	var files []RuleFileSummary
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(rulesDir, e.Name()))
		if err != nil {
			continue
		}
		var rules []YAMLRule
		if parseErr := yaml.Unmarshal(data, &rules); parseErr != nil {
			utils.LogWarn(fmt.Sprintf("handleRulesList: failed to parse %s: %v", e.Name(), parseErr))
		}
		files = append(files, RuleFileSummary{Filename: e.Name(), RuleCount: len(rules)})
	}
	if files == nil {
		files = []RuleFileSummary{}
	}
	httpJSON(w, http.StatusOK, files)
}

func handleRulesFile(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if filename == "" || strings.Contains(filename, "..") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}
	rulesDir := getDefaultRulesDir()
	rulesPath := filepath.Join(rulesDir, filename)
	// Resolve symlinks before the prefix check so a symlink inside rules/
	// pointing outside cannot bypass the containment guard.
	resolvedPath, err := filepath.EvalSymlinks(rulesPath)
	if err != nil {
		// File may not exist yet (POST to create). Fall back to cleaned path.
		resolvedPath = filepath.Clean(rulesPath)
	}
	cleanedDir := filepath.Clean(rulesDir) + string(filepath.Separator)
	if !strings.HasPrefix(resolvedPath+string(filepath.Separator), cleanedDir) {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}
	rulesPath = resolvedPath

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(rulesPath)
		if err != nil {
			httpJSON(w, http.StatusNotFound, map[string]string{"error": "Rule file not found"})
			return
		}
		var rules []YAMLRule
		if parseErr := yaml.Unmarshal(data, &rules); parseErr != nil {
			utils.LogWarn(fmt.Sprintf("handleRulesFile GET: failed to parse %s: %v", filename, parseErr))
		}
		if rules == nil {
			rules = []YAMLRule{}
		}
		httpJSON(w, http.StatusOK, rules)

	case http.MethodPost:
		var newRule YAMLRule
		if err := json.NewDecoder(r.Body).Decode(&newRule); err != nil {
			http.Error(w, "Invalid rule JSON", http.StatusBadRequest)
			return
		}
		// Validate required fields
		if newRule.ID == "" || newRule.Severity == "" || len(newRule.Patterns) == 0 {
			http.Error(w, "id, severity, and patterns are required", http.StatusBadRequest)
			return
		}
		// Validate all regex patterns before writing to disk. An invalid or
		// catastrophically-backtracking pattern would be loaded into every subsequent
		// scan with no error message.
		for _, pat := range newRule.Patterns {
			if _, err := regexp.Compile(pat.Regex); err != nil {
				http.Error(w, "invalid regex in patterns: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		for _, pat := range newRule.NegativePatterns {
			if _, err := regexp.Compile(pat.Regex); err != nil {
				http.Error(w, "invalid regex in negative_patterns: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		// Load existing
		var rules []YAMLRule
		data, err := os.ReadFile(rulesPath)
		if err == nil {
			if parseErr := yaml.Unmarshal(data, &rules); parseErr != nil {
				http.Error(w, "Failed to parse existing rules file: "+parseErr.Error(), http.StatusInternalServerError)
				return
			}
		}
		rules = append(rules, newRule)
		out, err := yaml.Marshal(rules)
		if err != nil {
			http.Error(w, "Failed to serialize rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(rulesPath, out, 0600); err != nil {
			http.Error(w, "Failed to write rules file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		httpJSON(w, http.StatusOK, map[string]string{"status": "added", "id": newRule.ID})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleRulesTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Pattern string `json:"pattern"`
		Code    string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	type MatchResult struct {
		Line    int    `json:"line"`
		Content string `json:"content"`
		Match   string `json:"match"`
	}

	// Reject patterns that are excessively long to guard against ReDoS.
	// Go's regexp package uses RE2 (no catastrophic backtracking), but very
	// long patterns can still cause high compile-time CPU usage.
	if len(req.Pattern) > 2048 {
		httpJSON(w, http.StatusOK, map[string]interface{}{
			"valid":   false,
			"error":   "pattern too long (max 2048 characters)",
			"matches": []MatchResult{},
		})
		return
	}
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		httpJSON(w, http.StatusOK, map[string]interface{}{
			"valid":   false,
			"error":   err.Error(),
			"matches": []MatchResult{},
		})
		return
	}

	lines := strings.Split(req.Code, "\n")
	var matches []MatchResult
	for i, line := range lines {
		loc := re.FindString(line)
		if loc != "" {
			matches = append(matches, MatchResult{Line: i + 1, Content: line, Match: loc})
		}
	}
	if matches == nil {
		matches = []MatchResult{}
	}
	httpJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"matches": matches,
	})
}
