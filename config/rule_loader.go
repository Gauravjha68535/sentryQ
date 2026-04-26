package config

import (
	"SentryQ/utils"
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule represents a single vulnerability pattern
type Rule struct {
	ID        string   `yaml:"id"`
	Languages []string `yaml:"languages"`
	Patterns  []struct {
		Regex         string         `yaml:"regex"`
		CompiledRegex *regexp.Regexp `yaml:"-"` // Added for performance (ignored by yaml)
	} `yaml:"patterns"`
	Severity    string  `yaml:"severity"`
	Description string  `yaml:"description"`
	Remediation string  `yaml:"remediation"`
	CWE         string  `yaml:"cwe"`
	OWASP       string  `yaml:"owasp"`
	Confidence  float64 `yaml:"confidence"`
	Framework   string  `yaml:"framework"` // Tag for framework-specific rules
}

// flexRule is a more tolerant intermediate representation that handles
// both map and list formats for "patterns", plus a singular "pattern" key.
type flexRule struct {
	ID          string      `yaml:"id"`
	Languages   []string    `yaml:"languages"`
	Patterns    interface{} `yaml:"patterns"` // can be a list or a map
	Pattern     string      `yaml:"pattern"`  // some files use singular "pattern"
	Severity    string      `yaml:"severity"`
	Description string      `yaml:"description"`
	Remediation string      `yaml:"remediation"`
	CWE         string      `yaml:"cwe"`
	OWASP       string      `yaml:"owasp"`
	Confidence  float64     `yaml:"confidence"`
	Framework   string      `yaml:"framework"`
}

// normalizeRule converts a flexRule to a strict Rule
func normalizeRule(fr flexRule) Rule {
	r := Rule{
		ID:          fr.ID,
		Languages:   fr.Languages,
		Severity:    fr.Severity,
		Description: fr.Description,
		Remediation: fr.Remediation,
		CWE:         fr.CWE,
		OWASP:       fr.OWASP,
		Confidence:  fr.Confidence,
		Framework:   fr.Framework,
	}

	switch p := fr.Patterns.(type) {
	case []interface{}:
		// Standard list format: patterns: [- regex: "..."]
		for _, item := range p {
			if m, ok := item.(map[string]interface{}); ok {
				if regexVal, ok := m["regex"].(string); ok {
					r.Patterns = append(r.Patterns, struct {
						Regex         string         `yaml:"regex"`
						CompiledRegex *regexp.Regexp `yaml:"-"`
					}{Regex: regexVal})
				}
			}
		}
	case map[string]interface{}:
		// Map format: patterns: {regex: "..."}
		if regexVal, ok := p["regex"].(string); ok {
			r.Patterns = append(r.Patterns, struct {
				Regex         string         `yaml:"regex"`
				CompiledRegex *regexp.Regexp `yaml:"-"`
			}{Regex: regexVal})
		}
	case string:
		// Single string format: patterns: "some_regex"
		r.Patterns = append(r.Patterns, struct {
			Regex         string         `yaml:"regex"`
			CompiledRegex *regexp.Regexp `yaml:"-"`
		}{Regex: p})
	}

	// Fallback: if "pattern" (singular) was used
	if len(r.Patterns) == 0 && fr.Pattern != "" {
		r.Patterns = append(r.Patterns, struct {
			Regex         string         `yaml:"regex"`
			CompiledRegex *regexp.Regexp `yaml:"-"`
		}{Regex: fr.Pattern})
	}

	return r
}

// LoadRulesFile loads rules from a single YAML file with maximum tolerance
func LoadRulesFile(filePath string) ([]Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var rules []Rule

	// === Strategy 1: Try strict parsing as []Rule ===
	if err := yaml.Unmarshal(data, &rules); err == nil {
		return compilePatterns(rules), nil
	}

	// === Strategy 2: Try flexible parsing as []flexRule ===
	var flexRules []flexRule
	if err := yaml.Unmarshal(data, &flexRules); err == nil {
		for _, fr := range flexRules {
			if fr.ID != "" {
				rules = append(rules, normalizeRule(fr))
			}
		}
		if len(rules) > 0 {
			return compilePatterns(rules), nil
		}
	}

	// === Strategy 3: Split file into individual YAML documents and parse each ===
	// This handles files where some rules are valid and others have syntax errors.
	rules = parseRulesLineByLine(data, filePath)
	if len(rules) > 0 {
		return compilePatterns(rules), nil
	}

	return nil, fmt.Errorf("failed to parse rule YAML (%s): no valid rules found", filepath.Base(filePath))
}

// parseRulesLineByLine splits YAML content at "- id:" boundaries and
// parses each rule individually. This rescues valid rules from files
// that contain some broken rules.
func parseRulesLineByLine(data []byte, filePath string) []Rule {
	var rules []Rule
	content := string(data)

	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentChunk strings.Builder
	inRule := false
	baseName := filepath.Base(filePath)
	totalBroken := 0

	for scanner.Scan() {
		line := scanner.Text()

		// Detect start of new rule: "- id:"
		if strings.HasPrefix(strings.TrimSpace(line), "- id:") {
			// Process previous chunk if exists
			if inRule && currentChunk.Len() > 0 {
				parsed := tryParseChunk(currentChunk.String())
				if parsed != nil {
					rules = append(rules, *parsed)
				} else {
					totalBroken++
				}
			}
			currentChunk.Reset()
			inRule = true
		}

		if inRule {
			currentChunk.WriteString(line)
			currentChunk.WriteString("\n")
		}
	}

	// Process last chunk
	if inRule && currentChunk.Len() > 0 {
		parsed := tryParseChunk(currentChunk.String())
		if parsed != nil {
			rules = append(rules, *parsed)
		} else {
			totalBroken++
		}
	}

	if totalBroken > 0 {
		utils.LogWarn(fmt.Sprintf("  %s: rescued %d rules, %d rules had syntax errors (skipped)",
			baseName, len(rules), totalBroken))
	}

	return rules
}

// sanitizeYAMLChunk aggressively cleans up common syntax errors in rule chunks.
// The most common issue is unescaped single quotes inside single-quoted YAML strings.
// For example: remediation: "Use os.getenv('SECRET_KEY')" or regex: 'foo['\"]bar'
// We detect lines with a key: 'value' pattern and escape inner single quotes.
func sanitizeYAMLChunk(chunk string) string {
	lines := strings.Split(chunk, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Find any YAML value wrapped in single quotes: "  key: 'value'"
		// We look for the pattern ": '" which indicates a single-quoted YAML value
		colonQuoteIdx := strings.Index(line, ": '")
		if colonQuoteIdx == -1 {
			// Also check for "- regex: '" list item pattern
			colonQuoteIdx = strings.Index(line, "regex: '")
			if colonQuoteIdx != -1 {
				colonQuoteIdx = strings.Index(line[colonQuoteIdx:], ": '")
				if colonQuoteIdx != -1 {
					colonQuoteIdx += strings.Index(line, "regex: '")
				}
			}
		}

		if colonQuoteIdx == -1 {
			continue
		}

		firstQuote := colonQuoteIdx + 2 // position of the opening '
		lastQuote := strings.LastIndex(line, "'")

		if firstQuote >= len(line) || lastQuote <= firstQuote {
			continue
		}

		innerString := line[firstQuote+1 : lastQuote]

		// Check if there are any unescaped single quotes inside
		// (A properly escaped single quote in YAML is '')
		testInner := strings.ReplaceAll(innerString, "''", "")
		if !strings.Contains(testInner, "'") {
			continue // No unescaped inner quotes, this line is fine
		}

		prefix := line[:firstQuote+1]
		suffix := line[lastQuote:]

		// Step 1: Temporarily protect already-escaped '' sequences
		cleanInner := strings.ReplaceAll(innerString, "''", "\x00\x00")
		// Step 2: Escape all remaining single quotes by doubling them
		cleanInner = strings.ReplaceAll(cleanInner, "'", "''")
		// Step 3: Restore the originally escaped sequences
		cleanInner = strings.ReplaceAll(cleanInner, "\x00\x00", "''")

		lines[i] = prefix + cleanInner + suffix
	}
	return strings.Join(lines, "\n")
}

// tryParseChunk attempts to parse a single YAML rule chunk
func tryParseChunk(chunk string) *Rule {
	sanitizedChunk := sanitizeYAMLChunk(chunk)

	// Try strict first
	var rules []Rule
	if err := yaml.Unmarshal([]byte(sanitizedChunk), &rules); err == nil && len(rules) > 0 {
		return &rules[0]
	}

	// Try flexible
	var flexRules []flexRule
	if err := yaml.Unmarshal([]byte(sanitizedChunk), &flexRules); err == nil && len(flexRules) > 0 {
		r := normalizeRule(flexRules[0])
		return &r
	}

	return nil
}

// compilePatterns pre-compiles regexes for all rules and removes any rule
// that ends up with zero compilable patterns so it never silently no-ops.
func compilePatterns(rules []Rule) []Rule {
	valid := rules[:0] // reuse backing array; no allocation
	for i := range rules {
		compiledAny := false
		for j := range rules[i].Patterns {
			if rules[i].Patterns[j].Regex == "" {
				// Empty regex matches everything — skip to avoid flooding results.
				utils.LogWarn(fmt.Sprintf("Rule %s has an empty regex pattern — skipping that pattern", rules[i].ID))
				continue
			}
			r, err := regexp.Compile(rules[i].Patterns[j].Regex)
			if err != nil {
				utils.LogWarn(fmt.Sprintf("Invalid regex in rule %s: %v — skipping pattern", rules[i].ID, err))
			} else {
				rules[i].Patterns[j].CompiledRegex = r
				compiledAny = true
			}
		}
		if !compiledAny {
			// All patterns in this rule are either empty or invalid — drop the
			// rule entirely so it doesn't appear in rule counts misleadingly.
			if rules[i].ID != "" {
				utils.LogWarn(fmt.Sprintf("Rule %s has no valid patterns and will be skipped", rules[i].ID))
			}
			continue
		}
		valid = append(valid, rules[i])
	}
	return valid
}

// langToRuleFiles maps a detected language name to the rule YAML file(s) it should load.
// Most languages follow the "{lang}.yaml" convention; exceptions are listed explicitly.
// Languages that map to multiple files (e.g. yaml infra files) return a slice.
var langToRuleFiles = map[string][]string{
	"dockerfile":    {"docker.yaml"},
	"objective-c":   {"objective-c.yaml"},
	"objective-cpp": {"cpp.yaml"},
	// yaml files may be k8s/ansible/helm/cloud manifests — load all infra rule sets
	"yaml": {"kubernetes.yaml", "ansible.yaml", "helm.yaml", "cloudformation.yaml", "azure.yaml", "gcp.yaml", "serverless.yaml", "cicd.yaml"},
	"json": {"cloudformation.yaml", "azure.yaml"},
	"xml":  {"aspnet.yaml"},
	"asp":  {"asp.yaml", "aspnet.yaml"},
	// vb / vbscript have no dedicated rule files — skip
	"vb":       {},
	"vbscript": {},
	// misc languages without rule files
	"css":         {},
	"sass":        {},
	"less":        {},
	"vue":         {},
	"svelte":      {},
	"toml":        {},
	"ini":         {},
	"env":         {},
	"text":        {},
	"markdown":    {},
	"tsql":        {"sql.yaml"},
	"plsql":       {"sql.yaml"},
	"webassembly": {"wasm.yaml"},
	"wat":         {"wasm.yaml"},
	"wasm":        {"wasm.yaml"},
	"graphql":     {"graphql.yaml", "graphql_subscriptions.yaml"},
	"gql":         {"graphql.yaml", "graphql_subscriptions.yaml"},
}

// alwaysLoadRuleFiles are loaded for every scan regardless of detected languages.
// These cover cross-cutting security concerns that span many languages.
var alwaysLoadRuleFiles = []string{
	"general.yaml",
	"insecure_randomness.yaml",
	"racecondition.yaml",
	"supplychain.yaml",
	"xxe.yaml",
	"deserialization.yaml",
	"ssrf.yaml",
	"api_security.yaml",
	"cicd.yaml",
	"graphql_subscriptions.yaml",
	"secrets.yaml",
	"cryptography.yaml",
	"authentication.yaml",
	"oauth_oidc.yaml",
	"template_injection.yaml",
	"nosql_injection.yaml",
	"prototype_pollution.yaml",
	"ldap_injection.yaml",
	"email_smtp_injection.yaml",
	"http_request_smuggling.yaml",
	"websocket_security.yaml",
	"jwt_advanced.yaml",
	"redos_regex.yaml",
	"container_security.yaml",
	"database_orm.yaml",
	"memory_safety_escapes.yaml",
	"service_mesh.yaml",
	"ebpf_security.yaml",
	"runtime_security.yaml",
	"cache_poisoning.yaml",
	"xss_advanced.yaml",
	"cors_advanced.yaml",
	"csp_bypass.yaml",
	"sidechannel_timing.yaml",
	"nosql_graphdb.yaml",
	"aiml.yaml",
	"android_security.yaml",
	"ios_security.yaml",
	"flutter_security.yaml",
}

// LoadRulesForLanguages loads only the rule files relevant to the detected languages,
// plus the always-on cross-language rule files. This avoids loading hundreds of
// irrelevant rules when scanning a single-language codebase.
func LoadRulesForLanguages(rulesDir string, languages map[string]bool) ([]Rule, error) {
	// Build the set of rule file names to load
	toLoad := make(map[string]bool)
	for _, f := range alwaysLoadRuleFiles {
		toLoad[f] = true
	}

	for lang := range languages {
		if fileNames, ok := langToRuleFiles[lang]; ok {
			for _, f := range fileNames {
				if f != "" {
					toLoad[f] = true
				}
			}
		} else {
			// Default convention: {lang}.yaml
			toLoad[lang+".yaml"] = true
		}
	}

	var allRules []Rule
	for fileName := range toLoad {
		path := filepath.Join(rulesDir, fileName)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue // No rule file for this language — skip silently
		}
		rules, err := LoadRulesFile(path)
		if err != nil {
			utils.LogError(fmt.Sprintf("Failed to parse rule YAML (%s)", fileName), err)
			continue
		}
		allRules = append(allRules, rules...)
		utils.LogInfo(fmt.Sprintf("Loaded %d rules from %s", len(rules), fileName))
	}

	return allRules, nil
}
