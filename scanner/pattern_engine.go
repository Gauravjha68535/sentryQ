package scanner

import (
	"QWEN_SCR_24_FEB_2026/config"
	"QWEN_SCR_24_FEB_2026/reporter"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

// scanJob represents a single file scanning job for the worker pool
type scanJob struct {
	filePath string
	rules    []config.Rule
}

// scanResult represents results from a single file scan
type scanResult struct {
	findings []reporter.Finding
}

// getDefaultConfidence returns a default confidence score based on severity
// Rules with explicit confidence in YAML will override this
func getDefaultConfidence(severity string) float64 {
	switch severity {
	case "critical":
		return 0.95
	case "high":
		return 0.85
	case "medium":
		return 0.70
	case "low":
		return 0.50
	case "info":
		return 0.40
	default:
		return 0.60
	}
}

// Pre-compiled regexes for framework detection (avoid recompiling per scan)
var frameworkDetectors = map[string]*regexp.Regexp{
	"django":  regexp.MustCompile(`(?i)"django"\s*[:=]|django-admin`),
	"flask":   regexp.MustCompile(`(?i)"flask"\s*[:=]|from\s+flask`),
	"fastapi": regexp.MustCompile(`(?i)"fastapi"\s*[:=]|from\s+fastapi`),
	"express": regexp.MustCompile(`(?i)"express"\s*[:=]|require\(['"]express['"]\)`),
	"spring":  regexp.MustCompile(`(?i)org\.springframework|spring-boot`),
	"laravel": regexp.MustCompile(`(?i)"laravel/framework"\s*[:=]|php\s+artisan`),
	"rails":   regexp.MustCompile(`(?i)gem\s+['"]rails['"]|rails/all`),
	"angular": regexp.MustCompile(`(?i)"@angular/core"\s*[:=]|angular\.module`),
	"react":   regexp.MustCompile(`(?i)"react"\s*[:=]|from\s+['"]react['"]`),
	"vue":     regexp.MustCompile(`(?i)"vue"\s*[:=]|from\s+['"]vue['"]`),
	"next_js": regexp.MustCompile(`(?i)"next"\s*[:=]|next\.config`),
	"nuxt_js": regexp.MustCompile(`(?i)"nuxt"\s*[:=]|nuxt\.config`),
	"svelte":  regexp.MustCompile(`(?i)"svelte"\s*[:=]|\.svelte`),
}

// detectFrameworks reads a subset of files to guess which frameworks are in use
func detectFrameworks(result *ScanResult) []string {
	frameworksFound := make(map[string]bool)

	importantFiles := map[string]bool{
		"package.json": true, "requirements.txt": true, "pom.xml": true,
		"go.mod": true, "gemfile": true, "composer.json": true,
	}

	// Quick check of package.json, requirements.txt, pom.xml, composer.json, etc.
	for _, files := range result.FilePaths {
		for _, file := range files {
			baseName := strings.ToLower(filepath.Base(file))
			if !importantFiles[baseName] {
				continue
			}

			content, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			source := string(content)

			for framework, re := range frameworkDetectors {
				if re.MatchString(source) {
					frameworksFound[framework] = true
				}
			}
		}
	}

	var frameworks []string
	for f := range frameworksFound {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

// frameworkFileMap maps detected framework names to their actual YAML filenames
// This handles case sensitivity (e.g., "angular" -> "Angular.yaml")
var frameworkFileMap = map[string]string{
	"django":  "django.yaml",
	"flask":   "flask.yaml",
	"fastapi": "fastapi.yaml",
	"express": "express.yaml",
	"spring":  "spring.yaml",
	"laravel": "laravel.yaml",
	"rails":   "rails.yaml",
	"angular": "Angular.yaml",
	"react":   "React.yaml",
	"vue":     "Vue.yaml",
	"next_js": "Next_js.yaml",
	"nuxt_js": "Nuxt_js.yaml",
	"svelte":  "svelte.yaml",
}

// localFrameworkDetectors for per-file verification to avoid generic language leakage
var localFrameworkDetectors = map[string]*regexp.Regexp{
	"angular": regexp.MustCompile(`(?i)import.*@angular|@Component|@Injectable`),
	"react":   regexp.MustCompile(`(?i)import.*react|useState|useEffect|JSX`),
	"vue":     regexp.MustCompile(`(?i)import.*vue|defineComponent|<template`),
	"next_js": regexp.MustCompile(`(?i)import.*next/|getServerSideProps|getStaticProps`),
	"nuxt_js": regexp.MustCompile(`(?i)import.*nuxt|useNuxtApp`),
	"express": regexp.MustCompile(`(?i)require\(['"]express['"]\)|import.*express`),
	"fastapi": regexp.MustCompile(`(?i)from\s+fastapi|FastAPI\(`),
	"flask":   regexp.MustCompile(`(?i)from\s+flask|Flask\(`),
}

// RunPatternScan performs multi-threaded pattern scanning across all files
func RunPatternScan(result *ScanResult, baseRules []config.Rule, rulesDir string) []reporter.Finding {
	// Detect frameworks and load specific rules
	detectedFrameworks := detectFrameworks(result)
	rules := append([]config.Rule(nil), baseRules...) // Copy base rules

	for _, framework := range detectedFrameworks {
		fileName, ok := frameworkFileMap[framework]
		if !ok {
			fileName = framework + ".yaml"
		}
		frameworkRulePath := filepath.Join(rulesDir, "frameworks", fileName)
		frameworkRules, err := config.LoadRulesFile(frameworkRulePath)
		if err == nil && len(frameworkRules) > 0 {
			// Tag framework rules to prevent leakage
			for i := range frameworkRules {
				frameworkRules[i].Framework = framework
			}
			rules = append(rules, frameworkRules...)
		}
	}
	// Pre-group rules by language for faster lookup
	rulesByLang := make(map[string][]config.Rule)
	for _, rule := range rules {
		for _, lang := range rule.Languages {
			rulesByLang[lang] = append(rulesByLang[lang], rule)
		}
	}

	// Collect all scanning jobs
	var jobs []scanJob
	for lang, files := range result.FilePaths {
		applicableRules, ok := rulesByLang[lang]
		if !ok || len(applicableRules) == 0 {
			continue
		}
		for _, filePath := range files {
			jobs = append(jobs, scanJob{
				filePath: filePath,
				rules:    applicableRules,
			})
		}
	}

	if len(jobs) == 0 {
		return nil
	}

	// Determine worker count (use CPU cores, min 2, max 8)
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}
	if numWorkers > 8 {
		numWorkers = 8
	}
	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}

	// Channel for jobs and results
	jobChan := make(chan scanJob, len(jobs))
	resultChan := make(chan scanResult, len(jobs))

	// Atomic counter for Sr numbers
	var srCounter int64

	// Start workers
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				findings := scanFile(job.filePath, job.rules, &srCounter)
				resultChan <- scanResult{findings: findings}
			}
		}()
	}

	// Send jobs
	for _, job := range jobs {
		jobChan <- job
	}
	close(jobChan)

	// Wait for completion and close results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect all findings
	var allFindings []reporter.Finding
	for res := range resultChan {
		allFindings = append(allFindings, res.findings...)
	}

	// Re-number findings sequentially
	for i := range allFindings {
		allFindings[i].SrNo = i + 1
	}

	return allFindings
}

// scanFile scans a single file against all applicable rules
func scanFile(filePath string, rules []config.Rule, counter *int64) []reporter.Finding {
	// Contextual Filtering 1: Skip test/mock files to reduce false positives
	if IsTestFile(filePath) {
		return nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	originalSource := string(content)

	// Contextual Filtering 2: Strip comments to avoid matching commented-out vulns
	ext := filepath.Ext(filePath)
	// We matched the file extension in helpers.go
	cleanSource := StripComments(originalSource, ext)

	var findings []reporter.Finding
	for _, rule := range rules {
		// Strict Isolation: Only run framework-specific rules on relevant files
		if rule.Framework != "" {
			if !shouldApplyFrameworkRule(rule.Framework, filePath, cleanSource) {
				continue
			}
		}

		for _, pattern := range rule.Patterns {
			if pattern.CompiledRegex == nil {
				continue
			}

			// Search against the clean source (comments replaced by spaces)
			matches := pattern.CompiledRegex.FindAllStringIndex(cleanSource, -1)
			for _, match := range matches {
				// We can still use originalSource or cleanSource for countLines
				// since the length and newlines are identical!
				startLine := countLines(originalSource[:match[0]]) + 1
				endLine := countLines(originalSource[:match[1]]) + 1

				lineRef := formatLineRef(startLine, endLine)

				// Determine confidence score
				confidence := rule.Confidence
				if confidence == 0 {
					confidence = getDefaultConfidence(rule.Severity)
				}

				srNo := int(atomic.AddInt64(counter, 1))

				findings = append(findings, reporter.Finding{
					SrNo:        srNo,
					IssueName:   rule.ID,
					FilePath:    filePath,
					Description: rule.Description,
					Severity:    normalizeSeverity(rule),
					LineNumber:  lineRef,
					AiValidated: "No",
					Remediation: rule.Remediation,
					RuleID:      rule.ID,
					Source:      "pattern-engine",
					CWE:         rule.CWE,
					OWASP:       rule.OWASP,
					Confidence:  confidence,
				})
				*counter = int64(srNo)
			}
		}
	}

	return findings
}

// shouldApplyFrameworkRule checks if a framework rule should apply to a specific file
func shouldApplyFrameworkRule(framework, filePath, content string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Step 1: File extension check (Base isolation)
	isJsTs := ext == ".js" || ext == ".ts" || ext == ".jsx" || ext == ".tsx"

	switch framework {
	case "svelte":
		return ext == ".svelte"
	case "react":
		if ext == ".jsx" || ext == ".tsx" {
			return true
		}
		if isJsTs {
			return localFrameworkDetectors["react"].MatchString(content)
		}
		return false
	case "angular":
		if isJsTs {
			return localFrameworkDetectors["angular"].MatchString(content)
		}
		return false
	case "vue":
		if ext == ".vue" {
			return true
		}
		if isJsTs {
			return localFrameworkDetectors["vue"].MatchString(content)
		}
		return false
	case "next_js":
		if isJsTs {
			return localFrameworkDetectors["next_js"].MatchString(content)
		}
		return false
	case "nuxt_js":
		if ext == ".vue" || isJsTs {
			return localFrameworkDetectors["nuxt_js"].MatchString(content)
		}
		return false
	case "laravel":
		return ext == ".php"
	case "rails":
		return ext == ".rb" || ext == ".erb"
	case "django", "flask", "fastapi":
		if ext == ".py" {
			// Optional: add content check if needed
			return true
		}
		return false
	case "express":
		if isJsTs {
			return localFrameworkDetectors["express"].MatchString(content)
		}
		return false
	case "spring":
		return ext == ".java" || ext == ".xml"
	default:
		return true // Fallback
	}
}

// normalizeSeverity enforces correct severity levels based on CWE mapping
func normalizeSeverity(rule config.Rule) string {
	// Critical Vulnerability Classes (RCE, SQLi, Auth Bypass, Deserialization)
	criticalCWEs := map[string]bool{
		"CWE-78":  true, // Command Injection
		"CWE-89":  true, // SQL Injection
		"CWE-94":  true, // Code Injection
		"CWE-502": true, // Deserialization
		"CWE-287": true, // Auth Bypass
		"CWE-918": true, // SSRF
		"CWE-798": true, // Hardcoded Credentials
	}

	highCWEs := map[string]bool{
		"CWE-79":  true, // XSS
		"CWE-22":  true, // Path Traversal
		"CWE-352": true, // CSRF
		"CWE-611": true, // XXE
		"CWE-942": true, // CORS Misconfiguration
	}

	cwe := strings.ToUpper(rule.CWE)
	if criticalCWEs[cwe] {
		return "critical"
	}
	if highCWEs[cwe] {
		return "high"
	}

	// Dynamic elevation for specific keywords in title/description
	desc := strings.ToLower(rule.Description + " " + rule.ID)
	if strings.Contains(desc, "rce") || strings.Contains(desc, "injection") || strings.Contains(desc, "bypass") || strings.Contains(rule.ID, "sql-injection") {
		if !strings.Contains(desc, "potential") && !strings.Contains(desc, "possible") {
			return "critical"
		}
		return "high"
	}

	if rule.Severity == "" {
		return "medium"
	}

	return strings.ToLower(rule.Severity)
}
