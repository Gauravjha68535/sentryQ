package scanner

import (
	"QWEN_SCR_24_FEB_2026/reporter"
	"os"
	"path/filepath"
	"strings"
)

// SuppressFalsePositives examines code context around each finding and suppresses
// known safe patterns that should not be flagged. This fixes the "mitigation blindness"
// problem where the scanner flags safe implementations (crypto.randomBytes, textContent,
// parameterized queries, ALLOWED_HOSTS, etc.).
func SuppressFalsePositives(findings []reporter.Finding, targetDir string) []reporter.Finding {
	// Cache file contents to avoid re-reading
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

	var result []reporter.Finding
	for _, f := range findings {
		content := readFile(f.FilePath)
		if content == "" {
			result = append(result, f)
			continue
		}

		if shouldSuppress(f, content) {
			// Mark as suppressed FP — don't remove, just downgrade
			f.AiValidated = "No (False Positive - Safe Pattern)"
			f.Severity = "info"
			f.Description = "[SUPPRESSED] " + f.Description
		}

		result = append(result, f)
	}
	return result
}

// shouldSuppress checks if a finding matches known safe patterns in the source code.
func shouldSuppress(f reporter.Finding, fileContent string) bool {
	vulnType := strings.ToUpper(normalizeForFP(f))
	lines := strings.Split(fileContent, "\n")
	lineNum := parseLineNum(f.LineNumber)

	// Get context: ±10 lines around the finding
	startCtx := lineNum - 11
	if startCtx < 0 {
		startCtx = 0
	}
	endCtx := lineNum + 10
	if endCtx > len(lines) {
		endCtx = len(lines)
	}
	context := strings.ToLower(strings.Join(lines[startCtx:endCtx], "\n"))

	switch vulnType {
	case "WEAK_RANDOM":
		// Safe: crypto.randomBytes, secrets.token_hex, os.urandom, SecureRandom
		safeRandomAPIs := []string{
			"crypto.randombytes", "secrets.token_hex", "secrets.token_urlsafe",
			"os.urandom", "securerandom", "crypto/rand",
		}
		for _, safe := range safeRandomAPIs {
			if strings.Contains(context, safe) {
				return true
			}
		}

	case "PATH_TRAVERSAL":
		// Safe: path.resolve + startsWith check
		hasResolve := strings.Contains(context, "path.resolve") || strings.Contains(context, "os.path.realpath")
		hasStartsWith := strings.Contains(context, "startswith") || strings.Contains(context, "startswith(")
		if hasResolve && hasStartsWith {
			return true
		}

	case "XSS":
		// Safe: textContent (not innerHTML), JSON.stringify
		if lineNum > 0 && lineNum <= len(lines) {
			line := strings.ToLower(lines[lineNum-1])
			if strings.Contains(line, "textcontent") && !strings.Contains(line, "innerhtml") {
				return true
			}
		}

	case "SQLI":
		// Safe: parameterized queries with ? or $1 placeholders
		if lineNum > 0 && lineNum <= len(lines) {
			line := strings.ToLower(lines[lineNum-1])
			// Check for parameterized query patterns
			paramPatterns := []string{
				"where id = ?", "= ?\"", "= ?\\'", "= $1",
				".prepare(", "preparedstatement", "preparestatement",
			}
			for _, p := range paramPatterns {
				if strings.Contains(line, p) {
					return true
				}
			}
		}

	case "SSRF":
		// Safe: allowlist check before the request
		if strings.Contains(context, "allowed_hosts") ||
			strings.Contains(context, "allowlist") ||
			strings.Contains(context, "whitelist") {
			// Check there's actually a guard (if/not in check)
			if strings.Contains(context, "not in") || strings.Contains(context, "!==") ||
				strings.Contains(context, "!full.startswith") {
				return true
			}
		}

	case "HARDCODED_SECRET":
		// Safe: environment variable access (not hardcoded)
		if lineNum > 0 && lineNum <= len(lines) {
			line := strings.ToLower(lines[lineNum-1])
			envPatterns := []string{
				"process.env.", "os.environ", "os.getenv",
				"environment.getenvironmentvariable", "system.getenv",
			}
			for _, p := range envPatterns {
				if strings.Contains(line, p) {
					return true
				}
			}
		}

	case "INPUT_VALIDATION":
		// Suppress generic "environment variable used without validation" on env vars
		if lineNum > 0 && lineNum <= len(lines) {
			line := strings.ToLower(lines[lineNum-1])
			if strings.Contains(line, "process.env.") || strings.Contains(line, "os.environ") {
				return true
			}
		}

	case "IDOR":
		// Safe: parameterized queries (the IDOR flag on safe SQL is misleading)
		if lineNum > 0 && lineNum <= len(lines) {
			line := strings.ToLower(lines[lineNum-1])
			if strings.Contains(line, "= ?") || strings.Contains(line, "= $1") ||
				strings.Contains(line, ".prepare(") {
				return true
			}
		}

	case "RESOURCE_LIMIT":
		// Downgrade "express.json() without size limit" — it's hygiene, not a vuln
		return true
	}

	return false
}

// normalizeForFP maps a finding to a vulnerability family for FP suppression.
func normalizeForFP(f reporter.Finding) string {
	cwe := strings.ToUpper(strings.TrimSpace(f.CWE))
	cweFamilies := map[string]string{
		"CWE-330": "WEAK_RANDOM", "CWE-331": "WEAK_RANDOM", "CWE-338": "WEAK_RANDOM",
		"CWE-22": "PATH_TRAVERSAL", "CWE-23": "PATH_TRAVERSAL",
		"CWE-79": "XSS",
		"CWE-89": "SQLI",
		"CWE-918": "SSRF",
		"CWE-798": "HARDCODED_SECRET", "CWE-259": "HARDCODED_SECRET",
		"CWE-20": "INPUT_VALIDATION",
		"CWE-770": "RESOURCE_LIMIT",
	}
	if family, ok := cweFamilies[cwe]; ok {
		return family
	}

	combined := strings.ToLower(f.IssueName + " " + f.RuleID)
	if strings.Contains(combined, "random") || strings.Contains(combined, "entropy") || strings.Contains(combined, "token generation") {
		return "WEAK_RANDOM"
	}
	if strings.Contains(combined, "path traversal") || strings.Contains(combined, "sendfile") {
		return "PATH_TRAVERSAL"
	}
	if strings.Contains(combined, "xss") || strings.Contains(combined, "cross site scripting") {
		return "XSS"
	}
	if strings.Contains(combined, "sqli") || strings.Contains(combined, "sql injection") {
		return "SQLI"
	}
	if strings.Contains(combined, "ssrf") {
		return "SSRF"
	}
	if strings.Contains(combined, "idor") || strings.Contains(combined, "insecure data access") {
		return "IDOR"
	}
	if strings.Contains(combined, "hardcoded") || strings.Contains(combined, "secret") {
		return "HARDCODED_SECRET"
	}
	if strings.Contains(combined, "body parser") || strings.Contains(combined, "size limit") {
		return "RESOURCE_LIMIT"
	}
	return ""
}

func parseLineNum(lineRef string) int {
	parts := strings.Split(lineRef, "-")
	var n int
	for _, ch := range parts[0] {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		}
	}
	return n
}
