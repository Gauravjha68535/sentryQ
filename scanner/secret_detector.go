package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// SecretDetector detects hardcoded secrets using pattern matching + entropy analysis
type SecretDetector struct {
	patterns []*regexp.Regexp
}

// secretDetectorPatterns is compiled once at startup to avoid the cost of
// regexp.MustCompile on every NewSecretDetector() call.
var secretDetectorPatterns = []*regexp.Regexp{
	// Generic secrets
	regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]`),
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"][a-zA-Z0-9]{16,}['"]`),
	regexp.MustCompile(`(?i)(secret|token|auth)\s*[=:]\s*['"][^'"]{16,}['"]`),

	// AWS credentials
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['"][^'"]{40}['"]`),

	// GitHub tokens
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`ghu_[a-zA-Z0-9]{36}`),

	// Stripe keys
	regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`),
	regexp.MustCompile(`sk_test_[a-zA-Z0-9]{24,}`),

	// Private keys
	regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),

	// JWT tokens
	regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),

	// Google API keys
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),

	// Slack tokens
	regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),

	// Generic high-entropy strings (will be filtered by entropy check)
	regexp.MustCompile(`['"][a-zA-Z0-9+/=]{32,}['"]`),
}

// HighEntropyThreshold is the Shannon entropy threshold above which a string
// is considered "high entropy" (likely a secret). This single constant is
// used by both the secret detector and the AST analyzer (via helpers.go).
const HighEntropyThreshold = 4.5

// descriptiveEntropyThreshold is a stricter threshold used ONLY for the
// description text ("High-entropy string detected") to reduce noise.
const descriptiveEntropyThreshold = 5.0

// NewSecretDetector creates a new secret detector with enhanced patterns
func NewSecretDetector() *SecretDetector {
	return &SecretDetector{patterns: secretDetectorPatterns}
}

// ScanSecrets scans for hardcoded secrets with entropy analysis
func (sd *SecretDetector) ScanSecrets(targetDir string) ([]reporter.Finding, error) {
	var findings []reporter.Finding
	srNo := 1

	utils.LogInfo("Starting secret detection scan...")

	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			utils.LogWarn(fmt.Sprintf("Secret scanner: skipping unreadable path %s: %v", path, err))
			return nil // log and continue — don't abort the entire scan
		}
		if info.IsDir() {
			// Skip common directories
			skipDirs := []string{"node_modules", "vendor", ".git", "__pycache__", "venv", ".venv", "env", ".env"}
			nameLower := strings.ToLower(info.Name())
			for _, skip := range skipDirs {
				if nameLower == skip {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Skip binary files and large files
		// Risk 3 fix: Lowered from 10MB to 2MB — large minified JS/JSON files
		// can spike RAM during regex+entropy processing
		if info.Size() > 2*1024*1024 { // 2MB
			utils.LogWarn(fmt.Sprintf("Secret scanner: skipping large file (%.1f MB) %s — secrets in files >2 MB are not checked",
				float64(info.Size())/(1024*1024), path))
			return nil
		}

		// Skip test files and examples (configurable)
		if utils.IsTestFile(path) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		source := string(content)
		newlineIndices := buildNewlineIndices(source)

		for _, pattern := range sd.patterns {
			matches := pattern.FindAllStringIndex(source, -1)
			for _, match := range matches {
				startLine := getLineNumber(newlineIndices, match[0])
				matchedText := source[match[0]:match[1]]

				// Check if this is a high-entropy string (likely a secret)
				if hasHighEntropy(matchedText) || isKnownSecretPattern(matchedText) {
					// Try to decode base64/hex to check for nested secrets
					decoded := tryDecodeSecret(matchedText)
					if decoded != "" && hasHighEntropy(decoded) {
						matchedText = decoded
					}

					// Live Validation (Disabled to prevent network leaking of sensitive tokens)
					issueName := "Hardcoded Secret Detected"
					severity := "critical"

					findings = append(findings, reporter.Finding{
						SrNo:        srNo,
						IssueName:   issueName,
						FilePath:    path,
						Description: generateSecretDescription(matchedText),
						Severity:    severity,
						LineNumber:  fmt.Sprintf("%d", startLine),
						AiValidated: "No",
						Remediation: "Remove hardcoded secret. Use environment variables, secrets manager, or vault. If VERIFIED LIVE, revoke immediately.",
						RuleID:      "secret-detector-entropy",
						Source:      "secret-detector",
						CWE:         "CWE-798",
						OWASP:       "A07:2021-Identification and Authentication Failures",
						Confidence:  0.95,
					})
					srNo++
				}
			}
		}

		return nil
	})

	return findings, err
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// Pre-compiled regexes for known secret patterns (avoid recompiling per match)
var knownSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`),                // AWS Access Key
	regexp.MustCompile(`^ghp_[a-zA-Z0-9]{36}$`),             // GitHub PAT
	regexp.MustCompile(`^sk_(live|test)_[a-zA-Z0-9]{24,}$`), // Stripe
	regexp.MustCompile(`^eyJ[a-zA-Z0-9_-]*\.eyJ`),           // JWT
	regexp.MustCompile(`^AIza[0-9A-Za-z_-]{35}$`),           // Google API
	regexp.MustCompile(`^xox[baprs]-`),                      // Slack
	regexp.MustCompile(`-----BEGIN.*PRIVATE KEY-----`),
}

// isKnownSecretPattern checks if string matches known secret patterns
func isKnownSecretPattern(s string) bool {
	for _, pattern := range knownSecretPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}
	return false
}

// tryDecodeSecret attempts to decode base64/hex encoded secrets
func tryDecodeSecret(s string) string {
	// Remove quotes and common prefixes
	s = strings.Trim(s, `'"`)
	s = regexp.MustCompile(`^(password|secret|key|token|api[_-]?key)\s*[=:]\s*`).ReplaceAllString(s, "")

	// Try base64 decode
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && len(decoded) > 8 {
		return string(decoded)
	}
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil && len(decoded) > 8 {
		return string(decoded)
	}

	// Try hex decode
	if decoded, err := hex.DecodeString(s); err == nil && len(decoded) > 8 {
		return string(decoded)
	}

	return ""
}



// generateSecretDescription generates a descriptive message for the finding
func generateSecretDescription(matchedText string) string {
	cleaned := regexp.MustCompile(`['":=\s]`).ReplaceAllString(matchedText, "")

	if strings.HasPrefix(cleaned, "AKIA") {
		return "AWS Access Key ID detected in source code"
	}
	if strings.HasPrefix(cleaned, "ghp_") {
		return "GitHub Personal Access Token detected"
	}
	if strings.HasPrefix(cleaned, "sk_live_") || strings.HasPrefix(cleaned, "sk_test_") {
		return "Stripe API key detected"
	}
	if strings.HasPrefix(cleaned, "eyJ") {
		return "JWT token detected in source code"
	}
	if strings.HasPrefix(cleaned, "AIza") {
		return "Google API key detected"
	}
	if strings.Contains(cleaned, "PRIVATE KEY") {
		return "Private key detected in source code"
	}
	if calculateEntropy(cleaned) > descriptiveEntropyThreshold {
		return "High-entropy string detected (likely a secret or credential)"
	}

	return "Potential hardcoded secret detected"
}


