package scanner

import (
	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type SemgrepResult struct {
	CheckID  string    `json:"check_id"`
	Path     string    `json:"path"`
	Start    StartInfo `json:"start"`
	End      EndInfo   `json:"end"`
	Extra    ExtraInfo `json:"extra"`
	Severity string    `json:"severity"`
}

type StartInfo struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type EndInfo struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type ExtraInfo struct {
	Message string `json:"message"`
}

type SemgrepOutput struct {
	Results []SemgrepResult `json:"results"`
}

// getSemgrepBin returns the correct executable name based on OS
func getSemgrepBin() string {
	if runtime.GOOS == "windows" {
		return "semgrep.exe"
	}
	return "semgrep"
}

func RunSemgrep(ctx context.Context, targetDir string) ([]reporter.Finding, error) {
	var findings []reporter.Finding

	_, err := exec.LookPath(getSemgrepBin())
	if err != nil {
		utils.LogInfo("Semgrep not found. Skipping Semgrep scan.")
		utils.LogInfo("Install with: pip3 install semgrep")
		return findings, nil
	}

	// Auto-detect project frameworks to load targeted rules
	frameworkConfigs := detectWebFrameworks(targetDir)

	utils.LogInfo(fmt.Sprintf("Semgrep detected. Running with targeted rules: %v", frameworkConfigs))

	args := []string{"--json", "--quiet"}

	// Always include the default auto config
	args = append(args, "--config", "auto")

	// Append targeted framework configs
	for _, conf := range frameworkConfigs {
		args = append(args, "--config", conf)
	}

	args = append(args, targetDir)

	cmd := exec.Command(getSemgrepBin(), args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() == 1 {
				// Findings found, continue
			} else if exitError.ExitCode() == 2 {
				utils.LogError("Semgrep configuration error", fmt.Errorf("%s", stderr.String()))
				return findings, nil
			}
		} else {
			utils.LogError("Semgrep execution failed", err)
			return findings, nil
		}
	}

	var output SemgrepOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		utils.LogError("Failed to parse Semgrep JSON", err)
		return findings, nil
	}

	utils.LogInfo(fmt.Sprintf("Semgrep found %d potential issues", len(output.Results)))

	for _, result := range output.Results {
		if blockedRuleIDs[result.CheckID] {
			continue
		}
		
		lineRef := formatLineRef(result.Start.Line, result.End.Line)
		severity := mapSemgrepSeverity(result.Severity)
		description := result.Extra.Message

		findings = append(findings, reporter.Finding{
			SrNo:        0,
			IssueName:   cleanSemgrepIssueName(result.CheckID),
			FilePath:    result.Path,
			Description: description,
			Severity:    severity,
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Review Semgrep rule: https://semgrep.dev/r/" + result.CheckID,
			RuleID:      result.CheckID,
			Source:      "semgrep",
		})
	}

	return findings, nil
}

func cleanSemgrepIssueName(checkID string) string {
	parts := strings.Split(checkID, ".")
	if len(parts) < 2 {
		return checkID
	}

	lang := parts[0]
	langName := mapLanguageName(lang)
	issueType := detectIssueType(parts)

	if issueType != "" {
		return fmt.Sprintf("%s %s", langName, issueType)
	}

	lastPart := parts[len(parts)-1]
	return fmt.Sprintf("%s %s", langName, cases.Title(language.English).String(strings.ReplaceAll(lastPart, "-", " ")))
}

func mapLanguageName(lang string) string {
	mapping := map[string]string{
		"go": "Go", "java": "Java", "javascript": "JavaScript",
		"typescript": "TypeScript", "python": "Python", "php": "PHP",
		"csharp": "C#", "ruby": "Ruby", "html": "HTML", "generic": "Generic",
	}
	if name, ok := mapping[lang]; ok {
		return name
	}
	return cases.Title(language.English).String(lang)
}

func detectIssueType(parts []string) string {
	full := strings.Join(parts, " ")

	if strings.Contains(full, "sql") || strings.Contains(full, "sqli") {
		return "SQL Injection"
	}
	if strings.Contains(full, "xss") {
		return "XSS Vulnerability"
	}
	if strings.Contains(full, "command") || strings.Contains(full, "exec") {
		return "Command Injection"
	}
	if strings.Contains(full, "secret") || strings.Contains(full, "api-key") {
		return "Hardcoded Secret"
	}
	if strings.Contains(full, "md5") || strings.Contains(full, "sha1") {
		return "Weak Cryptography"
	}
	if strings.Contains(full, "deserial") || strings.Contains(full, "pickle") {
		return "Insecure Deserialization"
	}
	if strings.Contains(full, "eval") {
		return "Dangerous Eval Usage"
	}
	if strings.Contains(full, "http") && strings.Contains(full, "plaintext") {
		return "Insecure HTTP Link"
	}
	if strings.Contains(full, "xxe") || strings.Contains(full, "doctype") {
		return "XXE Vulnerability"
	}
	if strings.Contains(full, "debug") {
		return "Debug Mode Enabled"
	}
	if strings.Contains(full, "template") {
		return "Template Vulnerability"
	}

	return ""
}

func mapSemgrepSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "error", "critical":
		return "critical"
	case "warning", "high":
		return "high"
	case "info", "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// detectWebFrameworks inspects package managers to find the framework stack and recommends Semgrep 'p/' configs
func detectWebFrameworks(targetDir string) []string {
	var configs []string

	// Check Go
	if _, err := os.Stat(filepath.Join(targetDir, "go.mod")); err == nil {
		configs = append(configs, "p/golang")

		content, _ := os.ReadFile(filepath.Join(targetDir, "go.mod"))
		text := string(content)
		if strings.Contains(text, "github.com/gin-gonic/gin") {
			configs = append(configs, "p/gin")
		}
		if strings.Contains(text, "github.com/dgrijalva/jwt-go") || strings.Contains(text, "github.com/golang-jwt/jwt") {
			configs = append(configs, "p/jwt")
		}
	}

	// Check Node.js/JS/TS
	if _, err := os.Stat(filepath.Join(targetDir, "package.json")); err == nil {
		content, _ := os.ReadFile(filepath.Join(targetDir, "package.json"))
		text := string(content)

		if strings.Contains(text, "react") {
			configs = append(configs, "p/react")
		}
		if strings.Contains(text, "express") {
			configs = append(configs, "p/express")
		}
		if strings.Contains(text, "jsonwebtoken") || strings.Contains(text, "jose") {
			configs = append(configs, "p/jwt")
		}
		if strings.Contains(text, "typescript") {
			configs = append(configs, "p/typescript")
		}
	}

	// Check Python
	if _, err := os.Stat(filepath.Join(targetDir, "requirements.txt")); err == nil {
		content, _ := os.ReadFile(filepath.Join(targetDir, "requirements.txt"))
		text := string(content)

		if strings.Contains(text, "Django") || strings.Contains(text, "django") {
			configs = append(configs, "p/django")
		}
		if strings.Contains(text, "Flask") || strings.Contains(text, "flask") {
			configs = append(configs, "p/flask")
		}
		if strings.Contains(text, "fastapi") {
			configs = append(configs, "p/fastapi")
		}
		if strings.Contains(text, "PyJWT") || strings.Contains(text, "python-jose") {
			configs = append(configs, "p/jwt")
		}
	}

	// Check Java
	if _, err := os.Stat(filepath.Join(targetDir, "pom.xml")); err == nil {
		content, _ := os.ReadFile(filepath.Join(targetDir, "pom.xml"))
		text := string(content)

		if strings.Contains(text, "spring-boot") || strings.Contains(text, "springframework") {
			configs = append(configs, "p/spring")
		}
	}

	return configs
}
