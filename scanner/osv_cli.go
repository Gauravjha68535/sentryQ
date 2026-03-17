package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
)

// getOSVBin returns the correct executable name based on OS
func getOSVBin() string {
	if runtime.GOOS == "windows" {
		return "osv-scanner.exe"
	}
	return "osv-scanner"
}

// CheckOSVCliInstalled checks if the osv-scanner binary is available in the system PATH
func CheckOSVCliInstalled() bool {
	_, err := exec.LookPath(getOSVBin())
	return err == nil
}

// OSVScannerResult represents the root JSON structure returned by the osv-scanner CLI
type OSVScannerResult struct {
	Results []OSVScannerResultItem `json:"results"`
}

// OSVScannerResultItem represents an individual target scan result
type OSVScannerResultItem struct {
	Source   map[string]interface{} `json:"source"`
	Packages []OSVScannerPackage    `json:"packages"`
}

// OSVScannerPackage represents a vulnerable package
type OSVScannerPackage struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		Version   string `json:"version"`
	} `json:"package"`
	Vulnerabilities []OSVCLIVulnerability `json:"vulnerabilities"`
}

// OSVCLIVulnerability represents the vulnerability object returned by the CLI
type OSVCLIVulnerability struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Details  string `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// mapOSVCLISeverity maps osv-scanner severity to our format
func mapOSVCLISeverity(severities []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) string {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			score := s.Score
			if score >= "9.0" {
				return "critical"
			} else if score >= "7.0" {
				return "high"
			} else if score >= "4.0" {
				return "medium"
			}
			return "low"
		}
	}
	return "medium"
}

// RunOSVCli runs the osv-scanner CLI against a target directory and returns findings.
func RunOSVCli(ctx context.Context, targetDir string) ([]reporter.Finding, error) {
	utils.LogInfo("🔍 Launching Google OSV-Scanner CLI...")

	cmd := exec.CommandContext(ctx, getOSVBin(), "scan", "--format", "json", "-r", targetDir)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Dir = targetDir

	analyzer := NewASTAnalyzer()

	// osv-scanner returns exit code 1 if vulnerabilities are found, so err is expected
	err := cmd.Run()

	// Extract just the JSON part, as osv-scanner might print warnings before it
	output := stdout.String()
	startIndex := strings.Index(output, "{")
	if startIndex != -1 {
		output = output[startIndex:]
	}

	var result OSVScannerResult
	if parseErr := json.Unmarshal([]byte(output), &result); parseErr != nil {
		utils.LogWarn(fmt.Sprintf("Failed to parse OSV-Scanner JSON output: %v", parseErr))
		if err != nil {
			utils.LogWarn(fmt.Sprintf("osv-scanner stderr: %s", stderr.String()))
		}
		return nil, fmt.Errorf("failed to parse osv-scanner output: %w", parseErr)
	}

	var findings []reporter.Finding
	srNo := 1

	for _, resItem := range result.Results {
		// Use the lockfile name as the source path if available
		filePath := targetDir
		if pathRaw, ok := resItem.Source["path"]; ok {
			if pathStr, ok := pathRaw.(string); ok {
				filePath = pathStr
			}
		}

		for _, pkg := range resItem.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				severity := mapOSVCLISeverity(vuln.Severity)

				fixedVersion := "latest"
				for _, affected := range vuln.Affected {
					if affected.Package.Ecosystem == pkg.Package.Ecosystem && affected.Package.Name == pkg.Package.Name {
						for _, r := range affected.Ranges {
							for _, event := range r.Events {
								if event.Fixed != "" {
									fixedVersion = event.Fixed
								}
							}
						}
					}
				}

				summary := vuln.Summary
				if summary == "" {
					summary = vuln.Details
				}
				// OSV CLI can return long details; truncate for the console report if necessary
				if len(summary) > 200 {
					summary = summary[:200] + "..."
				}

				description := fmt.Sprintf("Known vulnerability %s in %s@%s: %s",
					vuln.ID, pkg.Package.Name, pkg.Package.Version, summary)

				// Analyze Reachability via AST
				isReachable := analyzer.IsFunctionReachable(targetDir, pkg.Package.Name)

				issueName := fmt.Sprintf("SCA: %s in %s", vuln.ID, pkg.Package.Name)
				if !isReachable {
					issueName = "[UNREACHABLE] " + issueName
					severity = "low"
					description += "\n\nREACHABILITY: The AST Analyzer could not find any active invocations of this library in your codebase. It may be a false positive or an unused transitive dependency."
				} else {
					description += "\n\nREACHABILITY: Verified active usage of this library in the source code."
				}

				findings = append(findings, reporter.Finding{
					SrNo:        srNo,
					IssueName:   issueName,
					FilePath:    filePath,
					Description: description,
					Severity:    severity,
					LineNumber:  "N/A (Package Lockfile)", // CLI doesn't always provide line numbers
					AiValidated: "N/A (CVE Database)",
					Remediation: fmt.Sprintf("Upgrade %s to version %s or later", pkg.Package.Name, fixedVersion),
					RuleID:      fmt.Sprintf("sca-%s", strings.ToLower(vuln.ID)),
					Source:      "osv-scanner",
					CWE:         "CWE-1035",
					OWASP:       "A06:2021",
					Confidence:  1.0,
				})
				srNo++
			}
		}
	}

	utils.LogInfo(fmt.Sprintf("SCA complete: found %d known vulnerabilities using osv-scanner", len(findings)))
	return findings, nil
}
