package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// OSVResponse represents the OSV API response
type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVVulnerability represents a single vulnerability from OSV
type OSVVulnerability struct {
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

// Dependency represents a package dependency
type Dependency struct {
	Name       string
	Version    string
	Ecosystem  string
	SourceFile string
	LineNumber int
	Purl       string
	License    string
	Hash       string
}

// ScanDependencies scans for vulnerable dependencies using osv-scanner CLI if available,
// falling back to manual parsing and the OSV API if not.
func ScanDependencies(ctx context.Context, targetDir string) ([]reporter.Finding, error) {
	utils.LogInfo("Starting dependency vulnerability scan...")

	// 1. Try to use the official Google osv-scanner CLI first (Most Accurate)
	if CheckOSVCliInstalled() {
		return RunOSVCli(ctx, targetDir)
	}

	// 2. Fallback to our custom manual parser and the OSV HTTP API
	utils.LogWarn("osv-scanner CLI not found in PATH! Falling back to manual dependency scanning.")
	utils.LogWarn("For best results and lockfile support, install it: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2")
	return scanDependenciesFallback(ctx, targetDir)
}

// scanDependenciesFallback is the original manual dependency scanner
func scanDependenciesFallback(ctx context.Context, targetDir string) ([]reporter.Finding, error) {
	var findings []reporter.Finding
	srNo := 1

	// Collect dependencies from various package managers
	dependencies := collectDependencies(targetDir)
	utils.LogInfo(fmt.Sprintf("Found %d dependencies to scan (Manual Fallback)", len(dependencies)))

	// Query OSV API for each dependency
	analyzer := NewASTAnalyzer()

	for _, dep := range dependencies {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		vulns, err := queryOSV(ctx, dep)
		if err != nil {
			utils.LogWarn(fmt.Sprintf("Failed to query OSV for %s: %v", dep.Name, err))
			continue
		}

		for _, vuln := range vulns {
			severity := mapOSVSeverity(vuln.Severity)
			fixedVersion := getFixedVersion(vuln, dep.Ecosystem)

			summary := vuln.Summary
			if summary == "" {
				summary = vuln.Details
			}
			if len(summary) > 200 {
				summary = summary[:200] + "..."
			}

			description := fmt.Sprintf("Vulnerable dependency: %s@%s - %s", dep.Name, dep.Version, summary)

			// Reachability Analysis
			isReachable := analyzer.IsFunctionReachable(targetDir, dep.Name)
			issueName := fmt.Sprintf("CVE: %s - %s", vuln.ID, dep.Name)

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
				FilePath:    dep.SourceFile,
				Description: description,
				Severity:    severity,
				LineNumber:  fmt.Sprintf("%d", dep.LineNumber),
				AiValidated: "No",
				Remediation: fmt.Sprintf("Update %s to version %s or later. Details: %s", dep.Name, fixedVersion, vuln.Details),
				RuleID:      vuln.ID,
				Source:      "osv",
			})
			srNo++
		}
	}

	return findings, nil
}

func collectDependencies(targetDir string) []Dependency {
	var deps []Dependency

	// package.json (Node.js/npm)
	if data, err := os.ReadFile(filepath.Join(targetDir, "package.json")); err == nil {
		deps = append(deps, parsePackageJSON(data, filepath.Join(targetDir, "package.json"))...)
	}

	// requirements.txt (Python/PyPI)
	if data, err := os.ReadFile(filepath.Join(targetDir, "requirements.txt")); err == nil {
		deps = append(deps, parseRequirementsTXT(data, filepath.Join(targetDir, "requirements.txt"))...)
	}

	// go.mod (Go)
	if data, err := os.ReadFile(filepath.Join(targetDir, "go.mod")); err == nil {
		deps = append(deps, parseGoMod(data, filepath.Join(targetDir, "go.mod"))...)
	}

	// pom.xml (Java/Maven)
	if data, err := os.ReadFile(filepath.Join(targetDir, "pom.xml")); err == nil {
		deps = append(deps, parsePomXML(data, filepath.Join(targetDir, "pom.xml"))...)
	}

	// build.gradle (Java/Gradle)
	if data, err := os.ReadFile(filepath.Join(targetDir, "build.gradle")); err == nil {
		deps = append(deps, parseGradle(data, filepath.Join(targetDir, "build.gradle"))...)
	}

	// composer.json (PHP/Packagist)
	if data, err := os.ReadFile(filepath.Join(targetDir, "composer.json")); err == nil {
		deps = append(deps, parseComposerJSON(data, filepath.Join(targetDir, "composer.json"))...)
	}

	// Gemfile.lock (Ruby)
	if data, err := os.ReadFile(filepath.Join(targetDir, "Gemfile.lock")); err == nil {
		deps = append(deps, parseGemfileLock(data, filepath.Join(targetDir, "Gemfile.lock"))...)
	}

	// yarn.lock (Node.js/Yarn)
	if data, err := os.ReadFile(filepath.Join(targetDir, "yarn.lock")); err == nil {
		deps = append(deps, parseYarnLock(data, filepath.Join(targetDir, "yarn.lock"))...)
	}

	// pnpm-lock.yaml (Node.js/PNPM)
	if data, err := os.ReadFile(filepath.Join(targetDir, "pnpm-lock.yaml")); err == nil {
		deps = append(deps, parsePNPMLock(data, filepath.Join(targetDir, "pnpm-lock.yaml"))...)
	}

	return deps
}

// queryOSV queries the OSV API for vulnerabilities
func queryOSV(ctx context.Context, dep Dependency) ([]OSVVulnerability, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	request := map[string]interface{}{
		"package": map[string]string{
			"name":      dep.Name,
			"ecosystem": dep.Ecosystem,
		},
		"version": dep.Version,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/query", strings.NewReader(string(requestBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, err
	}

	return osvResp.Vulns, nil
}

// parsePackageJSON parses Node.js package.json
func parsePackageJSON(data []byte, sourceFile string) []Dependency {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	var deps []Dependency
	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{
			Name:       name,
			Version:    cleanVersion(version),
			Ecosystem:  "npm",
			SourceFile: sourceFile,
			LineNumber: 1,
		})
	}
	for name, version := range pkg.DevDependencies {
		deps = append(deps, Dependency{
			Name:       name,
			Version:    cleanVersion(version),
			Ecosystem:  "npm",
			SourceFile: sourceFile,
			LineNumber: 1,
		})
	}
	return deps
}

// parseRequirementsTXT parses Python requirements.txt
func parseRequirementsTXT(data []byte, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(utils.NormalizeNewlines(string(data)), "\n")

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Handle various formats: package==version, package>=version, package
		var name, version string
		if strings.Contains(line, "==") {
			parts := strings.Split(line, "==")
			name = strings.TrimSpace(parts[0])
			version = strings.TrimSpace(parts[1])
		} else if strings.Contains(line, ">=") {
			parts := strings.Split(line, ">=")
			name = strings.TrimSpace(parts[0])
			version = strings.TrimSpace(parts[1])
		} else if strings.Contains(line, "<=") {
			parts := strings.Split(line, "<=")
			name = strings.TrimSpace(parts[0])
			version = strings.TrimSpace(parts[1])
		} else {
			name = strings.TrimSpace(line)
			version = "latest"
		}

		if name != "" {
			deps = append(deps, Dependency{
				Name:       name,
				Version:    cleanVersion(version),
				Ecosystem:  "PyPI",
				SourceFile: sourceFile,
				LineNumber: lineNum + 1,
			})
		}
	}

	return deps
}

// parseGoMod parses Go go.mod
func parseGoMod(data []byte, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(utils.NormalizeNewlines(string(data)), "\n")
	inRequire := false

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}

		if inRequire || strings.HasPrefix(line, "require ") {
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				deps = append(deps, Dependency{
					Name:       parts[0],
					Version:    cleanVersion(parts[1]),
					Ecosystem:  "Go",
					SourceFile: sourceFile,
					LineNumber: lineNum + 1,
				})
			}
		}
	}

	return deps
}

// parsePomXML parses Java pom.xml using a more robust regex-based extraction
func parsePomXML(data []byte, sourceFile string) []Dependency {
	var deps []Dependency
	content := string(data)

	// Pattern for <dependency> blocks
	depBlockRe := regexp.MustCompile(`(?s)<dependency>(.*?)</dependency>`)
	groupRe := regexp.MustCompile(`<groupId>(.*?)</groupId>`)
	artifactRe := regexp.MustCompile(`<artifactId>(.*?)</artifactId>`)
	versionRe := regexp.MustCompile(`<version>(.*?)</version>`)

	blocks := depBlockRe.FindAllStringSubmatch(content, -1)
	for _, block := range blocks {
		inner := block[1]
		g := groupRe.FindStringSubmatch(inner)
		a := artifactRe.FindStringSubmatch(inner)
		v := versionRe.FindStringSubmatch(inner)

		if len(g) > 1 && len(a) > 1 {
			version := "latest"
			if len(v) > 1 {
				version = v[1]
			}
			deps = append(deps, Dependency{
				Name:       g[1] + ":" + a[1],
				Version:    cleanVersion(version),
				Ecosystem:  "Maven",
				SourceFile: sourceFile,
				LineNumber: 1, // Line number detection for XML is complex, defaulting to 1
			})
		}
	}

	return deps
}

// parseGradle parses build.gradle files
func parseGradle(data []byte, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(utils.NormalizeNewlines(string(data)), "\n")
	
	// Implementation of gradle dependency parsing: implementation 'group:artifact:version'
	re := regexp.MustCompile(`(?i)(?:implementation|runtimeOnly|compileOnly|api|testImplementation)\s+['"]([^'"]+:[^'"]+:[^'"]+)['"]`)
	
	for lineNum, line := range lines {
		match := re.FindStringSubmatch(line)
		if len(match) > 1 {
			parts := strings.Split(match[1], ":")
			if len(parts) >= 3 {
				deps = append(deps, Dependency{
					Name:       parts[0] + ":" + parts[1],
					Version:    cleanVersion(parts[2]),
					Ecosystem:  "Maven", // Gradle usually pulls from Maven Central
					SourceFile: sourceFile,
					LineNumber: lineNum + 1,
				})
			}
		}
	}
	return deps
}

// parseComposerJSON parses PHP composer.json
func parseComposerJSON(data []byte, sourceFile string) []Dependency {
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	var deps []Dependency
	for name, version := range pkg.Require {
		if name == "php" { continue }
		deps = append(deps, Dependency{
			Name:       name,
			Version:    cleanVersion(version),
			Ecosystem:  "Packagist",
			SourceFile: sourceFile,
			LineNumber: 1,
		})
	}
	for name, version := range pkg.RequireDev {
		deps = append(deps, Dependency{
			Name:       name,
			Version:    cleanVersion(version),
			Ecosystem:  "Packagist",
			SourceFile: sourceFile,
			LineNumber: 1,
		})
	}
	return deps
}

// parseYarnLock parses v1 yarn.lock files (simplified)
func parseYarnLock(data []byte, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(utils.NormalizeNewlines(string(data)), "\n")
	
	currentPkg := ""
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") { continue }
		
		if !strings.HasPrefix(line, " ") && strings.Contains(line, "@") {
			// Package definition: "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.8.3":
			currentPkg = strings.Split(trimmed, "@")[0]
			if strings.HasPrefix(currentPkg, "\"") {
				currentPkg = strings.Trim(currentPkg, "\"")
			}
		} else if strings.HasPrefix(trimmed, "version \"") && currentPkg != "" {
			version := strings.Trim(strings.TrimPrefix(trimmed, "version "), "\"")
			deps = append(deps, Dependency{
				Name:       currentPkg,
				Version:    version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
				LineNumber: lineNum + 1,
			})
			currentPkg = ""
		}
	}
	return deps
}

// parsePNPMLock parses pnpm-lock.yaml (simplified)
func parsePNPMLock(data []byte, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(utils.NormalizeNewlines(string(data)), "\n")
	
	// Simplified detection of: /package-name/version:
	re := regexp.MustCompile(`^\s+\/([^/]+)\/([^:]+):`)
	
	for lineNum, line := range lines {
		match := re.FindStringSubmatch(line)
		if len(match) > 2 {
			deps = append(deps, Dependency{
				Name:       match[1],
				Version:    match[2],
				Ecosystem:  "npm",
				SourceFile: sourceFile,
				LineNumber: lineNum + 1,
			})
		}
	}
	return deps
}

// parseGemfileLock parses Ruby Gemfile.lock
func parseGemfileLock(data []byte, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(utils.NormalizeNewlines(string(data)), "\n")
	inSpecs := false

	for lineNum, line := range lines {
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) >= 2 {
				deps = append(deps, Dependency{
					Name:       parts[0],
					Version:    cleanVersion(parts[1]),
					Ecosystem:  "RubyGems",
					SourceFile: sourceFile,
					LineNumber: lineNum + 1,
				})
			}
		}
	}

	return deps
}

// cleanVersion cleans version strings
func cleanVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimSuffix(v, ",")
	return strings.TrimSpace(v)
}

// mapOSVSeverity maps OSV severity to our format
func mapOSVSeverity(severities []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) string {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			score, err := strconv.ParseFloat(s.Score, 64)
			if err != nil {
				continue
			}
			if score >= 9.0 {
				return "critical"
			} else if score >= 7.0 {
				return "high"
			} else if score >= 4.0 {
				return "medium"
			}
			return "low"
		}
	}
	return "medium"
}

// getFixedVersion extracts the fixed version from OSV response
func getFixedVersion(vuln OSVVulnerability, ecosystem string) string {
	for _, affected := range vuln.Affected {
		if affected.Package.Ecosystem == ecosystem {
			for _, r := range affected.Ranges {
				for _, event := range r.Events {
					if event.Fixed != "" {
						return event.Fixed
					}
				}
			}
		}
	}
	return "latest"
}
