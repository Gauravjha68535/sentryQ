package scanner

import (
	"bytes"
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

	// Query OSV API using batched requests to minimise round-trips.
	// Fall back to individual queries for any batch that fails.
	analyzer := NewASTAnalyzer()

	processDep := func(dep Dependency, vulns []OSVVulnerability) {
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

			isReachable := analyzer.IsFunctionReachable(targetDir, dep.Name)
			issueName := fmt.Sprintf("CVE: %s - %s", vuln.ID, dep.Name)

			if !isReachable {
				issueName = "[UNREACHABLE] " + issueName
				severity = "low"
				description += "\n\nREACHABILITY: The AST Analyzer could not find any active invocations of this library in your codebase. It may be a false positive or an unused transitive dependency."
			} else {
				description += "\n\nREACHABILITY: Verified active usage of this library in the source code."
			}

			rem := fmt.Sprintf("Update %s to version %s or later. Details: %s", dep.Name, fixedVersion, vuln.Details)
			if fixedVersion == "unknown" {
				rem = fmt.Sprintf("No fixed version available for %s yet. Monitor the advisory for updates. Details: %s", dep.Name, vuln.Details)
			}

			findings = append(findings, reporter.Finding{
				SrNo:        srNo,
				IssueName:   issueName,
				FilePath:    dep.SourceFile,
				Description: description,
				Severity:    severity,
				LineNumber:  fmt.Sprintf("%d", dep.LineNumber),
				AiValidated: "No",
				Remediation: rem,
				RuleID:      vuln.ID,
				Source:      "osv",
			})
			srNo++
		}
	}

	for batchStart := 0; batchStart < len(dependencies); batchStart += osvBatchSize {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		end := batchStart + osvBatchSize
		if end > len(dependencies) {
			end = len(dependencies)
		}
		batch := dependencies[batchStart:end]

		batchVulns, err := queryOSVBatch(ctx, batch)
		if err != nil {
			// Batch failed — fall back to individual queries for this slice.
			utils.LogWarn(fmt.Sprintf("OSV batch query failed (%v), falling back to individual queries for %d deps", err, len(batch)))
			for _, dep := range batch {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				vulns, qErr := queryOSV(ctx, dep)
				if qErr != nil {
					utils.LogWarn(fmt.Sprintf("Failed to query OSV for %s: %v", dep.Name, qErr))
					continue
				}
				processDep(dep, vulns)
			}
			continue
		}

		for i, dep := range batch {
			if i >= len(batchVulns) {
				// API returned fewer results than we sent — process remaining deps as having no vulns.
				break
			}
			processDep(dep, batchVulns[i])
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

// osvHTTPClient is shared across all OSV calls to reuse TCP connections.
var osvHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	},
}

// osvBatchSize is the maximum number of packages sent in a single /v1/querybatch call.
// The OSV API does not publish a hard cap; 100 is a safe conservative batch size.
const osvBatchSize = 100

// osvBatchResponse is the envelope returned by the OSV /v1/querybatch endpoint.
type osvBatchResponse struct {
	Results []struct {
		Vulns []OSVVulnerability `json:"vulns"`
	} `json:"results"`
}

// queryOSVBatch queries the OSV /v1/querybatch endpoint for multiple packages in
// one HTTP round-trip, returning a slice of vulnerability lists that aligns
// 1-to-1 with the input deps slice.  Falls back to empty results on any error
// so the caller can gracefully degrade to individual queryOSV calls.
func queryOSVBatch(ctx context.Context, deps []Dependency) ([][]OSVVulnerability, error) {
	type pkgQuery struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	type batchReq struct {
		Queries []pkgQuery `json:"queries"`
	}

	req := batchReq{Queries: make([]pkgQuery, len(deps))}
	for i, d := range deps {
		req.Queries[i].Package.Name = d.Name
		req.Queries[i].Package.Ecosystem = d.Ecosystem
		req.Queries[i].Version = d.Version
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.osv.dev/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := osvHTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV batch API returned status %d", resp.StatusCode)
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, err
	}

	out := make([][]OSVVulnerability, len(deps))
	for i, r := range batchResp.Results {
		if i >= len(out) {
			break
		}
		out[i] = r.Vulns
	}
	return out, nil
}

// queryOSV queries the OSV API for vulnerabilities, with exponential backoff on 429/5xx.
func queryOSV(ctx context.Context, dep Dependency) ([]OSVVulnerability, error) {
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

	const maxRetries = 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/query", strings.NewReader(string(requestBody)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := osvHTTPClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			resp.Body.Close()
			if attempt == maxRetries {
				return nil, fmt.Errorf("OSV API returned status %d after %d retries", resp.StatusCode, maxRetries)
			}
			// Exponential backoff: 1s, 2s, 4s ± up to 500ms jitter
			backoff := time.Duration(1<<uint(attempt))*time.Second +
				time.Duration(time.Now().UnixNano()%int64(500*time.Millisecond))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
		}

		var osvResp OSVResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&osvResp)
		resp.Body.Close() // close immediately — not deferred so it doesn't accumulate in retry loops
		if decodeErr != nil {
			return nil, decodeErr
		}
		return osvResp.Vulns, nil
	}

	return nil, fmt.Errorf("OSV API: exceeded retry limit for %s", dep.Name)
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
	return "unknown"
}
