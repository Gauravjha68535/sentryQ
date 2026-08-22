package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// GenerateSBOM writes a CycloneDX-format SBOM JSON file derived from scan findings.
// The SBOM surfaces all unique third-party components referenced in dependency findings.
func GenerateSBOM(filename string, findings []Finding, projectName string) error {
	type hash struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	}
	type component struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		PURL    string `json:"purl,omitempty"`
	}
	type vuln struct {
		ID          string `json:"id"`
		Description string `json:"description,omitempty"`
		Severity    string `json:"severity,omitempty"`
	}
	type sbom struct {
		BOMFormat   string      `json:"bomFormat"`
		SpecVersion string      `json:"specVersion"`
		Version     int         `json:"version"`
		SerialNumber string     `json:"serialNumber"`
		Metadata    interface{} `json:"metadata"`
		Components  []component `json:"components"`
		Vulnerabilities []vuln  `json:"vulnerabilities,omitempty"`
	}

	// Deduplicate components by package name
	seen := make(map[string]bool)
	var components []component
	var vulns []vuln

	for _, f := range findings {
		if f.Status == "false_positive" || f.Status == "ignored" {
			continue
		}

		// Extract component name from finding (dependency scanner puts pkg name in IssueName or VulnerablePattern)
		pkgName := extractPackageName(f)
		if pkgName == "" {
			continue
		}

		if !seen[pkgName] {
			seen[pkgName] = true
			comp := component{
				Type: "library",
				Name: pkgName,
			}
			if f.VulnerablePattern != "" {
				comp.Version = extractVersion(f.VulnerablePattern)
			}
			if eco := extractEcosystem(f); eco != "" {
				if comp.Version != "" {
					comp.PURL = fmt.Sprintf("pkg:%s/%s@%s", eco, pkgName, comp.Version)
				} else {
					comp.PURL = fmt.Sprintf("pkg:%s/%s", eco, pkgName)
				}
			}
			components = append(components, comp)
		}

		// Add vulnerability if CVE-like
		if f.CWE != "" || strings.Contains(strings.ToUpper(f.IssueName), "CVE") {
			vulnID := f.RuleID
			if vulnID == "" {
				vulnID = f.CWE
			}
			if vulnID != "" {
				vulns = append(vulns, vuln{
					ID:          vulnID,
					Description: f.Description,
					Severity:    f.Severity,
				})
			}
		}
	}

	doc := sbom{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		Version:      1,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Metadata: map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"component": map[string]string{
				"type": "application",
				"name": projectName,
			},
		},
		Components:      components,
		Vulnerabilities: vulns,
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("sbom: marshal failed: %w", err)
	}
	return os.WriteFile(filename, data, 0600)
}

// extractEcosystem infers the CycloneDX/PURL ecosystem type from finding metadata.
func extractEcosystem(f Finding) string {
	src := strings.ToLower(f.Source + " " + f.RuleID + " " + f.IssueName)
	switch {
	case strings.Contains(src, "npm") || strings.Contains(src, "node") || strings.Contains(src, "yarn"):
		return "npm"
	case strings.Contains(src, "pypi") || strings.Contains(src, "pip") || strings.Contains(src, "python"):
		return "pypi"
	case strings.Contains(src, "golang") || strings.Contains(src, "go-module") || strings.Contains(src, "go mod"):
		return "golang"
	case strings.Contains(src, "maven") || strings.Contains(src, "gradle") || strings.Contains(src, "java"):
		return "maven"
	case strings.Contains(src, "rubygem") || strings.Contains(src, "bundler") || strings.Contains(src, "gem"):
		return "gem"
	case strings.Contains(src, "cargo") || strings.Contains(src, "rust") || strings.Contains(src, "crate"):
		return "cargo"
	case strings.Contains(src, "nuget") || strings.Contains(src, "dotnet") || strings.Contains(src, "csharp"):
		return "nuget"
	case strings.Contains(src, "composer") || strings.Contains(src, "php"):
		return "composer"
	}
	return ""
}

// extractPackageName tries to get a meaningful package name from a finding.
func extractPackageName(f Finding) string {
	// Dependency scanner findings often encode package in IssueName like "vuln-pkg-name"
	if strings.Contains(f.Source, "dependency") || strings.Contains(f.Source, "osv") || strings.Contains(f.Source, "supply") {
		if f.VulnerablePattern != "" {
			parts := strings.Fields(f.VulnerablePattern)
			if len(parts) > 0 {
				return parts[0]
			}
		}
		return f.IssueName
	}
	return ""
}

// extractVersion tries to extract a version string from a pattern like "pkg@1.2.3" or "pkg 1.2.3".
func extractVersion(pattern string) string {
	if idx := strings.Index(pattern, "@"); idx >= 0 {
		return pattern[idx+1:]
	}
	parts := strings.Fields(pattern)
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}
