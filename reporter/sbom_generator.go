package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CycloneDX 1.5 SBOM structures (JSON schema)

type CycloneDXSBOM struct {
	BOMFormat   string        `json:"bomFormat"`
	SpecVersion string        `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version     int           `json:"version"`
	Metadata    SBOMMetadata  `json:"metadata"`
	Components  []SBOMComponent `json:"components"`
	Vulnerabilities []SBOMVulnerability `json:"vulnerabilities,omitempty"`
}

type SBOMMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     []SBOMTool   `json:"tools"`
	Component SBOMComponent `json:"component"`
}

type SBOMTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type SBOMComponent struct {
	Type        string      `json:"type"`
	BOMRef      string      `json:"bom-ref,omitempty"`
	Name        string      `json:"name"`
	Version     string      `json:"version,omitempty"`
	PackageURL  string      `json:"purl,omitempty"`
	Description string      `json:"description,omitempty"`
	Licenses    []SBOMLicenseWrapper `json:"licenses,omitempty"`
	ExternalRefs []SBOMExternalRef   `json:"externalReferences,omitempty"`
}

type SBOMLicenseWrapper struct {
	License SBOMLicense `json:"license"`
}

type SBOMLicense struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type SBOMExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type SBOMVulnerability struct {
	BOMRef      string          `json:"bom-ref"`
	ID          string          `json:"id"`
	Source      SBOMVulnSource  `json:"source,omitempty"`
	Ratings     []SBOMRating    `json:"ratings,omitempty"`
	CWEs        []int           `json:"cwes,omitempty"`
	Description string          `json:"description"`
	Recommendation string       `json:"recommendation,omitempty"`
	Affects     []SBOMVulnAffect `json:"affects"`
}

type SBOMVulnSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type SBOMRating struct {
	Source   SBOMVulnSource `json:"source"`
	Score    float64        `json:"score,omitempty"`
	Severity string         `json:"severity"`
	Method   string         `json:"method,omitempty"`
}

type SBOMVulnAffect struct {
	Ref string `json:"ref"`
}

// GenerateSBOM produces a CycloneDX 1.5 SBOM JSON file from scan findings.
// Dependencies flagged by the dependency scanner appear as components;
// all findings appear as vulnerability entries.
func GenerateSBOM(filename string, findings []Finding, targetName string) error {
	sbom := CycloneDXSBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: SBOMMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []SBOMTool{
				{
					Vendor:  "SentryQ",
					Name:    "SentryQ",
					Version: Version,
				},
			},
			Component: SBOMComponent{
				Type:    "application",
				BOMRef:  "target",
				Name:    targetName,
				Version: "0.0.0",
			},
		},
	}

	// Extract unique dependency components from SCA findings
	seenComponents := map[string]bool{}
	for _, f := range findings {
		if !strings.Contains(strings.ToLower(f.Source), "dependency") &&
			!strings.Contains(strings.ToLower(f.Source), "sca") &&
			!strings.Contains(strings.ToLower(f.Source), "supply") {
			continue
		}
		compName := extractPackageName(f)
		if compName == "" || seenComponents[compName] {
			continue
		}
		seenComponents[compName] = true

		comp := SBOMComponent{
			Type:    "library",
			BOMRef:  "pkg-" + sanitizeBOMRef(compName),
			Name:    compName,
			Version: extractVersion(f),
		}
		if purl := buildPURL(f); purl != "" {
			comp.PackageURL = purl
		}
		sbom.Components = append(sbom.Components, comp)
	}

	// If no SCA components found, add a placeholder for the target itself
	if len(sbom.Components) == 0 {
		sbom.Components = []SBOMComponent{
			{
				Type:        "application",
				BOMRef:      "target-app",
				Name:        targetName,
				Description: "Scanned application",
			},
		}
	}

	// Map all findings as vulnerabilities
	for i, f := range findings {
		if f.Status == "false_positive" || f.Status == "ignored" {
			continue
		}

		vulnID := f.RuleID
		if vulnID == "" {
			vulnID = fmt.Sprintf("SENTRYQ-%04d", i+1)
		}

		vuln := SBOMVulnerability{
			BOMRef:         "vuln-" + sanitizeBOMRef(vulnID) + fmt.Sprintf("-%d", i),
			ID:             vulnID,
			Description:    f.Description,
			Recommendation: f.Remediation,
			Source: SBOMVulnSource{
				Name: "SentryQ",
			},
			Ratings: []SBOMRating{
				{
					Source:   SBOMVulnSource{Name: "SentryQ"},
					Severity: normalizeSBOMSeverity(f.Severity),
					Method:   "other",
				},
			},
			Affects: []SBOMVulnAffect{
				{Ref: "target"},
			},
		}

		if cweID := extractCWEInt(f.CWE); cweID > 0 {
			vuln.CWEs = []int{cweID}
		}

		sbom.Vulnerabilities = append(sbom.Vulnerabilities, vuln)
	}

	out, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return fmt.Errorf("sbom: marshal failed: %w", err)
	}
	if err := os.WriteFile(filename, out, 0644); err != nil {
		return fmt.Errorf("sbom: write failed: %w", err)
	}
	return nil
}

func normalizeSBOMSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func extractPackageName(f Finding) string {
	// Try to extract "package@version" from the issue name or description
	if strings.Contains(f.IssueName, "@") {
		parts := strings.SplitN(f.IssueName, "@", 2)
		return strings.TrimSpace(parts[0])
	}
	// Fall back to the rule ID prefix (e.g., "npm-lodash-prototype-pollution" → "lodash")
	return ""
}

func extractVersion(f Finding) string {
	if strings.Contains(f.IssueName, "@") {
		parts := strings.SplitN(f.IssueName, "@", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func buildPURL(f Finding) string {
	if !strings.Contains(f.IssueName, "@") {
		return ""
	}
	parts := strings.SplitN(f.IssueName, "@", 2)
	pkg := strings.TrimSpace(parts[0])
	ver := strings.TrimSpace(parts[1])

	// Detect ecosystem from file path or source
	ecosystem := "generic"
	lower := strings.ToLower(f.FilePath + f.Source)
	switch {
	case strings.Contains(lower, "package.json") || strings.Contains(lower, "npm"):
		ecosystem = "npm"
	case strings.Contains(lower, "requirements.txt") || strings.Contains(lower, "pypi"):
		ecosystem = "pypi"
	case strings.Contains(lower, "go.mod") || strings.Contains(lower, "golang"):
		ecosystem = "golang"
	case strings.Contains(lower, "pom.xml") || strings.Contains(lower, "maven"):
		ecosystem = "maven"
	case strings.Contains(lower, "gemfile") || strings.Contains(lower, "rubygems"):
		ecosystem = "gem"
	}

	return fmt.Sprintf("pkg:%s/%s@%s", ecosystem, pkg, ver)
}

func sanitizeBOMRef(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	return sb.String()
}

func extractCWEInt(cwe string) int {
	if cwe == "" {
		return 0
	}
	// "CWE-89: SQL Injection" → 89
	var n int
	if _, err := fmt.Sscanf(strings.TrimPrefix(strings.ToUpper(cwe), "CWE-"), "%d", &n); err == nil {
		return n
	}
	return 0
}
