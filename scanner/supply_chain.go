package scanner

import (
	"context"
	"fmt"
	"strings"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// SupplyChainScanner performs supply chain security analysis
type SupplyChainScanner struct {
	dependencies []Dependency
}

// NewSupplyChainScanner creates a new supply chain scanner
func NewSupplyChainScanner() *SupplyChainScanner {
	return &SupplyChainScanner{
		dependencies: make([]Dependency, 0),
	}
}

// ScanSupplyChain performs comprehensive supply chain security analysis
func (scs *SupplyChainScanner) ScanSupplyChain(ctx context.Context, targetDir string) ([]reporter.Finding, error) {
	var findings []reporter.Finding

	utils.LogInfo("Starting supply chain security analysis...")

	// Collect all dependencies
	scs.dependencies = scs.collectAllDependencies(targetDir)
	utils.LogInfo(fmt.Sprintf("Found %d dependencies", len(scs.dependencies)))

	// Check for vulnerabilities
	vulnFindings := scs.checkDependencyVulnerabilities(ctx)
	findings = append(findings, vulnFindings...)

	// Check for typosquatting
	typoFindings := scs.checkTyposquatting()
	findings = append(findings, typoFindings...)

	// Check for outdated dependencies
	outdatedFindings := scs.checkOutdatedDependencies()
	findings = append(findings, outdatedFindings...)

	return findings, nil
}



func (scs *SupplyChainScanner) collectAllDependencies(targetDir string) []Dependency {
	// Re-enable manual parsing to feed our Typosquatting engine
	return collectDependencies(targetDir)
}


func (scs *SupplyChainScanner) checkDependencyVulnerabilities(ctx context.Context) []reporter.Finding {
	var findings []reporter.Finding
	srNo := 1

	// Check against OSV database
	for _, dep := range scs.dependencies {
		vulns, err := queryOSV(ctx, dep)
		if err != nil {
			continue
		}

		for _, vuln := range vulns {
			findings = append(findings, reporter.Finding{
				SrNo:        srNo,
				IssueName:   fmt.Sprintf("CVE: %s - %s", vuln.ID, dep.Name),
				FilePath:    dep.SourceFile,
				Description: fmt.Sprintf("Vulnerable dependency: %s@%s - %s", dep.Name, dep.Version, vuln.Summary),
				Severity:    mapOSVSeverity(vuln.Severity),
				LineNumber:  "1",
				AiValidated: "No",
				Remediation: fmt.Sprintf("Update %s to version %s or later", dep.Name, getFixedVersion(vuln, dep.Ecosystem)),
				RuleID:      vuln.ID,
				Source:      "supply-chain",
			})
			srNo++
		}
	}

	return findings
}

func (scs *SupplyChainScanner) checkTyposquatting() []reporter.Finding {
	var findings []reporter.Finding
	srNo := 1

	// Known highly-targeted packages for Typosquatting
	topPackages := []string{
		"requests", "numpy", "pandas", "lodash", "express", "react", "axios",
		"moment", "webpack", "babel", "django", "flask", "spring", "urllib3",
		"beautifulsoup4", "boto3", "cors", "body-parser", "async", "chalk",
		"react-dom", "mongoose", "typescript", "eslint", "prettier", "jest",
	}

	for _, dep := range scs.dependencies {
		depName := strings.ToLower(dep.Name)

		for _, legitimate := range topPackages {
			// Don't flag exact matches
			if depName == legitimate {
				continue
			}

			// If length difference is too large, skip expensive check
			if len(depName) > len(legitimate)+2 || len(legitimate) > len(depName)+2 {
				continue
			}

			distance := computeLevenshteinDistance(depName, legitimate)

			// If distance is exactly 1 (e.g. react vs reacct, lodash vs l0dash)
			// OR distance is 2 but lengths are > 6, it's highly suspicious
			suspicious := distance == 1 || (distance == 2 && len(legitimate) > 6)

			// Fast-pass for known good prefixes that naturally look similar
			// e.g. react-dom vs react
			if strings.HasPrefix(depName, legitimate+"-") || strings.HasPrefix(legitimate, depName+"-") {
				suspicious = false
			}

			if suspicious {
				findings = append(findings, reporter.Finding{
					SrNo:        srNo,
					IssueName:   "Typosquatting Detected",
					FilePath:    dep.SourceFile,
					Description: fmt.Sprintf("Potential typosquatting package: %s (Levenshtein distance to '%s' is %d)", dep.Name, legitimate, distance),
					Severity:    "critical",
					LineNumber:  fmt.Sprintf("%d", dep.LineNumber),
					AiValidated: "No",
					Remediation: fmt.Sprintf("Verify if '%s' is intentional. If malicious, replace with '%s' immediately.", dep.Name, legitimate),
					RuleID:      "typosquatting-" + legitimate,
					Source:      "supply-chain",
				})
				srNo++
			}
		}
	}

	return findings
}

func (scs *SupplyChainScanner) checkOutdatedDependencies() []reporter.Finding {
	// Disabled to prevent naive version checks from producing unverified false positives.
	// Will be revisited with proper package manager API integration.
	return []reporter.Finding{}
}

// computeLevenshteinDistance calculates the minimum number of single-character edits to change word1 into word2
func computeLevenshteinDistance(s1, s2 string) int { // Using built-in Go 1.21+ min/max functions instead of custom ones.
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Create a 2D slice
	d := make([][]int, len(s1)+1)
	for i := range d {
		d[i] = make([]int, len(s2)+1)
	}

	for i := 0; i <= len(s1); i++ {
		d[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		d[0][j] = j
	}

	for j := 1; j <= len(s2); j++ {
		for i := 1; i <= len(s1); i++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			// Min of deletion, insertion, substitution
			d[i][j] = min(d[i-1][j]+1, min(d[i][j-1]+1, d[i-1][j-1]+cost))
		}
	}

	return d[len(s1)][len(s2)]
}
