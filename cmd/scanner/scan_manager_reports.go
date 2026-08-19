package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// webGenerateReportFiles creates HTML, CSV, PDF, SARIF, SBOM, and compliance reports.
func webGenerateReportFiles(scanID string, findings []reporter.Finding, targetDir string, cfg WebScanConfig) {
	reportsDir := filepath.Join(os.TempDir(), "sentryQ", scanID)
	if err := os.MkdirAll(reportsDir, 0700); err != nil {
		utils.LogError(fmt.Sprintf("Failed to create reports directory for scan %s", scanID), err)
		return
	}

	summary := reporter.GenerateReportSummary(findings, targetDir)

	// CSV
	csvPath := filepath.Join(reportsDir, "report.csv")
	if err := reporter.WriteCSV(csvPath, findings); err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to write CSV report for scan %s: %v", scanID, err))
	}

	// HTML
	htmlPath := filepath.Join(reportsDir, "report.html")
	if err := reporter.GenerateHTMLReport(htmlPath, findings, summary); err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to write HTML report for scan %s: %v", scanID, err))
	}

	// PDF
	pdfPath := filepath.Join(reportsDir, "report.pdf")
	riskScore := reporter.CalculateRiskScore(findings)
	if err := reporter.GeneratePDF(pdfPath, findings, summary, riskScore); err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to write PDF report for scan %s: %v", scanID, err))
	}

	// SARIF
	sarifPath := filepath.Join(reportsDir, "report.sarif")
	if err := reporter.GenerateSARIF(sarifPath, findings); err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to write SARIF report for scan %s: %v", scanID, err))
	}

	// CycloneDX SBOM — generated for every scan (used in ReportViewer download)
	sbomPath := filepath.Join(reportsDir, "sbom.cdx.json")
	if err := reporter.GenerateSBOM(sbomPath, findings, filepath.Base(targetDir)); err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to write SBOM for scan %s: %v", scanID, err))
	}

	// Compliance reports — OWASP Top 10 JSON + HTML, PCI DSS JSON
	owaspJSONPath := filepath.Join(reportsDir, "compliance-owasp.json")
	owaspReport, owaspErr := reporter.GenerateComplianceReport(owaspJSONPath, scanID, findings, reporter.FrameworkOWASP10)
	if owaspErr != nil {
		utils.LogWarn(fmt.Sprintf("Failed to write OWASP compliance report for scan %s: %v", scanID, owaspErr))
	} else {
		owaspHTMLPath := filepath.Join(reportsDir, "compliance-owasp.html")
		if err := reporter.GenerateComplianceHTML(owaspHTMLPath, scanID, owaspReport); err != nil {
			utils.LogWarn(fmt.Sprintf("Failed to write OWASP compliance HTML for scan %s: %v", scanID, err))
		}
	}

	pciJSONPath := filepath.Join(reportsDir, "compliance-pci.json")
	if _, err := reporter.GenerateComplianceReport(pciJSONPath, scanID, findings, reporter.FrameworkPCIDSS); err != nil {
		utils.LogWarn(fmt.Sprintf("Failed to write PCI DSS compliance report for scan %s: %v", scanID, err))
	}

	utils.LogInfo(fmt.Sprintf("Reports saved for scan %s at %s", scanID, reportsDir))
}

// mergeTwoFindings merges f into best, keeping the most informative fields.
func mergeTwoFindings(best *reporter.Finding, f reporter.Finding, severityWeight map[string]int, sources map[string]bool) {
	w := severityWeight[strings.ToLower(f.Severity)]
	bw := severityWeight[strings.ToLower(best.Severity)]
	if w > bw {
		best.Severity = f.Severity
		best.IssueName = f.IssueName
		best.Description = f.Description
		best.Remediation = f.Remediation
		best.CWE = f.CWE
		best.OWASP = f.OWASP
	} else if w == bw && len(f.Description) > len(best.Description) {
		best.Description = f.Description
		best.IssueName = f.IssueName
		if f.Remediation != "" {
			best.Remediation = f.Remediation
		}
	}
	if f.Source != "" {
		sources[f.Source] = true
	}
	if f.AiValidated == "Yes" {
		best.AiValidated = "Yes"
	}
	if f.Confidence > best.Confidence {
		best.Confidence = f.Confidence
	}
	if best.RuleID == "" && f.RuleID != "" {
		best.RuleID = f.RuleID
	}
	if best.VulnerablePattern == "" && f.VulnerablePattern != "" {
		best.VulnerablePattern = f.VulnerablePattern
	}
	if best.ExploitPoC == "" || best.ExploitPoC == "N/A" {
		if f.ExploitPoC != "" && f.ExploitPoC != "N/A" {
			best.ExploitPoC = f.ExploitPoC
		}
	}
	if best.FixedCode == "" && f.FixedCode != "" {
		best.FixedCode = f.FixedCode
	}
	// Preserve AiReasoning: keep the longer / more detailed explanation
	if len(f.AiReasoning) > len(best.AiReasoning) {
		best.AiReasoning = f.AiReasoning
	}
	// Preserve ExploitPath if the best doesn't have one
	if len(best.ExploitPath) == 0 && len(f.ExploitPath) > 0 {
		best.ExploitPath = f.ExploitPath
	}
}

// webDeduplicateFindings removes duplicate findings using two-pass deduplication:
//
//	Pass 1 — Exact-line dedup: findings at the exact same file+line are always merged
//	          regardless of vulnerability family (catches cross-engine same-line matches).
//
//	Pass 2 — Proximity clustering: within each file+vulnFamily group, cluster findings
//	          within ±15 lines (±0 for secrets) and keep the best per cluster.
func webDeduplicateFindings(findings []reporter.Finding) []reporter.Finding {
	severityWeight := map[string]int{
		"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
	}

	// ── Pass 1: Exact file+line deduplication ────────────────────────────────
	// Two findings at the identical file+line are always the same issue regardless
	// of how different engines label the vulnerability type.
	type exactKey struct {
		filePath string
		line     int
	}
	exactBest := make(map[exactKey]int) // key → index in pass1 slice
	var pass1 []reporter.Finding

	for _, f := range findings {
		line := utils.ParseStartLine(f.LineNumber)
		// Findings with no parseable line number (e.g. "N/A (Package Lockfile)" from
		// OSV/SCA) must never be grouped under line:0, which would incorrectly merge
		// distinct vulnerabilities from different packages into a single finding.
		if line <= 0 {
			pass1 = append(pass1, f)
			continue
		}
		key := exactKey{filePath: f.FilePath, line: line}
		if existIdx, seen := exactBest[key]; seen {
			sources := map[string]bool{}
			for _, s := range strings.Split(pass1[existIdx].Source, ", ") {
				if s != "" {
					sources[s] = true
				}
			}
			mergeTwoFindings(&pass1[existIdx], f, severityWeight, sources)
			var sl []string
			for s := range sources {
				sl = append(sl, s)
			}
			sort.Strings(sl)
			pass1[existIdx].Source = strings.Join(sl, ", ")
		} else {
			exactBest[key] = len(pass1)
			pass1 = append(pass1, f)
		}
	}

	// ── Pass 2: Proximity clustering within file+vulnFamily ──────────────────
	type groupKey struct {
		filePath string
		vulnType string
	}
	grouped := make(map[groupKey][]reporter.Finding)
	for _, f := range pass1 {
		vtype := normalizeVulnType(f)
		key := groupKey{filePath: f.FilePath, vulnType: vtype}
		grouped[key] = append(grouped[key], f)
	}

	var unique []reporter.Finding
	for key, group := range grouped {
		if len(group) == 1 {
			unique = append(unique, group[0])
			continue
		}

		sort.Slice(group, func(i, j int) bool {
			return utils.ParseStartLine(group[i].LineNumber) < utils.ParseStartLine(group[j].LineNumber)
		})

		// Proximity threshold: 0 for secrets (exact only), 15 for everything else
		prox := 15
		upperVuln := strings.ToUpper(key.vulnType)
		if strings.Contains(upperVuln, "SECRET") || strings.Contains(upperVuln, "CREDENTIAL") || strings.Contains(upperVuln, "HARDCODED") {
			prox = 0
		}

		clusters := [][]reporter.Finding{{group[0]}}
		for _, f := range group[1:] {
			lastCluster := &clusters[len(clusters)-1]
			lastLine := utils.ParseStartLine((*lastCluster)[len(*lastCluster)-1].LineNumber)
			thisLine := utils.ParseStartLine(f.LineNumber)
			if thisLine-lastLine <= prox {
				*lastCluster = append(*lastCluster, f)
			} else {
				clusters = append(clusters, []reporter.Finding{f})
			}
		}

		for _, cluster := range clusters {
			best := cluster[0]
			sources := make(map[string]bool)
			for _, s := range strings.Split(best.Source, ", ") {
				if s != "" {
					sources[s] = true
				}
			}
			for _, f := range cluster[1:] {
				mergeTwoFindings(&best, f, severityWeight, sources)
			}
			var sourceList []string
			for s := range sources {
				sourceList = append(sourceList, s)
			}
			sort.Strings(sourceList)
			best.Source = strings.Join(sourceList, ", ")
			unique = append(unique, best)
		}
	}

	return unique
}

// normalizeVulnType extracts a canonical vulnerability FAMILY from a finding for dedup grouping.
// Maps related CWEs to the same family so AI/Semgrep/Rules findings merge properly.
func normalizeVulnType(f reporter.Finding) string {
	// CWE family mapping: related CWEs → single canonical type
	cweFamilies := map[string]string{
		"CWE-89": "SQLI", "CWE-564": "SQLI",
		"CWE-78": "CMDI", "CWE-77": "CMDI",
		"CWE-79": "XSS",
		"CWE-22": "PATH_TRAVERSAL", "CWE-23": "PATH_TRAVERSAL", "CWE-36": "PATH_TRAVERSAL",
		"CWE-502": "DESERIALIZATION",
		"CWE-798": "HARDCODED_SECRET", "CWE-259": "HARDCODED_SECRET", "CWE-321": "HARDCODED_SECRET",
		"CWE-330": "WEAK_RANDOM", "CWE-331": "WEAK_RANDOM", "CWE-338": "WEAK_RANDOM",
		"CWE-918":  "SSRF",
		"CWE-1336": "TEMPLATE_INJECTION", "CWE-94": "TEMPLATE_INJECTION", "CWE-95": "TEMPLATE_INJECTION",
		"CWE-943":  "NOSQL_INJECTION",
		"CWE-915":  "MASS_ASSIGNMENT",
		"CWE-611":  "XXE",
		"CWE-352":  "CSRF",
		"CWE-98":   "FILE_INCLUSION",
		"CWE-770":  "RESOURCE_LIMIT",
		"CWE-1321": "PROTOTYPE_POLLUTION",
		"CWE-20":   "INPUT_VALIDATION",
	}

	// Try CWE family lookup first
	cwe := strings.ToUpper(strings.TrimSpace(f.CWE))
	if cwe != "" {
		// Handle formats like "CWE-79", "CWE 79", or just "79"
		if !strings.HasPrefix(cwe, "CWE-") {
			cwe = "CWE-" + strings.TrimPrefix(cwe, "CWE ")
		}
		if family, ok := cweFamilies[cwe]; ok {
			return family
		}
		// Unknown CWE — use it directly
		if strings.HasPrefix(cwe, "CWE-") {
			return cwe
		}
	}

	// Keyword-based grouping from RuleID and IssueName
	combined := strings.ToLower(f.RuleID + " " + f.IssueName + " " + f.Description)
	combined = strings.ReplaceAll(combined, "-", " ")
	combined = strings.ReplaceAll(combined, "_", " ")

	// Ordered by specificity (more specific matches first)
	keywordFamilies := []struct {
		keywords []string
		family   string
	}{
		{[]string{"nosql injection", "nosql"}, "NOSQL_INJECTION"},
		{[]string{"sql injection", "sqli", "sql query"}, "SQLI"},
		{[]string{"command injection", "cmdi", "os.system", "runtime.exec", "subprocess"}, "CMDI"},
		{[]string{"ssti", "server side template", "template injection", "render_template_string"}, "TEMPLATE_INJECTION"},
		{[]string{"xss", "cross site scripting", "reflected xss", "stored xss"}, "XSS"},
		{[]string{"path traversal", "directory traversal", "sendfile", "path join"}, "PATH_TRAVERSAL"},
		{[]string{"ssrf", "server side request"}, "SSRF"},
		{[]string{"deserialization", "pickle", "unserialize", "readobject", "objectinputstream"}, "DESERIALIZATION"},
		{[]string{"hardcoded secret", "hardcoded password", "hardcoded credential", "secret detected", "api key detected"}, "HARDCODED_SECRET"},
		{[]string{"weak random", "math.random", "predictable random", "insufficient entropy", "token generation"}, "WEAK_RANDOM"},
		{[]string{"prototype pollution"}, "PROTOTYPE_POLLUTION"},
		{[]string{"file inclusion", "lfi", "rfi"}, "FILE_INCLUSION"},
		{[]string{"xxe", "xml external"}, "XXE"},
		{[]string{"csrf", "cross site request"}, "CSRF"},
		{[]string{"idor", "insecure direct object"}, "IDOR"},
		{[]string{"mass assignment"}, "MASS_ASSIGNMENT"},
		{[]string{"cookie", "set-cookie", "samesite", "httponly", "secure flag"}, "COOKIE_SECURITY"},
		{[]string{"cors", "cross origin", "cross-origin", "access-control"}, "CORS_MISCONFIG"},
		{[]string{"cache", "cache-control", "pragma"}, "CACHE_MISCONFIG"},
		{[]string{"header", "hsts", "x-frame-options", "content-type-options", "security header"}, "INSECURE_HEADER"},
	}

	for _, kf := range keywordFamilies {
		for _, kw := range kf.keywords {
			if strings.Contains(combined, kw) {
				return kf.family
			}
		}
	}

	// Last resort: use ruleID or issue name
	if f.RuleID != "" {
		return "RULE:" + f.RuleID
	}
	return "GENERIC:" + strings.ToLower(f.IssueName)
}

