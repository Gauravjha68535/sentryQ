package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"QWEN_SCR_24_FEB_2026/ai"
	"QWEN_SCR_24_FEB_2026/config"
	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/scanner"
	"QWEN_SCR_24_FEB_2026/utils"

	"github.com/google/uuid"
)

// WebScanConfig mirrors the frontend config toggles
// Simplified to 2 modes:
// - EnableDeepScan: deps + semgrep + supply chain + compliance + threat intel
// - EnableAI: AI validation + AI discovery + consolidated merge
// Secret detection, pattern scan, AST, and taint analysis run ALWAYS.
type WebScanConfig struct {
	EnableDeepScan          bool   `json:"enableDeepScan"`
	EnableAI                bool   `json:"enableAI"`
	AIModel                 string `json:"aiModel"`
	OllamaHost              string `json:"ollamaHost"`
	ConsolidationModel      string `json:"consolidationModel"`
	ConsolidationOllamaHost string `json:"consolidationOllamaHost"`
	EnableMLFPReduction     bool   `json:"enableMLFPReduction"`
	CustomRulesDir          string `json:"customRulesDir"`
}

// StartScanFromUpload handles uploaded files
func StartScanFromUpload(targetDir string, configJSON string) (string, error) {
	scanID := uuid.New().String()[:8]
	var webCfg WebScanConfig
	json.Unmarshal([]byte(configJSON), &webCfg)

	displayName := filepath.Base(targetDir)

	if err := CreateScan(scanID, displayName, "upload", configJSON); err != nil {
		return "", fmt.Errorf("failed to create scan record: %v", err)
	}

	go func() {
		defer os.RemoveAll(targetDir) // Clean up upload temp directory
		runScan(scanID, targetDir, webCfg)
	}()
	return scanID, nil
}

// StartScanFromGit clones a repo and scans it
func StartScanFromGit(repoURL string, configJSON string) (string, error) {
	scanID := uuid.New().String()[:8]
	var webCfg WebScanConfig
	json.Unmarshal([]byte(configJSON), &webCfg)

	tmpDir, err := os.MkdirTemp("", "qwen-scan-"+scanID+"-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %v", err)
	}

	parts := strings.Split(strings.TrimSuffix(repoURL, ".git"), "/")
	displayName := parts[len(parts)-1]
	if displayName == "" {
		displayName = repoURL
	}

	if err := CreateScan(scanID, displayName, "git", configJSON); err != nil {
		return "", fmt.Errorf("failed to create scan record: %v", err)
	}

	go func() {
		defer os.RemoveAll(tmpDir)

		wsHub.BroadcastLog(scanID, fmt.Sprintf("Cloning repository: %s", repoURL), "phase")
		wsHub.BroadcastProgress(scanID, "Cloning Repository", 5)

		cmd := exec.Command("git", "clone", "--depth", "1", repoURL, tmpDir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			wsHub.BroadcastError(scanID, fmt.Sprintf("Git clone failed: %s", string(output)))
			UpdateScanStatus(scanID, "failed")
			return
		}

		wsHub.BroadcastLog(scanID, "Repository cloned successfully", "success")
		runScan(scanID, tmpDir, webCfg)
	}()

	return scanID, nil
}

// runScan is the core scan orchestration (runs in a goroutine)
func runScan(scanID string, targetDir string, cfg WebScanConfig) {
	startTime := time.Now()

	wsHub.BroadcastLog(scanID, "🚀 Starting security scan...", "phase")
	wsHub.BroadcastProgress(scanID, "Initializing", 2)

	if cfg.OllamaHost != "" {
		ai.SetOllamaHost(cfg.OllamaHost)
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Set Ollama Host to %s", cfg.OllamaHost), "info")
	}

	// Load rules
	rulesDir := "rules"
	if cfg.CustomRulesDir != "" {
		rulesDir = cfg.CustomRulesDir
	}
	rules, err := config.LoadRules(rulesDir)
	if err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Warning: Failed to load rules: %v", err), "warning")
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Loaded %d rules from %s", len(rules), rulesDir), "info")

	// Walk directory
	wsHub.BroadcastProgress(scanID, "Scanning Files", 10)
	wsHub.BroadcastLog(scanID, "Walking target directory...", "info")
	result, err := scanner.WalkDirectory(targetDir)
	if err != nil {
		wsHub.BroadcastError(scanID, fmt.Sprintf("Failed to walk directory: %v", err))
		UpdateScanStatus(scanID, "failed")
		return
	}
	totalFiles := 0
	for _, files := range result.FilePaths {
		totalFiles += len(files)
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Found %d files across %d languages", totalFiles, len(result.FilePaths)), "success")

	var allFindings []reporter.Finding

	// ── Always-On Scanners ──────────────────────────────────

	// Pattern Scan (always)
	wsHub.BroadcastProgress(scanID, "Pattern Matching", 20)
	wsHub.BroadcastLog(scanID, "Running pattern engine...", "phase")
	patternFindings := scanner.RunPatternScan(result, rules, rulesDir)
	for i := range patternFindings {
		patternFindings[i].Confidence = 0.70 // Base confidence for pattern matching
	}
	allFindings = append(allFindings, patternFindings...)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Pattern engine found %d issues", len(patternFindings)), "info")

	// AST Analysis (always)
	wsHub.BroadcastProgress(scanID, "AST Analysis", 30)
	wsHub.BroadcastLog(scanID, "Running AST analyzer...", "phase")
	astAnalyzer := scanner.NewASTAnalyzer()
	for _, files := range result.FilePaths {
		for _, file := range files {
			findings, err := astAnalyzer.AnalyzeFile(file)
			if err == nil {
				allFindings = append(allFindings, findings...)
			}
		}
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("AST analysis complete (%d total findings so far)", len(allFindings)), "info")

	// Taint Analysis (always)
	wsHub.BroadcastProgress(scanID, "Taint Analysis", 40)
	wsHub.BroadcastLog(scanID, "Running taint analyzer...", "phase")
	taintAnalyzer := scanner.NewTaintAnalyzer()
	for _, files := range result.FilePaths {
		for _, file := range files {
			findings, err := taintAnalyzer.AnalyzeTaintFlow(file)
			if err == nil {
				allFindings = append(allFindings, findings...)
			}
		}
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Taint analysis complete (%d total findings)", len(allFindings)), "info")

	// Secret Detection (always on — not togglable)
	wsHub.BroadcastProgress(scanID, "Secret Detection", 50)
	wsHub.BroadcastLog(scanID, "Scanning for hardcoded secrets...", "phase")
	secretDetector := scanner.NewSecretDetector()
	secretFindings, err := secretDetector.ScanSecrets(targetDir)
	if err == nil {
		allFindings = append(allFindings, secretFindings...)
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Secret detection complete (%d total findings)", len(allFindings)), "info")

	// ── Deep Scan Features (gated) ──────────────────────────

	if cfg.EnableDeepScan {
		// Dependency Scan
		wsHub.BroadcastProgress(scanID, "Dependency Scan", 52)
		wsHub.BroadcastLog(scanID, "Checking vulnerable dependencies...", "phase")
		depFindings, err := scanner.ScanDependencies(targetDir)
		if err == nil {
			allFindings = append(allFindings, depFindings...)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Dependency scan complete (%d total findings)", len(allFindings)), "info")

		// Semgrep
		wsHub.BroadcastProgress(scanID, "Semgrep Analysis", 55)
		wsHub.BroadcastLog(scanID, "Running Semgrep analysis...", "phase")
		semgrepFindings, err := scanner.RunSemgrep(targetDir)
		if err == nil {
			allFindings = append(allFindings, semgrepFindings...)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Semgrep analysis complete (%d total findings)", len(allFindings)), "info")

		// Supply Chain + OSV SCA
		wsHub.BroadcastProgress(scanID, "Supply Chain Analysis", 58)
		wsHub.BroadcastLog(scanID, "Running supply chain security checks...", "phase")
		supplyChainScanner := scanner.NewSupplyChainScanner()
		scFindings, err := supplyChainScanner.ScanSupplyChain(targetDir)
		if err == nil {
			allFindings = append(allFindings, scFindings...)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Supply chain analysis complete (%d total findings)", len(allFindings)), "info")

		// OSV.dev SCA Scanner
		if scanner.CheckOSVCliInstalled() {
			wsHub.BroadcastProgress(scanID, "OSV SCA Scan", 60)
			wsHub.BroadcastLog(scanID, "Running OSV.dev SCA vulnerability scan...", "phase")
			osvFindings, osvErr := scanner.RunOSVCli(targetDir)
			if osvErr == nil && len(osvFindings) > 0 {
				allFindings = append(allFindings, osvFindings...)
				wsHub.BroadcastLog(scanID, fmt.Sprintf("OSV SCA found %d known CVEs", len(osvFindings)), "success")
			} else if osvErr != nil {
				wsHub.BroadcastLog(scanID, fmt.Sprintf("OSV SCA scan skipped: %v", osvErr), "warning")
			}
		} else {
			wsHub.BroadcastLog(scanID, "OSV scanner not installed, skipping SCA", "info")
		}

		// Container Scanning (now part of Deep Scan)
		wsHub.BroadcastProgress(scanID, "Container Scanning", 62)
		wsHub.BroadcastLog(scanID, "Scanning Dockerfiles & Kubernetes manifests...", "phase")
		containerScanner := scanner.NewContainerScanner(int64(len(allFindings) + 1000))
		containerFindings, cErr := containerScanner.ScanContainers(targetDir)
		if cErr == nil {
			allFindings = append(allFindings, containerFindings...)
			wsHub.BroadcastLog(scanID, fmt.Sprintf("Container scan found %d issues", len(containerFindings)), "info")
		} else {
			wsHub.BroadcastLog(scanID, fmt.Sprintf("Container scan failed: %v", cErr), "warning")
		}

		// Threat Intelligence Enrichment (now part of Deep Scan)
		wsHub.BroadcastProgress(scanID, "Threat Intelligence", 63)
		wsHub.BroadcastLog(scanID, "Enriching findings with threat intelligence (CVE, CISA KEV, MITRE ATT&CK)...", "phase")
		threatIntelScanner := scanner.NewThreatIntelScanner()
		enrichedFindings, tiErr := threatIntelScanner.ScanWithThreatIntel(allFindings)
		if tiErr == nil {
			allFindings = enrichedFindings
			wsHub.BroadcastLog(scanID, "Threat intelligence enrichment complete", "success")
		} else {
			wsHub.BroadcastLog(scanID, fmt.Sprintf("Threat intel failed: %v", tiErr), "warning")
		}
	}

	// ── AI Discovery (was Container Scanning gated block) ──

	// ── Reachability Analysis (always) ──────────────────────

	wsHub.BroadcastProgress(scanID, "Reachability Analysis", 64)
	wsHub.BroadcastLog(scanID, "Building call graph for reachability analysis...", "phase")
	reachAnalyzer := scanner.NewReachabilityAnalyzer()
	if raErr := reachAnalyzer.BuildCallGraph(targetDir); raErr == nil {
		allFindings = reachAnalyzer.AnnotateFindings(allFindings)
		wsHub.BroadcastLog(scanID, "Reachability analysis complete", "info")
	} else {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Reachability analysis skipped: %v", raErr), "warning")
	}

	// ── AI-Powered Features (gated) ──────────────────────────

	modelName := cfg.AIModel
	if modelName == "" {
		modelName = ai.GetDefaultModel() // Standard default
	}

	consolidationModel := cfg.ConsolidationModel
	if consolidationModel == "" {
		consolidationModel = ai.GetDefaultModel() // Heavy default fallback
	}

	if cfg.EnableAI {
		// AI Discovery
		wsHub.BroadcastProgress(scanID, "AI Discovery", 70)
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Running AI discovery with model: %s", modelName), "phase")
		aiFindings := ai.RunAIDiscovery(modelName, targetDir)
		wsHub.BroadcastLog(scanID, fmt.Sprintf("AI discovered %d potential vulnerabilities", len(aiFindings)), "success")

		// ── Combined AI Validation ──────────────────────────────
		// Combine static findings and AI discoveries for batch validation
		// We prioritize Critical/High findings for validation to optimize time
		wsHub.BroadcastProgress(scanID, "AI Validation", 78)
		wsHub.BroadcastLog(scanID, "Preparing combined findings for AI validation...", "phase")

		fileContents := make(map[string]string)
		for _, files := range result.FilePaths {
			for _, file := range files {
				if data, err := os.ReadFile(file); err == nil {
					fileContents[file] = string(data)
				}
			}
		}

		// Initial rough deduplication to avoid redundant AI calls
		combinedForValidation := append([]reporter.Finding{}, allFindings...)
		combinedForValidation = append(combinedForValidation, aiFindings...)
		uniqueForValidation := webDeduplicateFindings(combinedForValidation)

		wsHub.BroadcastLog(scanID, fmt.Sprintf("Validating %d unique findings with AI...", len(uniqueForValidation)), "phase")
		validatedFindings := ai.ValidateFindingsBatch(modelName, uniqueForValidation, fileContents, 4, targetDir)

		// Split back into static and ai findings (merger expects them separate for now)
		var validatedStatic []reporter.Finding
		var validatedAI []reporter.Finding
		for _, f := range validatedFindings {
			if strings.Contains(f.Source, "ai") {
				validatedAI = append(validatedAI, f)
			} else {
				validatedStatic = append(validatedStatic, f)
			}
		}
		allFindings = validatedStatic
		aiFindings = validatedAI

		wsHub.BroadcastLog(scanID, "AI validation complete", "success")

		// Consolidate with Larger LLM
		if len(aiFindings) > 0 {
			if cfg.ConsolidationOllamaHost != "" {
				ai.SetOllamaHost(cfg.ConsolidationOllamaHost)
				wsHub.BroadcastLog(scanID, fmt.Sprintf("Switched to Consolidation Ollama Host: %s", cfg.ConsolidationOllamaHost), "info")
			}

			wsHub.BroadcastProgress(scanID, "AI Consolidation", 85)
			wsHub.BroadcastLog(scanID, fmt.Sprintf("Consolidating static + AI findings using Larger LLM: %s...", consolidationModel), "phase")
			merged, err := ai.ConsolidateFindings(allFindings, aiFindings, consolidationModel)
			if err == nil {
				allFindings = merged
				wsHub.BroadcastLog(scanID, "Consolidation complete", "success")
			} else {
				allFindings = append(allFindings, aiFindings...)
				wsHub.BroadcastLog(scanID, fmt.Sprintf("Consolidation failed, appending: %v", err), "warning")
			}
		}
	}

	// ── ML False Positive Reduction (gated) ─────────────────

	if cfg.EnableMLFPReduction && cfg.EnableAI {
		wsHub.BroadcastProgress(scanID, "ML FP Reduction", 87)
		wsHub.BroadcastLog(scanID, "Running ML-based false positive reduction...", "phase")
		mlReducer := ai.NewMLFPReducer(".scanner-cache")
		mlReducer.LoadHistory()
		allFindings = mlReducer.FilterFindingsByFPProbability(allFindings, 0.7)
		mlReducer.SaveHistory()
		wsHub.BroadcastLog(scanID, "ML FP reduction complete", "info")
	}

	// ── Confidence Calibration (always after AI) ────────────

	if cfg.EnableAI {
		wsHub.BroadcastLog(scanID, "Applying confidence calibration...", "info")
		calibrator := ai.NewConfidenceCalibrator(targetDir)
		allFindings = calibrator.ApplyCalibrationToFindings(allFindings)
		calibrator.SaveStats()
	}

	// ── Finalize ──────────────────────────────────────────────

	// Deduplication
	wsHub.BroadcastProgress(scanID, "Deduplication", 88)
	wsHub.BroadcastLog(scanID, "Deduplicating findings...", "phase")
	allFindings = webDeduplicateFindings(allFindings)

	// Sort by severity
	severityOrder := map[string]int{
		"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
	}
	for i := 0; i < len(allFindings); i++ {
		for j := i + 1; j < len(allFindings); j++ {
			if severityOrder[allFindings[j].Severity] > severityOrder[allFindings[i].Severity] {
				allFindings[i], allFindings[j] = allFindings[j], allFindings[i]
			}
		}
	}

	// Renumber and Calculate Multi-Engine Trust Score
	for i := range allFindings {
		allFindings[i].SrNo = i + 1

		// Initial trust score based on engines
		engines := strings.Split(allFindings[i].Source, ", ")
		baseScore := allFindings[i].Confidence * 100.0

		if len(engines) > 1 {
			// Boost score for multi-engine confirmation
			baseScore += float64(len(engines)-1) * 15.0
		}

		// AI validation boost
		if allFindings[i].AiValidated == "Yes" {
			baseScore += 10.0
		}

		if baseScore > 100 {
			baseScore = 100
		}
		allFindings[i].TrustScore = baseScore
	}

	// Populate code snippets
	wsHub.BroadcastLog(scanID, "Extracting code snippets...", "info")
	webPopulateCodeSnippets(allFindings, targetDir)

	// Relativize paths
	for i := range allFindings {
		if rel, err := filepath.Rel(targetDir, allFindings[i].FilePath); err == nil {
			allFindings[i].FilePath = rel
		}
	}

	// Calculate Risk Score
	riskScore := reporter.CalculateRiskScore(allFindings)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Security Risk Score: %d/100 (%s)", riskScore.Score, riskScore.Level), "info")

	// Calculate counts
	criticalCount := riskScore.CriticalCount
	highCount := riskScore.HighCount

	// ── Compliance Checking (gated) ─────────────────────────

	wsHub.BroadcastProgress(scanID, "Saving Results", 95)
	wsHub.BroadcastLog(scanID, "Saving findings to database...", "info")
	SaveFindings(scanID, allFindings)
	UpdateScanCounts(scanID, len(allFindings), criticalCount, highCount)
	UpdateScanStatus(scanID, "completed")

	// Generate report files
	wsHub.BroadcastLog(scanID, "Generating reports...", "info")
	webGenerateReportFiles(scanID, allFindings, targetDir)

	elapsed := time.Since(startTime)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("✅ Scan completed in %s — %d findings (%d critical, %d high) — Risk: %d/100 (%s)",
		elapsed.Round(time.Second), len(allFindings), criticalCount, highCount, riskScore.Score, riskScore.Level), "success")

	wsHub.BroadcastProgress(scanID, "Complete", 100)
	wsHub.Broadcast(scanID, WSMessage{Type: "findings_update", Count: len(allFindings)})
	wsHub.BroadcastComplete(scanID)
}

// webGenerateReportFiles creates HTML, CSV, and PDF reports
func webGenerateReportFiles(scanID string, findings []reporter.Finding, targetDir string) {
	reportsDir := filepath.Join(os.TempDir(), "qwen-reports", scanID)
	os.MkdirAll(reportsDir, 0755)

	summary := reporter.GenerateReportSummary(findings, targetDir)

	// CSV
	csvPath := filepath.Join(reportsDir, "report.csv")
	reporter.WriteCSV(csvPath, findings)

	// HTML
	htmlPath := filepath.Join(reportsDir, "report.html")
	reporter.GenerateHTMLReport(htmlPath, findings, summary)

	// PDF
	pdfPath := filepath.Join(reportsDir, "report.pdf")
	riskScore := reporter.CalculateRiskScore(findings)
	reporter.GeneratePDF(pdfPath, findings, summary, riskScore)

	utils.LogInfo(fmt.Sprintf("Reports saved for scan %s at %s", scanID, reportsDir))
}

// webDeduplicateFindings removes duplicate findings by physically grouping line locations
func webDeduplicateFindings(findings []reporter.Finding) []reporter.Finding {
	// Group findings by FilePath + startLine
	grouped := make(map[string][]reporter.Finding)

	for _, f := range findings {
		startLine := f.LineNumber
		if parts := strings.Split(f.LineNumber, "-"); len(parts) > 0 {
			startLine = parts[0]
		}
		key := fmt.Sprintf("%s|%s", f.FilePath, startLine)
		grouped[key] = append(grouped[key], f)
	}

	severityWeight := map[string]int{
		"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
	}

	var unique []reporter.Finding
	for _, group := range grouped {
		if len(group) == 1 {
			unique = append(unique, group[0])
			continue
		}

		bestFinding := group[0]
		bestWeight := severityWeight[strings.ToLower(bestFinding.Severity)]
		sources := make(map[string]bool)
		sources[bestFinding.Source] = true

		for _, f := range group[1:] {
			weight := severityWeight[strings.ToLower(f.Severity)]
			if weight > bestWeight {
				bestFinding.Severity = f.Severity
				bestFinding.IssueName = f.IssueName
				bestFinding.Description = f.Description
				bestFinding.Remediation = f.Remediation
				bestFinding.RuleID = f.RuleID
				bestFinding.CWE = f.CWE
				bestFinding.OWASP = f.OWASP
				bestWeight = weight
			}
			sources[f.Source] = true
		}

		var sourceList []string
		for s := range sources {
			if s != "" {
				sourceList = append(sourceList, s)
			}
		}
		bestFinding.Source = strings.Join(sourceList, ", ")

		for _, f := range group {
			if f.AiValidated == "Yes" {
				bestFinding.AiValidated = "Yes"
				break
			}
		}

		unique = append(unique, bestFinding)
	}

	return unique
}

// webPopulateCodeSnippets reads source files and extracts ~5 lines around each vulnerable line
func webPopulateCodeSnippets(findings []reporter.Finding, targetDir string) {
	fileCache := make(map[string][]string)

	for i := range findings {
		filePath := findings[i].FilePath
		// Try absolute path first, then relative to targetDir
		if !filepath.IsAbs(filePath) {
			filePath = filepath.Join(targetDir, filePath)
		}

		var lineNum int
		fmt.Sscanf(findings[i].LineNumber, "%d", &lineNum)
		if lineNum <= 0 {
			continue
		}

		if _, ok := fileCache[filePath]; !ok {
			content, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			fileCache[filePath] = strings.Split(utils.NormalizeNewlines(string(content)), "\n")
		}

		lines := fileCache[filePath]
		start := lineNum - 3
		if start < 0 {
			start = 0
		}
		end := lineNum + 2
		if end > len(lines) {
			end = len(lines)
		}

		var snippet strings.Builder
		for j := start; j < end; j++ {
			marker := "  "
			if j+1 == lineNum {
				marker = "→ "
			}
			snippet.WriteString(fmt.Sprintf("%s%4d | %s\n", marker, j+1, lines[j]))
		}
		findings[i].CodeSnippet = snippet.String()
	}
}

// ExtractUploadedZip extracts a zip file to a temp directory
func ExtractUploadedZip(zipPath string) (string, error) {
	destDir, err := os.MkdirTemp("", "qwen-upload-")
	if err != nil {
		return "", err
	}

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(destDir, f.Name)

		if !strings.HasPrefix(filepath.Clean(fpath), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		os.MkdirAll(filepath.Dir(fpath), os.ModePerm)
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			continue
		}

		io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}

	return destDir, nil
}
