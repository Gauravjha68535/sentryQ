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
type WebScanConfig struct {
	EnableAI           bool   `json:"enableAI"`
	EnableAIDiscovery  bool   `json:"enableAIDiscovery"`
	EnableSemgrep      bool   `json:"enableSemgrep"`
	EnableDeps         bool   `json:"enableDeps"`
	EnableSecrets      bool   `json:"enableSecrets"`
	EnableSupplyChain  bool   `json:"enableSupplyChain"`
	EnableCompliance   bool   `json:"enableCompliance"`
	EnableThreatIntel  bool   `json:"enableThreatIntel"`
	EnableConsolidated bool   `json:"enableConsolidated"`
	AIModel            string `json:"aiModel"`
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

	go runScan(scanID, targetDir, webCfg)
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
	wsHub.BroadcastProgress(scanID, "Initializing", 5)

	// Load rules
	rulesDir := "rules"
	rules, err := config.LoadRules(rulesDir)
	if err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Warning: Failed to load rules: %v", err), "warning")
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Loaded %d rules", len(rules)), "info")

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

	// Pattern Scan
	wsHub.BroadcastProgress(scanID, "Pattern Matching", 20)
	wsHub.BroadcastLog(scanID, "Running pattern engine...", "phase")
	patternFindings := scanner.RunPatternScan(result, rules, rulesDir)
	allFindings = append(allFindings, patternFindings...)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Pattern engine found %d issues", len(patternFindings)), "info")

	// AST Analysis
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

	// Taint Analysis
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

	// Secret Detection
	if cfg.EnableSecrets {
		wsHub.BroadcastProgress(scanID, "Secret Detection", 50)
		wsHub.BroadcastLog(scanID, "Scanning for hardcoded secrets...", "phase")
		secretDetector := scanner.NewSecretDetector()
		secretFindings, err := secretDetector.ScanSecrets(targetDir)
		if err == nil {
			allFindings = append(allFindings, secretFindings...)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Secret detection complete (%d total findings)", len(allFindings)), "info")
	}

	// Semgrep
	if cfg.EnableSemgrep {
		wsHub.BroadcastProgress(scanID, "Semgrep Analysis", 60)
		wsHub.BroadcastLog(scanID, "Running Semgrep analysis...", "phase")
		semgrepFindings, err := scanner.RunSemgrep(targetDir)
		if err == nil {
			allFindings = append(allFindings, semgrepFindings...)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Semgrep analysis complete (%d total findings)", len(allFindings)), "info")
	}

	// Supply Chain
	if cfg.EnableSupplyChain {
		wsHub.BroadcastProgress(scanID, "Supply Chain Analysis", 65)
		wsHub.BroadcastLog(scanID, "Running supply chain security checks...", "phase")
		supplyChainScanner := scanner.NewSupplyChainScanner()
		scFindings, err := supplyChainScanner.ScanSupplyChain(targetDir)
		if err == nil {
			allFindings = append(allFindings, scFindings...)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Supply chain analysis complete (%d total findings)", len(allFindings)), "info")
	}

	// AI model name
	modelName := cfg.AIModel
	if modelName == "" {
		modelName = "deepseek-r1:7b"
	}

	// AI Discovery
	if cfg.EnableAIDiscovery {
		wsHub.BroadcastProgress(scanID, "AI Discovery", 70)
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Running AI discovery with model: %s", modelName), "phase")
		aiFindings := ai.RunAIDiscovery(modelName, targetDir)
		wsHub.BroadcastLog(scanID, fmt.Sprintf("AI discovered %d potential vulnerabilities", len(aiFindings)), "success")

		if cfg.EnableConsolidated && len(aiFindings) > 0 {
			wsHub.BroadcastLog(scanID, "Consolidating static + AI findings...", "phase")
			merged, err := ai.ConsolidateFindings(allFindings, aiFindings, modelName)
			if err == nil {
				allFindings = merged
			} else {
				allFindings = append(allFindings, aiFindings...)
				wsHub.BroadcastLog(scanID, fmt.Sprintf("Consolidation failed, appending: %v", err), "warning")
			}
		} else {
			allFindings = append(allFindings, aiFindings...)
		}
	}

	// AI Validation
	if cfg.EnableAI && len(allFindings) > 0 {
		wsHub.BroadcastProgress(scanID, "AI Validation", 80)
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Validating %d findings with AI...", len(allFindings)), "phase")

		fileContents := make(map[string]string)
		for _, files := range result.FilePaths {
			for _, file := range files {
				data, err := os.ReadFile(file)
				if err == nil {
					fileContents[file] = string(data)
				}
			}
		}

		allFindings = ai.ValidateFindingsBatch(modelName, allFindings, fileContents, 4, targetDir)
		wsHub.BroadcastLog(scanID, "AI validation complete", "success")
	}

	// Deduplication
	wsHub.BroadcastProgress(scanID, "Deduplication", 90)
	wsHub.BroadcastLog(scanID, "Deduplicating findings...", "phase")
	allFindings = webDeduplicateFindings(allFindings)

	// Renumber
	for i := range allFindings {
		allFindings[i].SrNo = i + 1
	}

	// Relativize paths
	for i := range allFindings {
		if rel, err := filepath.Rel(targetDir, allFindings[i].FilePath); err == nil {
			allFindings[i].FilePath = rel
		}
	}

	// Calculate counts
	criticalCount := 0
	highCount := 0
	for _, f := range allFindings {
		if f.Severity == "critical" {
			criticalCount++
		} else if f.Severity == "high" {
			highCount++
		}
	}

	// Save to DB
	wsHub.BroadcastProgress(scanID, "Saving Results", 95)
	wsHub.BroadcastLog(scanID, "Saving findings to database...", "info")
	SaveFindings(scanID, allFindings)
	UpdateScanCounts(scanID, len(allFindings), criticalCount, highCount)
	UpdateScanStatus(scanID, "completed")

	// Generate report files
	wsHub.BroadcastLog(scanID, "Generating reports...", "info")
	webGenerateReportFiles(scanID, allFindings, targetDir)

	elapsed := time.Since(startTime)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("✅ Scan completed in %s — %d findings (%d critical, %d high)",
		elapsed.Round(time.Second), len(allFindings), criticalCount, highCount), "success")

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

// webDeduplicateFindings removes duplicate findings
func webDeduplicateFindings(findings []reporter.Finding) []reporter.Finding {
	seen := make(map[string]bool)
	var unique []reporter.Finding
	for _, f := range findings {
		key := fmt.Sprintf("%s|%s|%s", f.FilePath, f.LineNumber, f.RuleID)
		if f.RuleID == "" {
			key = fmt.Sprintf("%s|%s|%s", f.FilePath, f.LineNumber, f.IssueName)
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}
	return unique
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
