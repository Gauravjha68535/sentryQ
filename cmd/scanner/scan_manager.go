package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"QWEN_SCR_24_FEB_2026/ai"
	"QWEN_SCR_24_FEB_2026/config"
	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/scanner"
	"QWEN_SCR_24_FEB_2026/utils"

	"github.com/google/uuid"
)

// WebScanConfig mirrors the frontend config toggles
// 3 modes:
// - EnableDeepScan: deps + semgrep + supply chain + compliance + threat intel
// - EnableAI: AI validation + AI discovery + consolidated merge
// - EnableEnsemble: Full static scan (Report A) + Full AI scan (Report B) + Judge LLM merge
// Secret detection, pattern scan, AST, and taint analysis run ALWAYS.
type WebScanConfig struct {
	EnableDeepScan          bool   `json:"enableDeepScan"`
	EnableAI                bool   `json:"enableAI"`
	EnableEnsemble          bool   `json:"enableEnsemble"`
	AIModel                 string `json:"aiModel"`
	OllamaHost              string `json:"ollamaHost"`
	ConsolidationModel      string `json:"consolidationModel"`
	ConsolidationOllamaHost string `json:"consolidationOllamaHost"`
	JudgeModel              string `json:"judgeModel"`
	JudgeOllamaHost         string `json:"judgeOllamaHost"`
	EnableMLFPReduction     bool   `json:"enableMLFPReduction"`
	CustomRulesDir          string `json:"customRulesDir"`
}

var (
	activeScans   = make(map[string]context.CancelFunc)
	activeScansMu sync.Mutex
)

// registerScan registers a cancellation function for a scan
func registerScan(scanID string, cancel context.CancelFunc) {
	activeScansMu.Lock()
	defer activeScansMu.Unlock()
	activeScans[scanID] = cancel
}

// unregisterScan removes a scan's cancellation function
func unregisterScan(scanID string) {
	activeScansMu.Lock()
	defer activeScansMu.Unlock()
	delete(activeScans, scanID)
}

// StopScan terminates an active scan
func StopScan(scanID string) error {
	activeScansMu.Lock()
	cancel, exists := activeScans[scanID]
	activeScansMu.Unlock()

	if !exists {
		return fmt.Errorf("scan %s not found or already completed", scanID)
	}

	// Actually cancel the running scan context
	cancel()

	utils.LogInfo(fmt.Sprintf("Scan %s terminated by user request", scanID))
	// 5. Unregister
	unregisterScan(scanID)

	UpdateScanStatus(scanID, "stopped")
	wsHub.BroadcastLog(scanID, "🛑 Scan terminated by user", "warning")
	wsHub.BroadcastError(scanID, "Scan aborted by user")

	return nil
}

// StartScanFromUpload handles uploaded files
func StartScanFromUpload(targetDir string, configJSON string) (string, error) {
	scanID := uuid.New().String()[:8]
	var webCfg WebScanConfig
	if err := json.Unmarshal([]byte(configJSON), &webCfg); err != nil {
		return "", fmt.Errorf("failed to parse config JSON: %v", err)
	}

	displayName := filepath.Base(targetDir)

	if err := CreateScan(scanID, displayName, "upload", configJSON); err != nil {
		return "", fmt.Errorf("failed to create scan record: %v", err)
	}

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		registerScan(scanID, cancel)
		defer unregisterScan(scanID)
		defer cancel()

		defer os.RemoveAll(targetDir) // Clean up upload temp directory
		runScan(ctx, scanID, targetDir, webCfg)
	}()
	return scanID, nil
}

// isValidGitURL performs basic safety checks on the repository URL to prevent flag injection
func isValidGitURL(url string) bool {
	trimmed := strings.TrimSpace(url)
	if trimmed == "" {
		return false
	}
	// Prevent flag injection: URL must not start with a hyphen
	if strings.HasPrefix(trimmed, "-") {
		return false
	}
	// Basic format check
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") && !strings.HasPrefix(trimmed, "git@") && !strings.HasPrefix(trimmed, "ssh://") {
		return false
	}
	return true
}

// StartScanFromGit clones a repo and scans it
func StartScanFromGit(repoURL string, configJSON string) (string, error) {
	if !isValidGitURL(repoURL) {
		return "", fmt.Errorf("invalid or unsafe Git URL provided")
	}

	scanID := uuid.New().String()[:8]
	var webCfg WebScanConfig
	if err := json.Unmarshal([]byte(configJSON), &webCfg); err != nil {
		return "", fmt.Errorf("failed to parse config JSON: %v", err)
	}

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

		// Extra safety check for exec
		cmd := exec.Command("git", "clone", "--depth", "1", "--", repoURL, tmpDir)
		output, err := cmd.CombinedOutput()
		if err != nil {
			wsHub.BroadcastError(scanID, fmt.Sprintf("Git clone failed: %s", string(output)))
			UpdateScanStatus(scanID, "failed")
			return
		}

		wsHub.BroadcastLog(scanID, "Repository cloned successfully", "success")

		ctx, cancel := context.WithCancel(context.Background())
		registerScan(scanID, cancel)
		defer unregisterScan(scanID)
		defer cancel()

		runScan(ctx, scanID, tmpDir, webCfg)
	}()

	return scanID, nil
}

// runScan is the core scan orchestration (runs in a goroutine)
func runScan(ctx context.Context, scanID string, targetDir string, cfg WebScanConfig) {
	// Route to Ensemble pipeline if enabled
	if cfg.EnableEnsemble {
		runEnsembleScan(ctx, scanID, targetDir, cfg)
		return
	}

	startTime := time.Now()

	wsHub.BroadcastLog(scanID, "🚀 Starting security scan...", "phase")
	wsHub.BroadcastProgress(scanID, "Initializing", 2)

	if ctx.Err() != nil {
		return
	}

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

	// Walking directory
	wsHub.BroadcastProgress(scanID, "Scanning Files", 10)
	wsHub.BroadcastLog(scanID, "Walking target directory...", "info")
	if ctx.Err() != nil {
		return
	}
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
	if ctx.Err() != nil {
		return
	}

	// Pattern Scan (always)
	if ctx.Err() != nil {
		return
	}
	wsHub.BroadcastProgress(scanID, "Pattern Matching", 20)
	wsHub.BroadcastLog(scanID, "Running pattern engine...", "phase")
	patternFindings := scanner.RunPatternScan(result, rules, rulesDir)
	for i := range patternFindings {
		patternFindings[i].Confidence = 0.70 // Base confidence for pattern matching
	}
	allFindings = append(allFindings, patternFindings...)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Pattern engine found %d issues", len(patternFindings)), "info")

	// AST Analysis (always)
	if ctx.Err() != nil {
		return
	}
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
	if ctx.Err() != nil {
		return
	}
	wsHub.BroadcastProgress(scanID, "Taint Analysis", 40)
	wsHub.BroadcastLog(scanID, "Running taint analyzer...", "phase")
	taintAnalyzer := scanner.NewTaintAnalyzer()
	for _, files := range result.FilePaths {
		if ctx.Err() != nil {
			return
		}
		for _, file := range files {
			if ctx.Err() != nil {
				return
			}
			findings, err := taintAnalyzer.AnalyzeTaintFlow(file)
			if err == nil {
				allFindings = append(allFindings, findings...)
			}
		}
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Taint analysis complete (%d total findings)", len(allFindings)), "info")

	// Secret Detection (always on — not togglable)
	if ctx.Err() != nil {
		return
	}
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
		if ctx.Err() != nil {
			return
		}
		// Dependency Scan
		wsHub.BroadcastProgress(scanID, "Dependency Scan", 52)
		wsHub.BroadcastLog(scanID, "Checking vulnerable dependencies...", "phase")
		depFindings, err := scanner.ScanDependencies(ctx, targetDir)
		if err == nil {
			allFindings = append(allFindings, depFindings...)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Dependency scan complete (%d total findings)", len(allFindings)), "info")

		// Semgrep
		wsHub.BroadcastProgress(scanID, "Semgrep Analysis", 55)
		wsHub.BroadcastLog(scanID, "Running Semgrep analysis...", "phase")
		semgrepFindings, err := scanner.RunSemgrep(ctx, targetDir)
		if err == nil {
			allFindings = append(allFindings, semgrepFindings...)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Semgrep analysis complete (%d total findings)", len(allFindings)), "info")

		// Supply Chain + OSV SCA
		wsHub.BroadcastProgress(scanID, "Supply Chain Analysis", 58)
		wsHub.BroadcastLog(scanID, "Running supply chain security checks...", "phase")
		supplyChainScanner := scanner.NewSupplyChainScanner()
		scFindings, err := supplyChainScanner.ScanSupplyChain(ctx, targetDir)
		if err == nil {
			allFindings = append(allFindings, scFindings...)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Supply chain analysis complete (%d total findings)", len(allFindings)), "info")

		// OSV.dev SCA Scanner
		if scanner.CheckOSVCliInstalled() {
			wsHub.BroadcastProgress(scanID, "OSV SCA Scan", 60)
			wsHub.BroadcastLog(scanID, "Running OSV.dev SCA vulnerability scan...", "phase")
			osvFindings, osvErr := scanner.RunOSVCli(ctx, targetDir)
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
		if ctx.Err() != nil {
			return
		}
		// AI Discovery
		wsHub.BroadcastProgress(scanID, "AI Discovery", 70)
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Running AI discovery with model: %s", modelName), "phase")
		aiFindings := ai.RunAIDiscovery(ctx, modelName, targetDir, func(msg string, level string) {
			wsHub.BroadcastLog(scanID, msg, level)
		})
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

		// PRE-VALIDATION: Run severity recalibration + FP suppression BEFORE sending to AI
		// This ensures: (1) upgraded findings (e.g. PHP LFI INFO→HIGH) actually get validated
		//               (2) obvious FPs (safe patterns) skip expensive AI calls
		wsHub.BroadcastLog(scanID, "Pre-validation: recalibrating severities...", "info")
		combinedForValidation = recalibrateSeverities(combinedForValidation, targetDir)
		wsHub.BroadcastLog(scanID, "Pre-validation: suppressing known safe patterns...", "info")
		combinedForValidation = scanner.SuppressFalsePositives(combinedForValidation, targetDir)

		// Remove suppressed FPs from validation queue (they're already marked info/FP)
		var toValidate []reporter.Finding
		var alreadySuppressed []reporter.Finding
		for _, f := range combinedForValidation {
			if strings.Contains(f.AiValidated, "Safe Pattern") {
				alreadySuppressed = append(alreadySuppressed, f)
			} else {
				toValidate = append(toValidate, f)
			}
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Skipped %d pre-suppressed FPs from AI validation queue", len(alreadySuppressed)), "info")

		uniqueForValidation := webDeduplicateFindings(toValidate)

		wsHub.BroadcastLog(scanID, fmt.Sprintf("Validating %d unique findings with AI...", len(uniqueForValidation)), "phase")
		validatedFindings := ai.ValidateFindingsBatch(ctx, modelName, uniqueForValidation, fileContents, 4, func(msg string, level string) {
			wsHub.BroadcastLog(scanID, msg, level)
		})

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
		// Add back the pre-suppressed findings (they're already marked as FP/info)
		allFindings = append(allFindings, alreadySuppressed...)
		aiFindings = validatedAI

		wsHub.BroadcastLog(scanID, "AI validation complete", "success")

		// Consolidate with Larger LLM
		if len(aiFindings) > 0 {
			if cfg.ConsolidationOllamaHost != "" {
				ai.SetOllamaHost(cfg.ConsolidationOllamaHost)
				wsHub.BroadcastLog(scanID, fmt.Sprintf("Switched to Consolidation Ollama Host: %s", cfg.ConsolidationOllamaHost), "info")
			}

			wsHub.BroadcastProgress(scanID, "AI Consolidation", 85)
			wsHub.BroadcastLog(scanID, fmt.Sprintf("Consolidating static + AI findings using Judge LLM: %s...", consolidationModel), "phase")

			// Use the more robust JudgeFindings engine
			merged, err := ai.JudgeFindings(ctx, allFindings, aiFindings, consolidationModel, cfg.ConsolidationOllamaHost)
			if err == nil {
				allFindings = merged
				wsHub.BroadcastLog(scanID, "Consolidation complete", "success")
			} else {
				allFindings = append(allFindings, aiFindings...)
				wsHub.BroadcastLog(scanID, fmt.Sprintf("Consolidation failed, using simple merge: %v", err), "warning")
			}
		}
	}

	// ── Confidence Calibration (always after AI) ────────────

	if cfg.EnableAI {
		wsHub.BroadcastLog(scanID, "Applying confidence calibration...", "info")
		calibrator := ai.NewConfidenceCalibrator()
		allFindings = calibrator.ApplyCalibrationToFindings(allFindings)
		calibrator.SaveStats()
	}

	// ── ML False Positive Reduction (if enabled) ─────────────
	if cfg.EnableMLFPReduction {
		wsHub.BroadcastProgress(scanID, "ML FP Reduction", 87)
		wsHub.BroadcastLog(scanID, "Applying ML-based False Positive reduction...", "info")
		reducer := ai.NewMLFPReducer(".qwen-ml-cache")
		reducer.LoadHistory()
		allFindings = reducer.FilterFindingsByFPProbability(allFindings, 0.8)
		reducer.SaveHistory()
		wsHub.BroadcastLog(scanID, "ML False Positive reduction complete", "info")
	}

	// ── Finalize ──────────────────────────────────────────────

	// Deduplicate
	wsHub.BroadcastProgress(scanID, "Deduplication", 88)
	wsHub.BroadcastLog(scanID, "Deduplicating findings...", "phase")
	allFindings = webDeduplicateFindings(allFindings)

	// FP Suppression: check code context for safe patterns
	wsHub.BroadcastProgress(scanID, "False Positive Suppression", 90)
	wsHub.BroadcastLog(scanID, "Suppressing false positives on safe patterns...", "phase")
	allFindings = scanner.SuppressFalsePositives(allFindings, targetDir)

	// Severity Recalibration + UNREACHABLE fix
	wsHub.BroadcastProgress(scanID, "Severity Calibration", 92)
	wsHub.BroadcastLog(scanID, "Recalibrating severities...", "phase")
	allFindings = recalibrateSeverities(allFindings, targetDir)

	// Sort by severity (Critical -> Info)
	severityOrder := map[string]int{
		"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
	}
	sort.Slice(allFindings, func(i, j int) bool {
		return severityOrder[allFindings[i].Severity] > severityOrder[allFindings[j].Severity]
	})

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
	if err := SaveFindings(scanID, allFindings); err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Failed to save findings: %v", err), "error")
	}
	if err := UpdateScanCounts(scanID, len(allFindings), criticalCount, highCount); err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Failed to update scan counts: %v", err), "error")
	}
	if err := UpdateScanStatus(scanID, "completed"); err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Failed to update scan status: %v", err), "error")
	}

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

// webDeduplicateFindings removes duplicate findings using proximity-based clustering.
// Old approach: group by exact FilePath+startLine (misses same vuln at L12, L22, L31 from different engines).
// New approach: group by FilePath + normalized vuln type (CWE/keyword), then cluster within ±15 lines.
func webDeduplicateFindings(findings []reporter.Finding) []reporter.Finding {
	severityWeight := map[string]int{
		"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
	}

	// Step 1: Group findings by file + normalized vulnerability type
	type groupKey struct {
		filePath string
		vulnType string
	}
	grouped := make(map[groupKey][]reporter.Finding)

	for _, f := range findings {
		vtype := normalizeVulnType(f)
		key := groupKey{filePath: f.FilePath, vulnType: vtype}
		grouped[key] = append(grouped[key], f)
	}

	// Step 2: Within each group, cluster by line proximity
	var unique []reporter.Finding
	for key, group := range grouped {
		if len(group) == 1 {
			unique = append(unique, group[0])
			continue
		}

		// Sort by line number for clustering
		sort.Slice(group, func(i, j int) bool {
			li := parseStartLine(group[i].LineNumber)
			lj := parseStartLine(group[j].LineNumber)
			return li < lj
		})

		// Greedy clustering: merge findings within dynamic lineProximity lines
		clusters := [][]reporter.Finding{{group[0]}}
		for _, f := range group[1:] {
			lastCluster := &clusters[len(clusters)-1]
			lastLine := parseStartLine((*lastCluster)[len(*lastCluster)-1].LineNumber)
			thisLine := parseStartLine(f.LineNumber)

			// Determine proximity threshold (0 for secrets, else 5)
			prox := 5
			upperVuln := strings.ToUpper(key.vulnType)
			if strings.Contains(upperVuln, "SECRET") || strings.Contains(upperVuln, "CREDENTIAL") {
				prox = 0
			}

			if thisLine-lastLine <= prox {
				*lastCluster = append(*lastCluster, f)
			} else {
				clusters = append(clusters, []reporter.Finding{f})
			}
		}

		// Step 3: For each cluster, keep the best finding and merge metadata
		for _, cluster := range clusters {
			best := cluster[0]
			bestWeight := severityWeight[strings.ToLower(best.Severity)]
			sources := make(map[string]bool)
			if best.Source != "" {
				sources[best.Source] = true
			}

			for _, f := range cluster[1:] {
				w := severityWeight[strings.ToLower(f.Severity)]
				if w > bestWeight {
					// Keep higher severity's details
					best.Severity = f.Severity
					best.IssueName = f.IssueName
					best.Description = f.Description
					best.Remediation = f.Remediation
					best.CWE = f.CWE
					best.OWASP = f.OWASP
					bestWeight = w
				}
				// Prefer longer (more detailed) description at same severity
				if w == bestWeight && len(f.Description) > len(best.Description) {
					best.Description = f.Description
					best.IssueName = f.IssueName
				}
				if f.Source != "" {
					sources[f.Source] = true
				}
				if f.AiValidated == "Yes" {
					best.AiValidated = "Yes"
				}
				// Take highest confidence
				if f.Confidence > best.Confidence {
					best.Confidence = f.Confidence
				}
				// Prefer non-empty RuleID
				if best.RuleID == "" && f.RuleID != "" {
					best.RuleID = f.RuleID
				}
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
		"CWE-89":  "SQLI", "CWE-564": "SQLI",
		"CWE-78":  "CMDI", "CWE-77": "CMDI",
		"CWE-79":  "XSS",
		"CWE-22":  "PATH_TRAVERSAL", "CWE-23": "PATH_TRAVERSAL", "CWE-36": "PATH_TRAVERSAL",
		"CWE-502": "DESERIALIZATION",
		"CWE-798": "HARDCODED_SECRET", "CWE-259": "HARDCODED_SECRET", "CWE-321": "HARDCODED_SECRET",
		"CWE-330": "WEAK_RANDOM", "CWE-331": "WEAK_RANDOM", "CWE-338": "WEAK_RANDOM",
		"CWE-918": "SSRF",
		"CWE-1336": "TEMPLATE_INJECTION", "CWE-94": "TEMPLATE_INJECTION", "CWE-95": "TEMPLATE_INJECTION",
		"CWE-943": "NOSQL_INJECTION",
		"CWE-915": "MASS_ASSIGNMENT",
		"CWE-611": "XXE",
		"CWE-352": "CSRF",
		"CWE-98":  "FILE_INCLUSION",
		"CWE-770": "RESOURCE_LIMIT",
		"CWE-1321": "PROTOTYPE_POLLUTION",
		"CWE-20":  "INPUT_VALIDATION",
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

// recalibrateSeverities adjusts over-inflated and under-rated severities, and
// removes the [UNREACHABLE] tag from web framework route handlers.
func recalibrateSeverities(findings []reporter.Finding, targetDir string) []reporter.Finding {
	// Cache file contents
	fileCache := make(map[string]string)
	readFile := func(filePath string) string {
		if content, ok := fileCache[filePath]; ok {
			return content
		}
		absPath := filePath
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(targetDir, filePath)
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			return ""
		}
		content := string(data)
		fileCache[filePath] = content
		return content
	}

	// Web framework entry point markers (if these exist in the file, routes are reachable)
	webMarkers := []string{
		"$_get", "$_post", "$_request", "$_cookie", "$_server",          // PHP
		"@app.route", "flask", "def index", "@app.get", "@app.post",    // Python Flask
		"app.get(", "app.post(", "express()", "router.",                   // Node.js Express
		"@requestmapping", "@getmapping", "@postmapping", "httpservlet", // Java Spring/Servlet
	}

	for i := range findings {
		f := &findings[i]
		cwe := strings.ToUpper(strings.TrimSpace(f.CWE))
		lower := strings.ToLower(f.IssueName + " " + f.Description + " " + f.RuleID)

		// ── DOWNGRADE RULES ──

		// Math.random / weak random: Critical → High
		if (cwe == "CWE-338" || cwe == "CWE-330" || cwe == "CWE-331" ||
			strings.Contains(lower, "math.random") || strings.Contains(lower, "predictable random")) &&
			f.Severity == "critical" {
			f.Severity = "high"
		}

		// Reflected XSS (non-stored): Critical → High
		if cwe == "CWE-79" && f.Severity == "critical" &&
			!strings.Contains(lower, "stored") {
			f.Severity = "high"
		}

		// Missing body size limit / CWE-770: Medium → Low
		if cwe == "CWE-770" && (f.Severity == "medium" || f.Severity == "high") {
			f.Severity = "low"
		}

		// Generic input validation CWE-20: cap at Medium
		if cwe == "CWE-20" && f.Severity == "critical" {
			f.Severity = "medium"
		}

		// ── UPGRADE RULES ──

		// NoSQL Injection with req.body: High → Critical (auth bypass)
		if (cwe == "CWE-943" || strings.Contains(lower, "nosql")) &&
			f.Severity == "high" &&
			strings.Contains(lower, "req.body") {
			f.Severity = "critical"
		}

		// SSTI / Template Injection: anything below Critical → Critical (RCE)
		if (cwe == "CWE-1336" || cwe == "CWE-94" ||
			strings.Contains(lower, "template injection") || strings.Contains(lower, "ssti")) &&
			(f.Severity == "medium" || f.Severity == "high") {
			f.Severity = "critical"
		}

		// File Inclusion: INFO → High minimum
		if (cwe == "CWE-98" || strings.Contains(lower, "file inclusion") || strings.Contains(lower, "lfi")) &&
			(f.Severity == "info" || f.Severity == "low") {
			f.Severity = "high"
		}

		// ── FIX [UNREACHABLE] FOR WEB CODE ──
		if strings.Contains(f.Description, "[UNREACHABLE]") {
			content := strings.ToLower(readFile(f.FilePath))
			if content != "" {
				for _, marker := range webMarkers {
					if strings.Contains(content, marker) {
						// Remove [UNREACHABLE] tag — this IS reachable via HTTP
						f.Description = strings.Replace(f.Description, "[UNREACHABLE] ", "", 1)
						// Restore severity if downgraded
						if f.Severity == "info" || f.Severity == "low" {
							f.Severity = "high"
						}
						break
					}
				}
			}
		}
	}

	return findings
}

// parseStartLine extracts the first (start) line number from a line reference like "12" or "12-18"
func parseStartLine(lineRef string) int {
	parts := strings.Split(lineRef, "-")
	var n int
	fmt.Sscanf(parts[0], "%d", &n)
	return n
}

// webPopulateCodeSnippets reads source files and extracts ~5 lines around each vulnerable line
func webPopulateCodeSnippets(findings []reporter.Finding, targetDir string) {
	// Group findings by file to limit memory to one file at a time
	indicesByFile := make(map[string][]int)

	for i := range findings {
		var lineNum int
		fmt.Sscanf(findings[i].LineNumber, "%d", &lineNum)
		if lineNum <= 0 {
			continue
		}

		filePath := findings[i].FilePath
		// Try absolute path first, then relative to targetDir
		if !filepath.IsAbs(filePath) {
			filePath = filepath.Join(targetDir, filePath)
		}
		indicesByFile[filePath] = append(indicesByFile[filePath], i)
	}

	for filePath, indices := range indicesByFile {
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		lines := strings.Split(utils.NormalizeNewlines(string(content)), "\n")

		for _, idx := range indices {
			var lineNum int
			fmt.Sscanf(findings[idx].LineNumber, "%d", &lineNum)

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
			findings[idx].CodeSnippet = snippet.String()
		}
		// Memory for `content` and `lines` will be garbage collected after this loop iteration
	}
}


// ════════════════════════════════════════════════════════════
//  ENSEMBLE AUDIT MODE — 3-Phase Pipeline
// ════════════════════════════════════════════════════════════

// runEnsembleScan implements the 3-phase high-assurance audit pipeline
// runEnsembleScan runs the full 3-phase Ensemble Audit:
//
//	Phase 1 (0-40%):  All static scanners → Report A
//	Phase 2 (40-75%): Independent AI discovery → Report B
//	Phase 3 (75-95%): Judge LLM merges A+B → Final Master Report
func runEnsembleScan(ctx context.Context, scanID string, targetDir string, cfg WebScanConfig) {
	startTime := time.Now()

	wsHub.BroadcastLog(scanID, "🔬 Starting Ensemble Audit (3-Phase Pipeline)...", "phase")
	wsHub.BroadcastProgress(scanID, "Initializing Ensemble", 1)

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
	if ctx.Err() != nil {
		return
	}
	wsHub.BroadcastProgress(scanID, "Scanning Files", 3)
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

	// ════════════════════════════════════════════════════════
	//  PHASE 1: STATIC EXPERT (0-40%)
	// ════════════════════════════════════════════════════════
	if ctx.Err() != nil {
		return
	}
	wsHub.BroadcastLog(scanID, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "phase")
	wsHub.BroadcastLog(scanID, "📊 PHASE 1: Static Expert Scan", "phase")
	wsHub.BroadcastLog(scanID, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "phase")

	var staticFindings []reporter.Finding

	// Pattern Scan
	wsHub.BroadcastProgress(scanID, "Phase 1: Pattern Matching", 5)
	wsHub.BroadcastLog(scanID, "Running pattern engine...", "info")
	patternFindings := scanner.RunPatternScan(result, rules, rulesDir)
	for i := range patternFindings {
		patternFindings[i].Confidence = 0.70
	}
	staticFindings = append(staticFindings, patternFindings...)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Pattern engine found %d issues", len(patternFindings)), "info")

	// AST Analysis
	wsHub.BroadcastProgress(scanID, "Phase 1: AST Analysis", 8)
	wsHub.BroadcastLog(scanID, "Running AST analyzer...", "info")
	astAnalyzer := scanner.NewASTAnalyzer()
	for _, files := range result.FilePaths {
		for _, file := range files {
			findings, err := astAnalyzer.AnalyzeFile(file)
			if err == nil {
				staticFindings = append(staticFindings, findings...)
			}
		}
	}

	// Taint Analysis
	wsHub.BroadcastProgress(scanID, "Phase 1: Taint Analysis", 12)
	wsHub.BroadcastLog(scanID, "Running taint analyzer...", "info")
	taintAnalyzer := scanner.NewTaintAnalyzer()
	for _, files := range result.FilePaths {
		for _, file := range files {
			findings, err := taintAnalyzer.AnalyzeTaintFlow(file)
			if err == nil {
				staticFindings = append(staticFindings, findings...)
			}
		}
	}

	// Secret Detection
	wsHub.BroadcastProgress(scanID, "Phase 1: Secret Detection", 16)
	wsHub.BroadcastLog(scanID, "Scanning for hardcoded secrets...", "info")
	secretDetector := scanner.NewSecretDetector()
	secretFindings, err := secretDetector.ScanSecrets(targetDir)
	if err == nil {
		staticFindings = append(staticFindings, secretFindings...)
	}

	// Dependency Scan
	wsHub.BroadcastProgress(scanID, "Phase 1: Dependency Scan", 20)
	wsHub.BroadcastLog(scanID, "Checking vulnerable dependencies...", "info")
	depFindings, err := scanner.ScanDependencies(ctx, targetDir)
	if err == nil {
		staticFindings = append(staticFindings, depFindings...)
	}

	// Semgrep
	wsHub.BroadcastProgress(scanID, "Phase 1: Semgrep Analysis", 24)
	wsHub.BroadcastLog(scanID, "Running Semgrep analysis...", "info")
	semgrepFindings, err := scanner.RunSemgrep(ctx, targetDir)
	if err == nil {
		staticFindings = append(staticFindings, semgrepFindings...)
	}

	// Supply Chain
	wsHub.BroadcastProgress(scanID, "Phase 1: Supply Chain", 28)
	wsHub.BroadcastLog(scanID, "Running supply chain security checks...", "info")
	supplyChainScanner := scanner.NewSupplyChainScanner()
	scFindings, err := supplyChainScanner.ScanSupplyChain(ctx, targetDir)
	if err == nil {
		staticFindings = append(staticFindings, scFindings...)
	}

	// OSV SCA
	if scanner.CheckOSVCliInstalled() {
		wsHub.BroadcastProgress(scanID, "Phase 1: OSV SCA Scan", 30)
		osvFindings, osvErr := scanner.RunOSVCli(ctx, targetDir)
		if osvErr == nil && len(osvFindings) > 0 {
			staticFindings = append(staticFindings, osvFindings...)
		}
	}

	// Container Scanning
	wsHub.BroadcastProgress(scanID, "Phase 1: Container Scanning", 32)
	wsHub.BroadcastLog(scanID, "Scanning Dockerfiles & Kubernetes manifests...", "info")
	containerScanner := scanner.NewContainerScanner(int64(len(staticFindings) + 1000))
	containerFindings, cErr := containerScanner.ScanContainers(targetDir)
	if cErr == nil {
		staticFindings = append(staticFindings, containerFindings...)
	}

	// Threat Intel Enrichment
	wsHub.BroadcastProgress(scanID, "Phase 1: Threat Intelligence", 35)
	wsHub.BroadcastLog(scanID, "Enriching with threat intelligence...", "info")
	threatIntelScanner := scanner.NewThreatIntelScanner()
	enrichedFindings, tiErr := threatIntelScanner.ScanWithThreatIntel(staticFindings)
	if tiErr == nil {
		staticFindings = enrichedFindings
	}

	// Reachability Analysis
	wsHub.BroadcastProgress(scanID, "Phase 1: Reachability Analysis", 37)
	reachAnalyzer := scanner.NewReachabilityAnalyzer()
	if raErr := reachAnalyzer.BuildCallGraph(targetDir); raErr == nil {
		staticFindings = reachAnalyzer.AnnotateFindings(staticFindings)
	}

	// Deduplicate Phase 1
	staticFindings = webDeduplicateFindings(staticFindings)

	wsHub.BroadcastProgress(scanID, "Phase 1: Complete", 40)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("✅ Phase 1 Complete: Static Expert found %d findings", len(staticFindings)), "success")

	// Save Report A to DB
	wsHub.BroadcastLog(scanID, "Saving Static Report (Report A) to database...", "info")
	if err := SaveFindingsWithPhase(scanID, staticFindings, "static"); err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Failed to save static findings: %v", err), "error")
	}

	// ════════════════════════════════════════════════════════
	//  PHASE 2: AI EXPERT (40-75%)
	// ════════════════════════════════════════════════════════
	if ctx.Err() != nil {
		return
	}
	wsHub.BroadcastLog(scanID, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "phase")
	wsHub.BroadcastLog(scanID, "🤖 PHASE 2: AI Expert Scan", "phase")
	wsHub.BroadcastLog(scanID, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "phase")

	modelName := cfg.AIModel
	if modelName == "" {
		modelName = ai.GetDefaultModel()
	}

	wsHub.BroadcastProgress(scanID, "Phase 2: AI Discovery", 45)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Running AI Discovery with model: %s", modelName), "info")
	wsHub.BroadcastLog(scanID, "AI is independently scanning all supported files...", "info")
	aiFindings := ai.RunAIDiscovery(ctx, modelName, targetDir)

	// AI self-validation of its own findings
	if len(aiFindings) > 0 {
		wsHub.BroadcastProgress(scanID, "Phase 2: AI Self-Validation", 65)
		wsHub.BroadcastLog(scanID, fmt.Sprintf("AI validating its own %d discoveries...", len(aiFindings)), "info")

		fileContents := make(map[string]string)
		for _, files := range result.FilePaths {
			for _, file := range files {
				if data, err := os.ReadFile(file); err == nil {
					fileContents[file] = string(data)
				}
			}
		}
		aiFindings = ai.ValidateFindingsBatch(ctx, modelName, aiFindings, fileContents, 4)
	}

	// Deduplicate Phase 2
	aiFindings = webDeduplicateFindings(aiFindings)

	wsHub.BroadcastProgress(scanID, "Phase 2: Complete", 75)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("✅ Phase 2 Complete: AI Expert found %d findings", len(aiFindings)), "success")

	// Save Report B to DB
	wsHub.BroadcastLog(scanID, "Saving AI Report (Report B) to database...", "info")
	if err := SaveFindingsWithPhase(scanID, aiFindings, "ai"); err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Failed to save AI findings: %v", err), "error")
	}

	// ════════════════════════════════════════════════════════
	//  PHASE 3: JUDGE LLM (75-95%)
	// ════════════════════════════════════════════════════════
	if ctx.Err() != nil {
		return
	}
	wsHub.BroadcastLog(scanID, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "phase")
	wsHub.BroadcastLog(scanID, "⚖️  PHASE 3: AI Judge — Merging Reports", "phase")
	wsHub.BroadcastLog(scanID, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "phase")

	judgeModel := cfg.JudgeModel
	if judgeModel == "" {
		judgeModel = cfg.ConsolidationModel
	}
	if judgeModel == "" {
		judgeModel = ai.GetDefaultModel()
	}

	wsHub.BroadcastProgress(scanID, "Phase 3: Judge Review", 80)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Judge LLM (%s) reviewing %d static + %d AI findings...",
		judgeModel, len(staticFindings), len(aiFindings)), "info")

	var allFindings []reporter.Finding

	masterFindings, judgeErr := ai.JudgeFindings(ctx, staticFindings, aiFindings, judgeModel, cfg.JudgeOllamaHost)
	if judgeErr != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Judge failed: %v — falling back to simple merge", judgeErr), "warning")
		// Fallback: combine both reports and deduplicate
		allFindings = append(staticFindings, aiFindings...)
		allFindings = webDeduplicateFindings(allFindings)
	} else {
		allFindings = masterFindings
		wsHub.BroadcastLog(scanID, fmt.Sprintf("⚖️  Judge verdict: %d final findings", len(allFindings)), "success")
	}

	wsHub.BroadcastProgress(scanID, "Phase 3: Finalizing", 90)

	// ── ML False Positive Reduction (if enabled) ─────────────
	if cfg.EnableMLFPReduction {
		wsHub.BroadcastLog(scanID, "Applying ML-based False Positive reduction...", "info")
		reducer := ai.NewMLFPReducer(".qwen-ml-cache")
		reducer.LoadHistory()
		allFindings = reducer.FilterFindingsByFPProbability(allFindings, 0.8)
		reducer.SaveHistory()
		wsHub.BroadcastLog(scanID, "ML False Positive reduction complete", "info")
	}

	// ── Finalize ──────────────────────────────────────────────

	// FP Suppression: check code context for safe patterns
	wsHub.BroadcastLog(scanID, "Suppressing false positives on safe patterns...", "phase")
	allFindings = scanner.SuppressFalsePositives(allFindings, targetDir)

	// Severity Recalibration + UNREACHABLE fix
	wsHub.BroadcastLog(scanID, "Recalibrating severities...", "phase")
	allFindings = recalibrateSeverities(allFindings, targetDir)

	// Sort by severity
	severityOrder := map[string]int{
		"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
	}
	sort.Slice(allFindings, func(i, j int) bool {
		return severityOrder[allFindings[i].Severity] > severityOrder[allFindings[j].Severity]
	})

	// Renumber and Calculate Trust Score
	for i := range allFindings {
		allFindings[i].SrNo = i + 1

		engines := strings.Split(allFindings[i].Source, ", ")
		baseScore := allFindings[i].Confidence * 100.0
		if len(engines) > 1 {
			baseScore += float64(len(engines)-1) * 15.0
		}
		if allFindings[i].AiValidated == "Yes" {
			baseScore += 10.0
		}
		if baseScore > 100 {
			baseScore = 100
		}
		allFindings[i].TrustScore = baseScore
	}

	// Populate code snippets
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

	criticalCount := riskScore.CriticalCount
	highCount := riskScore.HighCount

	// Save Final Master Report
	wsHub.BroadcastProgress(scanID, "Saving Master Report", 93)
	wsHub.BroadcastLog(scanID, "Saving Final Master Report to database...", "info")
	if err := SaveFindingsWithPhase(scanID, allFindings, "final"); err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Failed to save final findings: %v", err), "error")
	}
	if err := UpdateScanCounts(scanID, len(allFindings), criticalCount, highCount); err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Failed to update scan counts: %v", err), "error")
	}
	if err := UpdateScanStatus(scanID, "completed"); err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Failed to update scan status: %v", err), "error")
	}

	// Generate report files
	wsHub.BroadcastLog(scanID, "Generating reports (CSV, HTML, PDF)...", "info")
	webGenerateReportFiles(scanID, allFindings, targetDir)

	elapsed := time.Since(startTime)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("✅ Ensemble Audit completed in %s — %d master findings (%d critical, %d high) — Risk: %d/100 (%s)",
		elapsed.Round(time.Second), len(allFindings), criticalCount, highCount, riskScore.Score, riskScore.Level), "success")
	wsHub.BroadcastLog(scanID, fmt.Sprintf("📊 Report Breakdown: %d static (Phase 1) + %d AI (Phase 2) → %d final (Judge)",
		len(staticFindings), len(aiFindings), len(allFindings)), "info")

	wsHub.BroadcastProgress(scanID, "Complete", 100)
	wsHub.Broadcast(scanID, WSMessage{Type: "findings_update", Count: len(allFindings)})
	wsHub.BroadcastComplete(scanID)
}
