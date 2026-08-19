package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"SentryQ/ai"
	"SentryQ/config"
	"SentryQ/reporter"
	"SentryQ/scanner"
	"SentryQ/utils"
)

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

	rulesDir := getDefaultRulesDir()
	if cfg.CustomRulesDir != "" {
		rulesDir = cfg.CustomRulesDir
	}

	// Walk directory first so we know which languages are present
	if ctx.Err() != nil {
		return
	}
	wsHub.BroadcastProgress(scanID, "Scanning Files", 3)
	wsHub.BroadcastLog(scanID, "Walking target directory...", "info")
	result, err := scanner.WalkDirectory(targetDir)
	if err != nil {
		wsHub.BroadcastError(scanID, fmt.Sprintf("Failed to walk directory: %v", err))
		if err := UpdateScanStatus(scanID, "failed"); err != nil {
			utils.LogError(fmt.Sprintf("Failed to mark scan %s as failed", scanID), err)
		}
		return
	}
	totalFiles := 0
	for _, files := range result.FilePaths {
		totalFiles += len(files)
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Found %d files across %d languages", totalFiles, len(result.FilePaths)), "success")

	// Load only rules relevant to the detected languages
	detectedLangs := make(map[string]bool)
	for lang := range result.FilePaths {
		detectedLangs[lang] = true
	}
	rules, err := config.LoadRulesForLanguages(rulesDir, detectedLangs)
	if err != nil {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Warning: Failed to load rules: %v", err), "warning")
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Loaded %d rules for %d detected language(s)", len(rules), len(detectedLangs)), "info")

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
	patternFindings := scanner.RunPatternScan(ctx, result, rules, rulesDir)
	staticFindings = append(staticFindings, patternFindings...)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("Pattern engine found %d issues", len(patternFindings)), "info")

	// AST Analysis
	wsHub.BroadcastProgress(scanID, "Phase 1: AST Analysis", 8)
	wsHub.BroadcastLog(scanID, "Running AST analyzer...", "info")
	astAnalyzer := scanner.NewASTAnalyzer()
	for _, files := range result.FilePaths {
		for _, file := range files {
			if ctx.Err() != nil {
				break
			}
			findings, err := astAnalyzer.AnalyzeFile(ctx, file)
			if err != nil {
				utils.LogWarn(fmt.Sprintf("AST analysis failed for %s: %v", file, err))
				continue
			}
			staticFindings = append(staticFindings, findings...)
		}
	}

	// Taint Analysis with cross-file index
	wsHub.BroadcastProgress(scanID, "Phase 1: Taint Analysis", 12)
	wsHub.BroadcastLog(scanID, "Running taint analyzer (cross-file mode)...", "info")
	taintAnalyzer := scanner.NewTaintAnalyzer()
	crossIdx := taintAnalyzer.BuildCrossFileIndex(targetDir)
	utils.LogInfo(fmt.Sprintf("Cross-file taint index: %d functions indexed", len(crossIdx.TaintedFunctions)))
	for _, files := range result.FilePaths {
		for _, file := range files {
			if ctx.Err() != nil {
				break
			}
			findings, err := taintAnalyzer.AnalyzeTaintFlowWithIndex(file, crossIdx)
			if err == nil {
				staticFindings = append(staticFindings, findings...)
			} else {
				utils.LogWarn(fmt.Sprintf("Taint analysis failed for %s: %v", file, err))
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

	// Container Scanning
	wsHub.BroadcastProgress(scanID, "Phase 1: Container Scanning", 32)
	wsHub.BroadcastLog(scanID, "Scanning Dockerfiles & Kubernetes manifests...", "info")
	containerScanner := scanner.NewContainerScanner(int64(len(staticFindings)) + 1)
	containerFindings, cErr := containerScanner.ScanContainers(targetDir, ctx)
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
	if !checkPause(scanID, ctx) {
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
	aiFindings := ai.RunAIDiscovery(ctx, modelName, targetDir, func(msg string, level string) {
		wsHub.BroadcastLog(scanID, msg, level)
	})

	// Build file contents map once — shared by both Phase 2 (AI self-validation)
	// and Phase 3 (static pre-validation). Uses the package-level maxFileContentSize.
	// A cumulative size cap prevents OOM on repositories with many large files.
	const maxTotalFileContents = 512 * 1024 * 1024 // 512 MB cumulative cap
	fileContents := make(map[string]string)
	var cumulativeSize int64
	for _, files := range result.FilePaths {
		for _, file := range files {
			info, statErr := os.Stat(file)
			if statErr != nil || info.Size() > maxFileContentSize {
				continue
			}
			if cumulativeSize+info.Size() > maxTotalFileContents {
				utils.LogWarn("fileContents map reached 512 MB cumulative cap — skipping remaining files")
				goto fileContentsDone
			}
			if data, err := os.ReadFile(file); err == nil {
				fileContents[file] = string(data)
				cumulativeSize += info.Size()
			}
		}
	}
fileContentsDone:

	// AI self-validation of its own findings
	if len(aiFindings) > 0 {
		wsHub.BroadcastProgress(scanID, "Phase 2: AI Self-Validation", 65)
		wsHub.BroadcastLog(scanID, fmt.Sprintf("AI validating its own %d discoveries...", len(aiFindings)), "info")
		aiFindings = ai.ValidateFindingsBatch(ctx, modelName, aiFindings, fileContents, func(msg string, level string) {
			wsHub.BroadcastLog(scanID, msg, level)
		})
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
	if !checkPause(scanID, ctx) {
		return
	}
	wsHub.BroadcastLog(scanID, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "phase")
	wsHub.BroadcastLog(scanID, "⚖️  PHASE 3: AI Judge — Merging Reports", "phase")
	wsHub.BroadcastLog(scanID, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "phase")

	// Pre-Judge: AI Validation for Static Findings (generates remediations and filters FPs).
	// Reuses the fileContents map built above — no second disk read.
	wsHub.BroadcastProgress(scanID, "Phase 3: Static Pre-Validation", 78)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("AI validating %d static discoveries for remediation insights...", len(staticFindings)), "info")
	staticFindings = ai.ValidateFindingsBatch(ctx, modelName, staticFindings, fileContents, func(msg string, level string) {
		wsHub.BroadcastLog(scanID, msg, level)
	})

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
		mlCacheDir := ".sentryq-ml-cache"
		if homeDir, err := os.UserHomeDir(); err == nil {
			mlCacheDir = filepath.Join(homeDir, ".sentryq", "ml-cache")
		}
		reducer := ai.NewFPHistoryCache(mlCacheDir)
		if err := reducer.LoadHistory(); err != nil {
			utils.LogWarn("ML FP reducer: failed to load history: " + err.Error())
		}
		allFindings = reducer.FilterFindingsByFPProbability(allFindings, 0.8)
		// SaveHistory skipped — filter adds no feedback; feedback comes from UI triage
		wsHub.BroadcastLog(scanID, "FP history filter complete", "info")
	}

	// ── Finalize ──────────────────────────────────────────────

	// FP Suppression: check code context for safe patterns
	wsHub.BroadcastLog(scanID, "Suppressing false positives on safe patterns...", "phase")
	allFindings = scanner.SuppressFalsePositives(allFindings, targetDir)

	// Severity Recalibration + UNREACHABLE fix
	wsHub.BroadcastLog(scanID, "Recalibrating severities...", "phase")
	allFindings = recalibrateSeverities(allFindings, targetDir)

	// Final dedup pass after recalibration (severity changes can affect clustering)
	allFindings = webDeduplicateFindings(allFindings)

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
	webGenerateReportFiles(scanID, allFindings, targetDir, cfg)

	elapsed := time.Since(startTime)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("✅ Ensemble Audit completed in %s — %d master findings (%d critical, %d high) — Risk: %d/100 (%s)",
		elapsed.Round(time.Second), len(allFindings), criticalCount, highCount, riskScore.Score, riskScore.Level), "success")
	wsHub.BroadcastLog(scanID, fmt.Sprintf("📊 Report Breakdown: %d static (Phase 1) + %d AI (Phase 2) → %d final (Judge)",
		len(staticFindings), len(aiFindings), len(allFindings)), "info")

	wsHub.BroadcastProgress(scanID, "Complete", 100)
	wsHub.Broadcast(scanID, WSMessage{Type: "findings_update", Count: len(allFindings)})
	wsHub.BroadcastComplete(scanID)
}
