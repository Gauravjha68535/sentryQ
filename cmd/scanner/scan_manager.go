package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"SentryQ/ai"
	"SentryQ/config"
	"SentryQ/reporter"
	"SentryQ/scanner"
	"SentryQ/utils"
)

// WebScanConfig mirrors the frontend config toggles
// 3 modes:
// - EnableDeepScan: deps + semgrep + supply chain + compliance + threat intel
// - EnableAI: AI validation + AI discovery + consolidated merge
// - EnableEnsemble: Full static scan (Report A) + Full AI scan (Report B) + Judge LLM merge
// Secret detection, pattern scan, AST, and taint analysis run ALWAYS.
type WebScanConfig struct {
	EnableDeepScan          bool     `json:"enableDeepScan"`
	EnableAI                bool     `json:"enableAI"`
	EnableEnsemble          bool     `json:"enableEnsemble"`
	AIModel                 string   `json:"aiModel"`
	OllamaHost              string   `json:"ollamaHost"`
	ConsolidationModel      string   `json:"consolidationModel"`
	ConsolidationOllamaHost string   `json:"consolidationOllamaHost"`
	JudgeModel              string   `json:"judgeModel"`
	JudgeOllamaHost         string   `json:"judgeOllamaHost"`
	EnableMLFPReduction     bool     `json:"enableMLFPReduction"`
	CustomRulesDir          string   `json:"customRulesDir"`
	// ChangedFiles, when non-empty, restricts scanning to only these absolute paths.
	ChangedFiles            []string `json:"changedFiles,omitempty"`
	// Policy gates — evaluated after scan completion.
	// PolicyFailOn is the minimum severity that causes a policy violation ("critical", "high", "medium", "low").
	// Empty string means no severity-based policy gate.
	PolicyFailOn string `json:"policyFailOn"`
	// MaxCritical is the maximum number of critical findings allowed (-1 = no limit).
	MaxCritical int `json:"maxCritical"`
	// MaxHigh is the maximum number of high findings allowed (-1 = no limit).
	MaxHigh int `json:"maxHigh"`
	// MaxMedium is the maximum number of medium findings allowed (-1 = no limit).
	MaxMedium int `json:"maxMedium"`
	// MaxLow is the maximum number of low findings allowed (-1 = no limit).
	MaxLow int `json:"maxLow"`
	// MaxTotal is the maximum total findings allowed (-1 = no limit).
	MaxTotal int `json:"maxTotal"`
	// WebhookURLs is a comma-separated list of webhook endpoint URLs to notify on scan completion.
	WebhookURLs string `json:"webhookUrls"`
	// PR/MR decoration fields.
	PRProvider string `json:"prProvider"`
	PRToken    string `json:"prToken"`
	PRRepo     string `json:"prRepo"`
	PRNumber   int    `json:"prNumber"`
	MRiid      int    `json:"mrIid"`
	// IncrementalScan, when true, restricts scanning to files changed relative to BaseBranch.
	IncrementalScan bool   `json:"incrementalScan"`
	BaseBranch      string `json:"baseBranch"`
}

var (
	activeScans   = make(map[string]context.CancelFunc)
	activeScansMu sync.Mutex
)


// runScan is the core scan orchestration (runs in a goroutine)
func runScan(ctx context.Context, scanID string, targetDir string, cfg WebScanConfig) {
	registerPauseControl(scanID)
	defer unregisterPauseControl(scanID)

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

	rulesDir := getDefaultRulesDir()
	if cfg.CustomRulesDir != "" {
		rulesDir = cfg.CustomRulesDir
	}

	// Walk directory first so we know which languages are present
	wsHub.BroadcastProgress(scanID, "Scanning Files", 10)
	wsHub.BroadcastLog(scanID, "Walking target directory...", "info")
	if ctx.Err() != nil {
		return
	}
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
	patternFindings := scanner.RunPatternScan(ctx, result, rules, rulesDir)
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
			if ctx.Err() != nil {
				break
			}
			findings, err := astAnalyzer.AnalyzeFile(ctx, file)
			if err != nil {
				utils.LogWarn(fmt.Sprintf("AST analysis failed for %s: %v", file, err))
				continue
			}
			allFindings = append(allFindings, findings...)
		}
	}
	wsHub.BroadcastLog(scanID, fmt.Sprintf("AST analysis complete (%d total findings so far)", len(allFindings)), "info")

	// Taint Analysis (always)
	if ctx.Err() != nil {
		return
	}
	wsHub.BroadcastProgress(scanID, "Taint Analysis", 40)
	wsHub.BroadcastLog(scanID, "Running taint analyzer (building cross-file index)...", "phase")
	taintAnalyzer := scanner.NewTaintAnalyzer()
	crossFileIdx := taintAnalyzer.BuildCrossFileIndex(targetDir)
	utils.LogInfo(fmt.Sprintf("Cross-file taint index: %d tainted functions indexed", len(crossFileIdx.TaintedFunctions)))
	for _, files := range result.FilePaths {
		if ctx.Err() != nil {
			return
		}
		for _, file := range files {
			if ctx.Err() != nil {
				return
			}
			findings, err := taintAnalyzer.AnalyzeTaintFlowWithIndex(file, crossFileIdx)
			if err == nil {
				allFindings = append(allFindings, findings...)
			} else {
				utils.LogWarn(fmt.Sprintf("Taint analysis failed for %s: %v", file, err))
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
	} else {
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Secret detection error: %v", err), "warning")
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

		// Container Scanning (now part of Deep Scan)
		wsHub.BroadcastProgress(scanID, "Container Scanning", 62)
		wsHub.BroadcastLog(scanID, "Scanning Dockerfiles & Kubernetes manifests...", "phase")
		containerScanner := scanner.NewContainerScanner(int64(len(allFindings) + 1000))
		containerFindings, cErr := containerScanner.ScanContainers(targetDir, ctx)
		if cErr == nil {
			allFindings = append(allFindings, containerFindings...)
			wsHub.BroadcastLog(scanID, fmt.Sprintf("Container scan found %d issues", len(containerFindings)), "info")
		} else {
			wsHub.BroadcastLog(scanID, fmt.Sprintf("Container scan failed: %v", cErr), "warning")
		}

		// Threat Intelligence Enrichment (now part of Deep Scan)
		wsHub.BroadcastProgress(scanID, "Threat Intelligence", 63)
		wsHub.BroadcastLog(scanID, "Enriching findings with threat intelligence (MITRE ATT&CK)...", "phase")
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

	if !checkPause(scanID, ctx) {
		return
	}

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
		consolidationModel = cfg.JudgeModel // Treat JudgeModel as alias for ConsolidationModel
	}
	if consolidationModel == "" {
		consolidationModel = ai.GetDefaultModel() // Heavy default fallback
	}

	if cfg.EnableAI {
		if !checkPause(scanID, ctx) {
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

		const maxTotalFileContentsStd = 512 * 1024 * 1024 // 512 MB cumulative cap (same as ensemble)
		fileContents := make(map[string]string)
		var cumulativeSizeStd int64
		for _, files := range result.FilePaths {
			for _, file := range files {
				info, statErr := os.Stat(file)
				if statErr != nil || info.Size() > maxFileContentSize {
					continue
				}
				if cumulativeSizeStd+info.Size() > maxTotalFileContentsStd {
					utils.LogWarn("fileContents map reached 512 MB cumulative cap — skipping remaining files for AI context")
					break
				}
				if data, err := os.ReadFile(file); err == nil {
					fileContents[file] = string(data)
					cumulativeSizeStd += info.Size()
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
		// Pre-AI suppression: avoids sending obvious FPs (safe patterns, test files)
		// to the expensive AI validation step. A second pass runs post-AI at line ~879
		// to catch any regressions introduced by AI-phase merging.
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
		validatedFindings := ai.ValidateFindingsBatch(ctx, modelName, uniqueForValidation, fileContents, func(msg string, level string) {
			wsHub.BroadcastLog(scanID, msg, level)
		})

		// Split back into static and ai findings (merger expects them separate for now)
		var validatedStatic []reporter.Finding
		var validatedAI []reporter.Finding
		for _, f := range validatedFindings {
			if f.AiValidated == "No (False Positive)" || f.AiValidated == "Error" {
				// Drop findings explicitly rejected by AI or that had a validation API error
				continue
			}
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
			// JudgeOllamaHost takes precedence; fall back to ConsolidationOllamaHost
			judgeHost := cfg.JudgeOllamaHost
			if judgeHost == "" {
				judgeHost = cfg.ConsolidationOllamaHost
			}
			if judgeHost != "" {
				wsHub.BroadcastLog(scanID, fmt.Sprintf("Using Judge Ollama Host: %s", judgeHost), "info")
			}

			wsHub.BroadcastProgress(scanID, "AI Consolidation", 85)
			wsHub.BroadcastLog(scanID, fmt.Sprintf("Consolidating static + AI findings using Judge LLM: %s...", consolidationModel), "phase")

			// Use the more robust JudgeFindings engine
			merged, err := ai.JudgeFindings(ctx, allFindings, aiFindings, consolidationModel, judgeHost)
			if err == nil {
				allFindings = merged
				wsHub.BroadcastLog(scanID, "Consolidation complete", "success")
			} else {
				allFindings = append(allFindings, aiFindings...)
				wsHub.BroadcastLog(scanID, fmt.Sprintf("Consolidation failed, using simple merge: %v", err), "warning")
			}
		}
	}

	// ── Post-Judge Cleanup: Drop explicitly rejected findings ───────
	// Only drop findings the AI validator explicitly marked as false positives.
	// Plain "No" (default for unprocessed static findings) must NOT be dropped
	// here because the Judge has already made the final keep/reject decision.
	if cfg.EnableAI {
		var cleanFindings []reporter.Finding
		droppedCount := 0
		for _, f := range allFindings {
			if f.AiValidated == "No (False Positive)" {
				droppedCount++
				continue
			}
			cleanFindings = append(cleanFindings, f)
		}
		if droppedCount > 0 {
			wsHub.BroadcastLog(scanID, fmt.Sprintf("Post-Judge cleanup: dropped %d false-positive findings", droppedCount), "info")
		}
		allFindings = cleanFindings
	}

	// ── Confidence Calibration (always after AI) ────────────
	// NOTE: batch_validator already creates a ConfidenceCalibrator, records
	// validation outcomes, and calls SaveStats(). Creating a second fresh
	// calibrator here and calling SaveStats() again would overwrite those
	// learned stats with zeroes. We only call ApplyCalibrationToFindings so
	// the saved stats (learned during batch validation) are applied to the
	// final merged findings — no SaveStats() call here.
	if cfg.EnableAI {
		wsHub.BroadcastLog(scanID, "Applying confidence calibration...", "info")
		calibrator := ai.NewConfidenceCalibrator()
		allFindings = calibrator.ApplyCalibrationToFindings(allFindings)
	}

	// ── ML False Positive Reduction (if enabled) ─────────────
	if cfg.EnableMLFPReduction {
		wsHub.BroadcastProgress(scanID, "ML FP Reduction", 87)
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
	webGenerateReportFiles(scanID, allFindings, targetDir, cfg)

	// ── Policy Gate Evaluation ─────────────────────────────────
	evaluatePolicyGate(scanID, cfg, allFindings, criticalCount, highCount)

	// ── Fire webhooks (per-scan config first, then global settings) ──
	// Per-scan webhook URLs (from config) take priority; fall back to global settings.
	webhookURLs := cfg.WebhookURLs
	if webhookURLs == "" {
		appSettings.RLock()
		webhookURLs = appSettings.WebhookURLs
		appSettings.RUnlock()
	}
	if webhookURLs != "" {
		FireWebhooks(strings.Split(webhookURLs, ","), scanID, targetDir, "completed", allFindings, nil)
	}

	// ── PR/MR Decoration ─────────────────────────────────────────
	if cfg.PRProvider != "" {
		prCfg := PRConfig{
			Provider: cfg.PRProvider,
			Token:    cfg.PRToken,
			Repo:     cfg.PRRepo,
			PRNumber: cfg.PRNumber,
			MRID:     cfg.MRiid,
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("Decorating %s PR/MR with findings...", cfg.PRProvider), "info")
		go DecoratePR(prCfg, scanID, allFindings)
	}

	elapsed := time.Since(startTime)
	wsHub.BroadcastLog(scanID, fmt.Sprintf("✅ Scan completed in %s — %d findings (%d critical, %d high) — Risk: %d/100 (%s)",
		elapsed.Round(time.Second), len(allFindings), criticalCount, highCount, riskScore.Score, riskScore.Level), "success")

	wsHub.BroadcastProgress(scanID, "Complete", 100)
	wsHub.Broadcast(scanID, WSMessage{Type: "findings_update", Count: len(allFindings)})
	wsHub.BroadcastComplete(scanID)
}

