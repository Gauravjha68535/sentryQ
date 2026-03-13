package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"QWEN_SCR_24_FEB_2026/ai"
	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/scanner"
	"QWEN_SCR_24_FEB_2026/utils"

	"github.com/fatih/color"
)

// Shared state for graceful shutdown
var (
	currentFindings  []reporter.Finding
	findingsMu       sync.Mutex
	activeScanConfig *ScanConfig
	interrupted      int32 // atomic flag: 1 = interrupted
)

// parseFlags parses CLI flags and returns a ScanConfig if -d is provided.
// Returns nil if no flags are set (interactive mode).
func parseFlags() *ScanConfig {
	targetDir := flag.String("d", "", "Target directory to scan (required for CLI mode)")
	rulesDir := flag.String("r", "rules", "Path to rules directory")
	enableAI := flag.Bool("ai", false, "Enable AI validation via local LLM")
	enableAIDiscovery := flag.Bool("ai-discovery", false, "Enable AI-powered vulnerability discovery")
	enableSemgrep := flag.Bool("semgrep", false, "Enable Semgrep analysis")
	enableDeps := flag.Bool("deps", true, "Enable dependency scanning")
	enableSecrets := flag.Bool("secrets", true, "Enable secret detection")
	enableSupplyChain := flag.Bool("supply-chain", false, "Enable supply chain security (SBOM)")
	enableCompliance := flag.Bool("compliance", false, "Enable compliance checking")
	enableThreatIntel := flag.Bool("threat-intel", false, "Enable threat intelligence enrichment")
	enableSymbolic := flag.Bool("symbolic", false, "Enable symbolic execution")
	enableMLFP := flag.Bool("ml-fp", false, "Enable ML false-positive reduction")
	enableConsolidation := flag.Bool("consolidated", false, "Enable Consolidated AI + Static intelligence (deduplication mode)")
	// AI Options
	modelName := flag.String("model", ai.GetDefaultModel(), "AI model name for validation")
	ollamaHost := flag.String("ollama-host", "localhost:11434", "Ollama host:port (e.g. 192.168.1.42:11434 for remote)")
	outputCSV := flag.String("csv", "report.csv", "Output CSV report path")
	outputHTML := flag.String("html", "report.html", "Output HTML report path")
	outputPDF := flag.String("pdf", "report.pdf", "Output PDF report path")
	dashPort := flag.Int("port", 8080, "Port for the Web Dashboard")
	frameworks := flag.String("frameworks", "", "Comma-separated compliance frameworks (PCI-DSS,HIPAA,SOC2,ISO27001,GDPR)")

	flag.Parse()

	// If no target directory provided, return nil to trigger interactive mode
	if *targetDir == "" {
		return nil
	}

	// Validate target directory
	if _, err := os.Stat(*targetDir); os.IsNotExist(err) {
		color.Red("✗ Error: Directory does not exist: %s", *targetDir)
		os.Exit(1)
	}

	config := &ScanConfig{
		TargetDir:             *targetDir,
		RulesDir:              *rulesDir,
		EnableAI:              *enableAI,
		EnableAIDiscovery:     *enableAIDiscovery,
		EnableSemgrep:         *enableSemgrep,
		EnableDependencyScan:  *enableDeps,
		EnableSecretDetection: *enableSecrets,
		EnableSupplyChain:     *enableSupplyChain,
		EnableCompliance:      *enableCompliance,
		EnableThreatIntel:     *enableThreatIntel,
		EnableSymbolicExec:    *enableSymbolic,
		EnableMLFPReduction:   *enableMLFP,
		EnableAIConsolidation: *enableConsolidation,
		ModelName:             *modelName,
		OllamaHost:            *ollamaHost,
		OutputCSV:             *outputCSV,
		OutputHTML:            *outputHTML,
		OutputPDF:             *outputPDF,
		DashboardPort:         *dashPort,
		ComplianceFrameworks:  []string{},
	}

	// Parse compliance frameworks
	if *frameworks != "" {
		for _, fw := range splitAndTrim(*frameworks) {
			if fw != "" {
				config.ComplianceFrameworks = append(config.ComplianceFrameworks, fw)
			}
		}
	}

	return config
}

// splitAndTrim splits a comma-separated string and trims whitespace
func splitAndTrim(s string) []string {
	var result []string
	for _, item := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func main() {
	utils.InitLogger()

	// Check for --web flag before normal flag parsing
	for _, arg := range os.Args[1:] {
		if arg == "--web" || arg == "-web" {
			utils.PrintBanner()
			utils.LogInfo("🌐 Starting Web UI mode...")
			StartWebServer(5336)
			return
		}
	}

	// Try CLI flags first; fall back to interactive menu
	config := parseFlags()
	if config == nil {
		config = ShowMainMenu()
	} else {
		utils.PrintBanner()
	}

	// Register graceful shutdown handler
	activeScanConfig = config
	setupGracefulShutdown()

	// Configure Ollama host (for remote AI)
	if config.OllamaHost != "" && config.OllamaHost != "localhost:11434" {
		ai.SetOllamaHost(config.OllamaHost)
		utils.LogInfo(fmt.Sprintf("Using remote Ollama: %s", config.OllamaHost))
	}

	// Start scanning
	utils.LogHeader("🚀 STARTING SECURITY SCAN")
	fmt.Println()

	// Step 1: Walk directory
	utils.LogSubHeader("🔍 Step 1: Scanning Files")
	bar := utils.CreateProgressBar(100, "Analyzing files")

	result, err := scanner.WalkDirectory(config.TargetDir)
	if err != nil {
		utils.LogError("Failed to scan directory", err)
		os.Exit(1)
	}
	bar.Set(100)
	bar.Finish()

	result.DisplayStats()
	fmt.Println()

	var allFindings []reporter.Finding

	if config.EnableStaticPlusAI {
		// ═══ HYBRID MODE: Static scan first, then AI discovery, then validate ALL ═══

		// --- Run Static Engine ---
		utils.LogHeader("📋 STATIC SCANNING (Phase 1 of 3)")
		staticFindings := runStaticEngine(config, result)
		allFindings = append(allFindings, staticFindings...)
		updateFindings(allFindings)
		utils.LogInfo(fmt.Sprintf("Static engine found %d issues", len(staticFindings)))
		fmt.Println()

		// --- Run AI Discovery ---
		utils.LogHeader("🧠 AI VULNERABILITY DISCOVERY (Phase 2 of 3)")
		discoveryFindings := ai.RunAIDiscovery(config.ModelName, config.TargetDir)
		allFindings = append(allFindings, discoveryFindings...)
		updateFindings(allFindings)
		utils.LogInfo(fmt.Sprintf("AI discovered %d additional vulnerabilities", len(discoveryFindings)))
		fmt.Println()

		// --- AI Validation of ALL findings ---
		utils.LogHeader("🤖 AI VALIDATION (Phase 3 of 3)")
		fileContents := loadFileContents(config.TargetDir)
		allFindings = ai.ValidateFindingsBatch(config.ModelName, allFindings, fileContents, 10, config.TargetDir)
		updateFindings(allFindings)

		// Confidence Calibration
		calibrator := ai.NewConfidenceCalibrator(config.TargetDir)
		allFindings = calibrator.ApplyCalibrationToFindings(allFindings)
		calibrator.SaveStats()

		// ML False Positive Reduction (if enabled)
		if config.EnableMLFPReduction {
			utils.LogSubHeader("🧠 ML False Positive Reduction")
			mlReducer := ai.NewMLFPReducer(".scanner-cache")
			mlReducer.LoadHistory()
			allFindings = mlReducer.FilterFindingsByFPProbability(allFindings, 0.7)
			mlReducer.SaveHistory()
			stats := mlReducer.GetFPStatistics()
			utils.LogInfo(fmt.Sprintf("ML FP Rate: %.1f%%", stats["fp_rate"].(float64)*100))
		}
		fmt.Println()

	} else if config.EnableAIConsolidation {
		// ═══ CONSOLIDATED MODE: Static -> Stash -> AI -> Merge ═══
		utils.LogHeader("🧠 CONSOLIDATED AI + STATIC INTELLIGENCE")

		// Phase 1: Static Scan
		utils.LogSubHeader("📋 Phase 1: Static Security Analysis")
		staticFindings := runStaticEngine(config, result)
		utils.LogInfo(fmt.Sprintf("Static engine found %d issues", len(staticFindings)))

		// "Local DB" Stash (JSON)
		stashPath := filepath.Join(config.TargetDir, ".findings_stashed.json")
		stashData, _ := json.MarshalIndent(staticFindings, "", "  ")
		os.WriteFile(stashPath, stashData, 0644)
		utils.LogInfo(fmt.Sprintf("Findings stashed to local DB: %s", stashPath))
		fmt.Println()

		// Phase 2: AI Discovery
		utils.LogSubHeader("🧠 Phase 2: AI Discovery Scan")
		aiDiscoveryFindings := ai.RunAIDiscovery(config.ModelName, config.TargetDir)
		utils.LogInfo(fmt.Sprintf("AI discovered %d vulnerabilities", len(aiDiscoveryFindings)))
		fmt.Println()

		// Phase 3: Semantic Merge
		utils.LogSubHeader("🔄 Phase 3: Semantic Deduplication & Merging")
		mergedFindings, err := ai.ConsolidateFindings(staticFindings, aiDiscoveryFindings, config.ModelName)
		if err != nil {
			utils.LogWarn(fmt.Sprintf("Deduplication failed: %v. Using raw list.", err))
			allFindings = append(staticFindings, aiDiscoveryFindings...)
		} else {
			allFindings = mergedFindings
		}
		updateFindings(allFindings)
		fmt.Println()

	} else if config.EnableAIDiscovery {
		// ═══ AI-ONLY MODE: Skip all static engines, let AI do everything ═══
		utils.LogHeader("🧠 AI VULNERABILITY DISCOVERY")
		discoveryFindings := ai.RunAIDiscovery(config.ModelName, config.TargetDir)
		allFindings = append(allFindings, discoveryFindings...)
		updateFindings(allFindings)
		utils.LogInfo(fmt.Sprintf("AI discovered %d vulnerabilities", len(discoveryFindings)))
		fmt.Println()

		// AI Validation of AI-discovered findings (if option 3 was selected)
		if config.EnableAI {
			utils.LogHeader("🤖 AI VALIDATION")
			fileContents := loadFileContents(config.TargetDir)
			allFindings = ai.ValidateFindingsBatch(config.ModelName, allFindings, fileContents, 10, config.TargetDir)
			updateFindings(allFindings)
			fmt.Println()
		}
	} else {
		// ═══ STATIC ENGINE MODE: Run all traditional scan steps ═══

		// Step 2: Load rules
		utils.LogSubHeader("📋 Step 2: Loading Rules")
		rules, err := config.LoadRules(config.RulesDir)
		if err != nil {
			utils.LogError("Failed to load rules", err)
			os.Exit(1)
		}
		utils.LogInfo(fmt.Sprintf("Loaded %d custom rules", len(rules)))
		fmt.Println()

		// Step 3: Pattern matching
		utils.LogSubHeader("🎯 Step 3: Pattern Matching")
		customBar := utils.CreateProgressBar(100, "Scanning with custom rules")
		customFindings := scanner.RunPatternScan(result, rules, config.RulesDir)
		customBar.Set(100)
		customBar.Finish()
		utils.LogInfo(fmt.Sprintf("Custom rules found %d potential issues", len(customFindings)))
		fmt.Println()

		// Step 3b: AST-based deep analysis
		var astFindings []reporter.Finding
		utils.LogSubHeader("🌳 Step 3b: AST Deep Analysis")
		astBar := utils.CreateProgressBar(100, "AST analysis (Python/JS/Java/Kotlin)")
		astFindings, astErr := scanner.ScanWithAST(config.TargetDir)
		astBar.Set(100)
		astBar.Finish()
		if astErr != nil {
			utils.LogError("AST analysis failed", astErr)
		} else {
			utils.LogInfo(fmt.Sprintf("AST analysis found %d vulnerabilities", len(astFindings)))
		}
		fmt.Println()

		// Step 4: Semgrep (if enabled)
		var semgrepFindings []reporter.Finding
		if config.EnableSemgrep {
			utils.LogSubHeader("🔍 Step 4: Semgrep Analysis")
			semgrepBar := utils.CreateProgressBar(100, "Running Semgrep")
			semgrepFindings, err = scanner.RunSemgrep(config.TargetDir)
			semgrepBar.Set(100)
			semgrepBar.Finish()
			if err != nil {
				utils.LogError("Semgrep scan failed", err)
			}
			fmt.Println()
		}

		// Step 5: Dependency scanning (if enabled)
		var depFindings []reporter.Finding
		if config.EnableDependencyScan {
			utils.LogSubHeader("📦 Step 5: Dependency Scanning")
			depFindings, err = scanner.ScanDependencies(config.TargetDir)
			if err != nil {
				utils.LogError("Dependency scan failed", err)
			} else {
				utils.LogInfo(fmt.Sprintf("Found %d dependency vulnerabilities", len(depFindings)))
			}
			fmt.Println()
		}

		// Step 6: Secret detection (if enabled)
		var secretFindings []reporter.Finding
		if config.EnableSecretDetection {
			utils.LogSubHeader("🔑 Step 6: Secret Detection")
			secretDetector := scanner.NewSecretDetector()
			secretFindings, err = secretDetector.ScanSecrets(config.TargetDir)
			if err != nil {
				utils.LogError("Secret scan failed", err)
			} else {
				utils.LogInfo(fmt.Sprintf("Found %d hardcoded secrets", len(secretFindings)))
			}
			fmt.Println()
		}

		// Step 7: Supply chain security (if enabled)
		var supplyChainFindings []reporter.Finding
		if config.EnableSupplyChain {
			utils.LogSubHeader("⛓️ Step 7: Supply Chain Security")
			supplyChainScanner := scanner.NewSupplyChainScanner()
			supplyChainFindings, err = supplyChainScanner.ScanSupplyChain(config.TargetDir)
			if err != nil {
				utils.LogError("Supply chain scan failed", err)
			} else {
				utils.LogInfo(fmt.Sprintf("Found %d supply chain issues", len(supplyChainFindings)))
				sbomPath := "sbom.json"
				err = supplyChainScanner.GenerateSBOMFile(sbomPath)
				if err != nil {
					utils.LogError("Failed to generate SBOM", err)
				} else {
					utils.LogInfo(fmt.Sprintf("SBOM generated: %s", sbomPath))
				}
			}
			fmt.Println()
		}

		// Step 8: Taint / Data Flow Analysis (if enabled)
		var taintFindings []reporter.Finding
		if config.EnableSymbolicExec {
			utils.LogSubHeader("🔮 Step 8: Taint / Data Flow Analysis")
			taintBar := utils.CreateProgressBar(100, "Tracking user input → dangerous sinks")
			var taintErr error
			taintFindings, taintErr = scanner.ScanTaintFlows(config.TargetDir)
			taintBar.Set(100)
			taintBar.Finish()
			if taintErr != nil {
				utils.LogError("Taint analysis failed", taintErr)
			} else {
				utils.LogInfo(fmt.Sprintf("Taint analysis found %d injection flows", len(taintFindings)))
			}
			fmt.Println()
		}

		// Step 8a: Container Image Scanning (if enabled)
		var containerFindings []reporter.Finding
		if config.EnableContainerScan {
			utils.LogSubHeader("🐳 Step 8a: Container Image Scanning")
			containerScanner := scanner.NewContainerScanner(int64(len(allFindings) + 1000))
			var cErr error
			containerFindings, cErr = containerScanner.ScanContainers(config.TargetDir)
			if cErr != nil {
				utils.LogError("Container scan failed", cErr)
			} else {
				utils.LogInfo(fmt.Sprintf("Found %d container configuration issues", len(containerFindings)))
			}
			fmt.Println()
		}

		// Step 9: Merge all findings
		utils.LogSubHeader("🔄 Deduplication")
		allFindings = mergeAndDeduplicate(customFindings, semgrepFindings)
		allFindings = append(allFindings, astFindings...)
		allFindings = append(allFindings, depFindings...)
		allFindings = append(allFindings, secretFindings...)
		allFindings = append(allFindings, supplyChainFindings...)
		allFindings = append(allFindings, taintFindings...)
		allFindings = append(allFindings, containerFindings...)
		utils.LogInfo(fmt.Sprintf("Total unique findings: %d", len(allFindings)))
		updateFindings(allFindings)
		fmt.Println()

		// AI Validation only (if enabled but NOT AI Discovery mode)
		if config.EnableAI {
			utils.LogHeader("🤖 AI VALIDATION")
			fileContents := loadFileContents(config.TargetDir)
			allFindings = ai.ValidateFindingsBatch(config.ModelName, allFindings, fileContents, 10, config.TargetDir)
			updateFindings(allFindings)

			if config.EnableMLFPReduction {
				utils.LogSubHeader("🧠 ML False Positive Reduction")
				mlReducer := ai.NewMLFPReducer(".scanner-cache")
				mlReducer.LoadHistory()
				allFindings = mlReducer.FilterFindingsByFPProbability(allFindings, 0.7)
				mlReducer.SaveHistory()
				stats := mlReducer.GetFPStatistics()
				utils.LogInfo(fmt.Sprintf("ML FP Rate: %.1f%%", stats["fp_rate"].(float64)*100))
			}

			// Confidence Calibration
			calibrator := ai.NewConfidenceCalibrator(config.TargetDir)
			allFindings = calibrator.ApplyCalibrationToFindings(allFindings)
			calibrator.SaveStats()

			fmt.Println()
		}
	}

	// Step 11: Threat Intelligence (if enabled)
	if config.EnableThreatIntel {
		utils.LogSubHeader("🌐 Threat Intelligence Enrichment")
		threatIntelScanner := scanner.NewThreatIntelScanner()
		allFindings, err = threatIntelScanner.ScanWithThreatIntel(allFindings)
		if err != nil {
			utils.LogError("Threat intel enrichment failed", err)
		} else {
			threatReport := threatIntelScanner.GenerateThreatIntelReport(allFindings)
			utils.LogInfo(fmt.Sprintf("CVE Findings: %v", threatReport["cve_findings"]))
			utils.LogInfo(fmt.Sprintf("MITRE ATT&CK Mappings: %v", threatReport["mitre_techniques"]))
		}
		fmt.Println()
	}

	// Step 12: Compliance Checking (if enabled)
	var complianceReports []*reporter.ComplianceReport
	if config.EnableCompliance && len(config.ComplianceFrameworks) > 0 {
		utils.LogSubHeader("📋 Compliance Automation")
		complianceReporter := reporter.NewComplianceReporter()

		for _, framework := range config.ComplianceFrameworks {
			err = complianceReporter.LoadFramework(framework)
			if err != nil {
				utils.LogError(fmt.Sprintf("Failed to load %s framework", framework), err)
				continue
			}

			complianceReporter.MapFindingsToControls(allFindings, framework)
			report, err := complianceReporter.GenerateComplianceReport(framework)
			if err != nil {
				utils.LogError(fmt.Sprintf("Failed to generate %s report", framework), err)
				continue
			}

			complianceReports = append(complianceReports, report)
			reportPath := fmt.Sprintf("compliance-%s.json", framework)
			err = complianceReporter.ExportComplianceReport(report, reportPath)
			if err != nil {
				utils.LogError(fmt.Sprintf("Failed to export %s report", framework), err)
			} else {
				utils.LogInfo(fmt.Sprintf("%s Compliance Score: %.1f%%", framework, report.ComplianceScore))
			}
		}
		fmt.Println()
	}

	// Step 12.1: Software Composition Analysis — OSV.dev (if supply chain enabled)
	if config.EnableSupplyChain {
		utils.LogSubHeader("🔎 SCA: OSV.dev Vulnerability Database")
		scaFindings, scaErr := scanner.ScanDependenciesWithOSV(config.TargetDir)
		if scaErr != nil {
			utils.LogError("SCA scan failed", scaErr)
		} else if len(scaFindings) > 0 {
			utils.LogInfo(fmt.Sprintf("Found %d known CVEs in dependencies", len(scaFindings)))
			allFindings = append(allFindings, scaFindings...)
		}
		fmt.Println()
	}

	// Step 12.2: Reachability Analysis — downgrade unreachable findings
	utils.LogSubHeader("🔗 Reachability Analysis")
	reachAnalyzer := scanner.NewReachabilityAnalyzer()
	if err := reachAnalyzer.BuildCallGraph(config.TargetDir); err != nil {
		utils.LogWarn(fmt.Sprintf("Reachability analysis failed: %v", err))
	} else {
		allFindings = reachAnalyzer.AnnotateFindings(allFindings)
	}
	fmt.Println()

	// Step 12.5: Sort all findings by Severity (Critical > High > Medium > Low > Info)
	severityOrder := map[string]int{
		"Critical": 5, "critical": 5, "CRITICAL": 5,
		"High": 4, "high": 4, "HIGH": 4,
		"Medium": 3, "medium": 3, "MEDIUM": 3,
		"Low": 2, "low": 2, "LOW": 2,
		"Info": 1, "info": 1, "INFO": 1,
	}
	sort.Slice(allFindings, func(i, j int) bool {
		return severityOrder[allFindings[i].Severity] > severityOrder[allFindings[j].Severity]
	})

	// Step 13: Assign sequential Sr. No.
	for i := range allFindings {
		allFindings[i].SrNo = i + 1
	}

	// Step 14: Calculate Risk Score
	riskScore := reporter.CalculateRiskScore(allFindings)
	priorityMatrix := reporter.GetPriorityMatrix(allFindings)

	utils.LogInfo(fmt.Sprintf("Security Risk Score: %d/100 (%s)", riskScore.Score, riskScore.Level))
	utils.LogInfo(reporter.GetPrioritySummary(priorityMatrix))
	fmt.Println()

	// Step 14b: Populate code snippets for all findings
	populateCodeSnippets(allFindings)

	// Step 15: Generate Reports
	saveReports(config, allFindings)

	// Print summary
	summary := reporter.GenerateReportSummary(allFindings, config.TargetDir)
	utils.PrintSummary(
		summary.TotalFindings,
		summary.CriticalCount,
		summary.HighCount,
		summary.MediumCount,
		summary.LowCount,
		summary.AIValidatedCount,
	)

	// Print compliance summary
	if len(complianceReports) > 0 {
		fmt.Println()
		color.Cyan("═══════════════════════════════════════════════════════")
		color.White("              📋 COMPLIANCE SUMMARY")
		color.Cyan("═══════════════════════════════════════════════════════")
		fmt.Println()

		for _, report := range complianceReports {
			fmt.Printf("  %s: %.1f%% Compliant (%d/%d controls)\n",
				report.Framework,
				report.ComplianceScore,
				report.CompliantControls,
				report.TotalControls)
		}
		fmt.Println()
	}

	utils.LogHeader("✅ SCAN COMPLETE")
	fmt.Println()

	// Step 16: Start Web Dashboard (if enabled)
	if config.EnableWebDashboard {
		UpdateDashboardFindings(allFindings)

		// Fallback if port was somehow set to 0
		port := config.DashboardPort
		if port <= 0 {
			port = 8080
		}
		StartWebDashboard(port)
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func loadFileContents(targetDir string) map[string]string {
	contents := make(map[string]string)
	result, err := scanner.WalkDirectory(targetDir)
	if err != nil {
		return contents
	}

	for _, files := range result.FilePaths {
		for _, filePath := range files {
			content, err := os.ReadFile(filePath)
			if err == nil {
				contents[filePath] = string(content)
			}
		}
	}

	return contents
}

// populateCodeSnippets reads source files and extracts ~5 lines around each vulnerable line
func populateCodeSnippets(findings []reporter.Finding) {
	fileCache := make(map[string][]string) // filePath → lines

	for i := range findings {
		filePath := findings[i].FilePath
		lineStr := findings[i].LineNumber

		var lineNum int
		fmt.Sscanf(lineStr, "%d", &lineNum)
		if lineNum <= 0 {
			continue
		}

		// Cache file lines
		if _, ok := fileCache[filePath]; !ok {
			content, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			fileCache[filePath] = strings.Split(utils.NormalizeNewlines(string(content)), "\n")
		}

		lines := fileCache[filePath]
		start := lineNum - 3 // 2 lines before
		if start < 0 {
			start = 0
		}
		end := lineNum + 2 // 2 lines after
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

// severityRank maps severity strings to an integer rank for comparison
func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// deduplicateStrings splits pipe-delimited inputs and returns unique items joined by " | "
func deduplicateStrings(parts []string) string {
	seen := make(map[string]bool)
	var uniq []string
	for _, p := range parts {
		// Split already-merged pipe-delimited values
		for _, sub := range strings.Split(p, " | ") {
			sub = strings.TrimSpace(sub)
			if sub != "" && !seen[sub] {
				seen[sub] = true
				uniq = append(uniq, sub)
			}
		}
	}
	// We do not formally sort to preserve chronological relevance, but we could.
	return strings.Join(uniq, " | ")
}

func mergeAndDeduplicate(findingsList ...[]reporter.Finding) []reporter.Finding {
	// Key: FilePath:LineNumber (or a highly specific fallback for OSV which has no line)
	mergedMap := make(map[string]reporter.Finding)

	for _, findings := range findingsList {
		for _, f := range findings {
			// Key heavily on physical file location. For supply chain (no line), use IssueName.
			var key string
			if f.LineNumber == "" || f.LineNumber == "0" || f.LineNumber == "-1" {
				// Supply chain or structural finding (no exact line)
				key = fmt.Sprintf("structural:%s:%s", f.FilePath, f.IssueName)
			} else {
				// Exact Code Snippet Match
				key = fmt.Sprintf("line:%s:%s", f.FilePath, f.LineNumber)
			}

			if existing, ok := mergedMap[key]; ok {
				// Merge logic: Combine this finding with the existing one

				// 1. Upgrade Severity if current is higher
				if severityRank(f.Severity) > severityRank(existing.Severity) {
					existing.Severity = strings.ToLower(f.Severity)
				}

				// 2. Keep the highest confidence
				if f.Confidence > existing.Confidence {
					existing.Confidence = f.Confidence
				}

				// 3. Aggregate metadata strings natively avoiding visual duplicates
				existing.IssueName = deduplicateStrings([]string{existing.IssueName, f.IssueName})
				existing.RuleID = deduplicateStrings([]string{existing.RuleID, f.RuleID})

				// Descriptions can be long, so join with newlines if they differ
				if !strings.Contains(existing.Description, f.Description) {
					existing.Description = existing.Description + "\n\nAlso flagged as: " + f.Description
				}
				if !strings.Contains(existing.Remediation, f.Remediation) {
					existing.Remediation = existing.Remediation + "\n\nAlternative Fix: " + f.Remediation
				}

				mergedMap[key] = existing
			} else {
				// First time seeing this location, add it directly
				mergedMap[key] = f
			}
		}
	}

	// 4. Transform map back to ordered list and assign Serial Numbers
	var finalMerged []reporter.Finding
	srNo := 1
	for _, v := range mergedMap {
		v.SrNo = srNo
		srNo++
		finalMerged = append(finalMerged, v)
	}

	return finalMerged
}

// updateFindings safely updates the shared findings slice for graceful shutdown access
func updateFindings(findings []reporter.Finding) {
	findingsMu.Lock()
	currentFindings = make([]reporter.Finding, len(findings))
	copy(currentFindings, findings)
	findingsMu.Unlock()
}

// saveReports generates CSV, HTML, and PDF reports
func saveReports(config *ScanConfig, findings []reporter.Finding) {
	utils.LogSubHeader("📄 Generating Reports")

	absTarget, _ := filepath.Abs(config.TargetDir)

	// Assign sequential Sr numbers and relativize paths
	for i := range findings {
		findings[i].SrNo = i + 1
		if filepath.IsAbs(findings[i].FilePath) {
			rel, err := filepath.Rel(absTarget, findings[i].FilePath)
			if err == nil {
				findings[i].FilePath = rel
			}
		}
	}

	if err := reporter.WriteCSV(config.OutputCSV, findings); err != nil {
		utils.LogError("Failed to write CSV report", err)
	} else {
		utils.LogInfo(fmt.Sprintf("CSV report saved to: %s", config.OutputCSV))
	}

	summary := reporter.GenerateReportSummary(findings, config.TargetDir)
	if err := reporter.GenerateHTMLReport(config.OutputHTML, findings, summary); err != nil {
		utils.LogError("Failed to write HTML report", err)
	} else {
		utils.LogInfo(fmt.Sprintf("HTML report saved to: %s", config.OutputHTML))
	}

	riskScore := reporter.CalculateRiskScore(findings)
	if err := reporter.GeneratePDF(config.OutputPDF, findings, summary, riskScore); err != nil {
		utils.LogError("Failed to write PDF report", err)
	} else {
		utils.LogInfo(fmt.Sprintf("PDF report saved to: %s", config.OutputPDF))
	}
}

// setupGracefulShutdown registers a SIGINT handler for Ctrl+C
func setupGracefulShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan

		// IMMEDIATELY set interrupt flag to stop all running operations
		atomic.StoreInt32(&interrupted, 1)
		ai.SetInterrupted(true)

		// Small delay for the running operations to notice the flag and stop
		time.Sleep(200 * time.Millisecond)

		// Get current findings
		findingsMu.Lock()
		count := len(currentFindings)
		findings := make([]reporter.Finding, len(currentFindings))
		copy(findings, currentFindings)
		findingsMu.Unlock()

		fmt.Println()
		fmt.Println()
		color.Yellow("═══════════════════════════════════════════════════════")
		color.Yellow("  ⚠️  SCAN INTERRUPTED (Ctrl+C)")
		color.Yellow("═══════════════════════════════════════════════════════")
		fmt.Println()

		if count > 0 {
			color.White("  Found %d issues so far.", count)
			fmt.Println()
			fmt.Print(color.HiYellowString("  Do you want to save partial reports? (y/n): "))

			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))

			if answer == "y" || answer == "yes" {
				fmt.Println()
				color.Green("  Saving partial reports...")
				saveReports(activeScanConfig, findings)
				fmt.Println()
				color.Green("  ✓ Partial reports saved successfully!")
			} else {
				color.Yellow("  Reports not saved.")
			}
		} else {
			color.White("  No issues found yet. Nothing to save.")
		}

		fmt.Println()
		color.Yellow("  Exiting gracefully...")
		fmt.Println()
		os.Exit(0)
	}()
}

// runStaticEngine runs all static scanning steps and returns merged findings
func runStaticEngine(cfg *ScanConfig, result *scanner.ScanResult) []reporter.Finding {
	var allFindings []reporter.Finding

	// Load rules
	utils.LogSubHeader("📋 Loading Rules")
	rules, err := cfg.LoadRules(cfg.RulesDir)
	if err != nil {
		utils.LogError("Failed to load rules", err)
	} else {
		utils.LogInfo(fmt.Sprintf("Loaded %d custom rules", len(rules)))
	}
	fmt.Println()

	// Pattern matching
	utils.LogSubHeader("🎯 Pattern Matching")
	customBar := utils.CreateProgressBar(100, "Scanning with custom rules")
	customFindings := scanner.RunPatternScan(result, rules, cfg.RulesDir)
	customBar.Set(100)
	customBar.Finish()
	utils.LogInfo(fmt.Sprintf("Custom rules found %d potential issues", len(customFindings)))
	fmt.Println()

	// AST analysis
	utils.LogSubHeader("🌳 AST Deep Analysis")
	astBar := utils.CreateProgressBar(100, "AST analysis (Python/JS/Java/Kotlin)")
	astFindings, astErr := scanner.ScanWithAST(cfg.TargetDir)
	astBar.Set(100)
	astBar.Finish()
	if astErr != nil {
		utils.LogError("AST analysis failed", astErr)
	} else {
		utils.LogInfo(fmt.Sprintf("AST analysis found %d vulnerabilities", len(astFindings)))
	}
	fmt.Println()

	// Semgrep
	var semgrepFindings []reporter.Finding
	if cfg.EnableSemgrep {
		utils.LogSubHeader("🔍 Semgrep Analysis")
		semgrepBar := utils.CreateProgressBar(100, "Running Semgrep")
		semgrepFindings, err = scanner.RunSemgrep(cfg.TargetDir)
		semgrepBar.Set(100)
		semgrepBar.Finish()
		if err != nil {
			utils.LogError("Semgrep scan failed", err)
		}
		fmt.Println()
	}

	// Dependency scanning
	var depFindings []reporter.Finding
	if cfg.EnableDependencyScan {
		utils.LogSubHeader("📦 Dependency Scanning")
		depFindings, err = scanner.ScanDependencies(cfg.TargetDir)
		if err != nil {
			utils.LogError("Dependency scan failed", err)
		} else {
			utils.LogInfo(fmt.Sprintf("Found %d dependency vulnerabilities", len(depFindings)))
		}
		fmt.Println()
	}

	// Secret detection
	var secretFindings []reporter.Finding
	if cfg.EnableSecretDetection {
		utils.LogSubHeader("🔑 Secret Detection")
		secretDetector := scanner.NewSecretDetector()
		secretFindings, err = secretDetector.ScanSecrets(cfg.TargetDir)
		if err != nil {
			utils.LogError("Secret scan failed", err)
		} else {
			utils.LogInfo(fmt.Sprintf("Found %d hardcoded secrets", len(secretFindings)))
		}
		fmt.Println()
	}

	// Supply chain
	var supplyChainFindings []reporter.Finding
	if cfg.EnableSupplyChain {
		utils.LogSubHeader("⛓️ Supply Chain Security")
		supplyChainScanner := scanner.NewSupplyChainScanner()
		supplyChainFindings, err = supplyChainScanner.ScanSupplyChain(cfg.TargetDir)
		if err != nil {
			utils.LogError("Supply chain scan failed", err)
		} else {
			utils.LogInfo(fmt.Sprintf("Found %d supply chain issues", len(supplyChainFindings)))
		}
		fmt.Println()
	}

	// Taint analysis
	var taintFindings []reporter.Finding
	if cfg.EnableSymbolicExec {
		utils.LogSubHeader("🔮 Taint / Data Flow Analysis")
		taintBar := utils.CreateProgressBar(100, "Tracking user input → dangerous sinks")
		var taintErr error
		taintFindings, taintErr = scanner.ScanTaintFlows(cfg.TargetDir)
		taintBar.Set(100)
		taintBar.Finish()
		if taintErr != nil {
			utils.LogError("Taint analysis failed", taintErr)
		} else {
			utils.LogInfo(fmt.Sprintf("Taint analysis found %d injection flows", len(taintFindings)))
		}
		fmt.Println()
	}

	// Container scanning
	if cfg.EnableContainerScan {
		utils.LogSubHeader("🐳 Container Image Scanning")
		containerScanner := scanner.NewContainerScanner(int64(len(allFindings) + 1000))
		containerFindings, cErr := containerScanner.ScanContainers(cfg.TargetDir)
		if cErr != nil {
			utils.LogError("Container scan failed", cErr)
		} else {
			utils.LogInfo(fmt.Sprintf("Found %d container configuration issues", len(containerFindings)))
			allFindings = append(allFindings, containerFindings...)
		}
		fmt.Println()
	}

	// Merge all
	allFindings = append(allFindings, mergeAndDeduplicate(customFindings, semgrepFindings)...)
	allFindings = append(allFindings, astFindings...)
	allFindings = append(allFindings, depFindings...)
	allFindings = append(allFindings, secretFindings...)
	allFindings = append(allFindings, supplyChainFindings...)
	allFindings = append(allFindings, taintFindings...)

	utils.LogInfo(fmt.Sprintf("Total static findings: %d", len(allFindings)))

	return allFindings
}
