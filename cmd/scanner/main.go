package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"SentryQ/ai"
	"SentryQ/reporter"
	"SentryQ/utils"

	"github.com/google/uuid"
)

func main() {
	// ── Version flag ──────────────────────────────────────────────────────────
	versionFlag   := flag.Bool("version", false, "Print version and exit")

	// ── Server / Ollama flags ──────────────────────────────────────────────────
	portPtr       := flag.Int("port", 5336, "Web server port")
	ollamaPtr     := flag.String("ollama-host", "", "Remote Ollama host:port (overrides OLLAMA_HOST env var)")

	// ── CI Policy flags ───────────────────────────────────────────────────────
	failOn        := flag.String("fail-on", "", "Exit 1 if any finding at or above this severity (critical|high|medium|low)")
	maxCritical   := flag.Int("max-critical", -1, "Fail if critical findings exceed this count (-1 = no limit)")
	maxHigh       := flag.Int("max-high", -1, "Fail if high findings exceed this count (-1 = no limit)")
	maxMedium     := flag.Int("max-medium", -1, "Fail if medium findings exceed this count (-1 = no limit)")
	maxLow        := flag.Int("max-low", -1, "Fail if low findings exceed this count (-1 = no limit)")
	maxTotal      := flag.Int("max-total", -1, "Fail if total findings exceed this count (-1 = no limit)")

	// ── AI flags ──────────────────────────────────────────────────────────────
	enableAI       := flag.Bool("enable-ai", false, "Enable AI-powered vulnerability discovery and validation")
	enableEnsemble := flag.Bool("enable-ensemble", false, "Enable Ensemble Audit (3-phase: static → AI → judge merge; implies --enable-ai)")
	aiModel        := flag.String("ai-model", "", "AI model to use for discovery/validation (default: auto-selected)")
	judgeModel     := flag.String("judge-model", "", "Judge LLM model for Ensemble merge (default: same as --ai-model)")

	// ── Incremental scan ──────────────────────────────────────────────────────
	changedOnly   := flag.Bool("changed-only", false, "Scan only files changed since last git commit (uses git diff HEAD~1)")
	baseBranch    := flag.String("base-branch", "main", "Base branch for incremental diff (used with --changed-only)")

	// ── PR decoration ─────────────────────────────────────────────────────────
	prProvider    := flag.String("pr-provider", "", "PR platform: github or gitlab")
	prToken       := flag.String("pr-token", "", "GitHub/GitLab personal access token")
	prRepo        := flag.String("pr-repo", "", "Repo in owner/name format (GitHub) or namespace/project (GitLab)")
	prNumber      := flag.Int("pr-number", 0, "GitHub PR number")
	mrIID         := flag.Int("mr-iid", 0, "GitLab MR IID")
	gitlabURL     := flag.String("gitlab-url", "https://gitlab.com", "GitLab base URL")
	maxPRComments := flag.Int("max-pr-comments", 20, "Max inline PR comments to post (0 = unlimited)")

	// ── Webhooks ──────────────────────────────────────────────────────────────
	webhookURLs   := flag.String("webhook", "", "Comma-separated webhook URLs to notify on scan completion")

	// ── SBOM ──────────────────────────────────────────────────────────────────
	sbomOut       := flag.String("sbom", "", "Write CycloneDX SBOM JSON to this file path")

	// ── Scan diff ─────────────────────────────────────────────────────────────
	diffFlag      := flag.Bool("diff", false, "Diff mode: compare two scan IDs (provide IDs as positional args)")

	flag.Parse()

	// ── PORT env override ─────────────────────────────────────────────────────
	port := *portPtr
	if envPort := os.Getenv("PORT"); envPort != "" && *portPtr == 5336 {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}
	if port <= 0 || port > 65535 {
		port = 5336
	}

	// ── Ollama host ───────────────────────────────────────────────────────────
	ollamaHost := *ollamaPtr
	if ollamaHost == "" {
		ollamaHost = os.Getenv("OLLAMA_HOST")
	}
	if ollamaHost != "" {
		fmt.Printf("🔗 Ollama: %s\n", ollamaHost)
		ai.SetOllamaHost(ollamaHost)
	} else {
		fmt.Println("🔗 Ollama: localhost:11434")
	}

	// ── Version / banner ─────────────────────────────────────────────────────
	if *versionFlag {
		fmt.Println(getVersion())
		return
	}
	utils.PrintBanner()

	// ── Subcommands ───────────────────────────────────────────────────────────
	if flag.NArg() > 0 {
		switch flag.Arg(0) {
		case "update":
			RunUpdate()
			return
		case "version":
			fmt.Println(getVersion())
			return
		}
	}

	// ── Scan diff mode ────────────────────────────────────────────────────────
	if *diffFlag {
		if flag.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "Usage: sentryq --diff <scan-id-1> <scan-id-2>")
			os.Exit(1)
		}
		if err := InitDB(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ DB init failed: %v\n", err)
			os.Exit(1)
		}
		defer CloseDB()
		diff, err := DiffScans(flag.Arg(0), flag.Arg(1))
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Diff failed: %v\n", err)
			os.Exit(1)
		}
		PrintDiff(diff)
		if *sbomOut != "" {
			fmt.Fprintln(os.Stderr, "⚠️  --sbom is not supported in diff mode")
		}
		return
	}

	// ── CLI scan mode ─────────────────────────────────────────────────────────
	if flag.NArg() > 0 {
		targetDir := flag.Arg(0)
		fmt.Printf("🚀 Starting CLI scan of: %s\n", targetDir)

		if err := InitDB(); err != nil {
			fmt.Printf("❌ Failed to initialize database: %v\n", err)
			return
		}
		defer CloseDB()
		loadSettings()

		// Build policy config from flags
		policy := PolicyConfig{
			FailOn:      *failOn,
			MaxCritical: *maxCritical,
			MaxHigh:     *maxHigh,
			MaxMedium:   *maxMedium,
			MaxLow:      *maxLow,
			MaxTotal:    *maxTotal,
		}

		// Build PR config
		prCfg := PRConfig{
			Provider:    *prProvider,
			Token:       *prToken,
			Repo:        *prRepo,
			PRNumber:    *prNumber,
			MRID:        *mrIID,
			GitLabURL:   *gitlabURL,
			MaxComments: *maxPRComments,
		}
		// Env var overrides for CI token security
		if t := os.Getenv("SENTRYQ_PR_TOKEN"); t != "" {
			prCfg.Token = t
		}

		// Resolve changed-only file list
		var changedFiles []string
		if *changedOnly {
			changed, err := getChangedFiles(targetDir, *baseBranch)
			if err != nil {
				utils.LogWarn(fmt.Sprintf("--changed-only: git diff failed (%v) — falling back to full scan", err))
			} else if len(changed) == 0 {
				fmt.Println("No changed files detected — nothing to scan.")
				return
			} else {
				changedFiles = changed
				fmt.Printf("📂 Incremental scan: %d changed file(s)\n", len(changedFiles))
			}
		}

		useEnsemble := *enableEnsemble
		useAI := *enableAI || useEnsemble
		model := *aiModel
		if model == "" && useAI {
			model = ai.GetDefaultModel()
		}
		jModel := *judgeModel
		if jModel == "" {
			jModel = model
		}
		cfg := WebScanConfig{
			EnableDeepScan: true,
			EnableAI:       useAI,
			EnableEnsemble: useEnsemble,
			AIModel:        model,
			JudgeModel:     jModel,
			OllamaHost:     ollamaHost,
			ChangedFiles:   changedFiles,
		}

		scanID := "cli-" + uuid.New().String()
		if err := CreateScan(scanID, targetDir, "cli", "{}"); err != nil {
			fmt.Printf("❌ Failed to create scan record: %v\n", err)
			return
		}

		ctx := context.Background()
		runScan(ctx, scanID, targetDir, cfg)

		findings, err := GetFindingsForScan(scanID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to retrieve findings: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n✅ CLI Scan Complete. Total Findings: %d\n", len(findings))

		// SBOM generation
		if *sbomOut != "" {
			if err := reporter.GenerateSBOM(*sbomOut, findings, filepath.Base(targetDir)); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  SBOM generation failed: %v\n", err)
			} else {
				fmt.Printf("📦 SBOM written to %s\n", *sbomOut)
			}
		}

		// Webhook notification
		var wURLs []string
		if *webhookURLs != "" {
			wURLs = strings.Split(*webhookURLs, ",")
		}
		if envW := os.Getenv("SENTRYQ_WEBHOOK_URLS"); envW != "" {
			wURLs = append(wURLs, strings.Split(envW, ",")...)
		}

		// Policy evaluation
		violations := EvaluatePolicy(findings, policy)
		FireWebhooks(wURLs, scanID, targetDir, "completed", findings, violations)

		// PR decoration
		if prCfg.Provider != "" {
			DecoratePR(prCfg, scanID, findings)
		}

		exitCode := PrintPolicyResult(violations)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return
	}

	// ── Web server mode ───────────────────────────────────────────────────────
	StartWebServer(port)
}

// getChangedFiles returns the list of files changed relative to baseBranch using git diff.
func getChangedFiles(repoDir, baseBranch string) ([]string, error) {
	// Try "git diff <base>...HEAD --name-only" first (best for PR context)
	out, err := runGit(repoDir, "diff", "--name-only", baseBranch+"...HEAD")
	if err != nil || strings.TrimSpace(out) == "" {
		// Fall back to "git diff HEAD~1 --name-only" (single commit delta)
		out, err = runGit(repoDir, "diff", "--name-only", "HEAD~1")
		if err != nil {
			return nil, err
		}
	}

	var files []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		abs := filepath.Join(repoDir, line)
		if _, statErr := os.Stat(abs); statErr == nil {
			files = append(files, abs)
		}
	}
	return files, nil
}

func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}

func getVersion() string {
	return "SentryQ v" + reporter.Version
}
