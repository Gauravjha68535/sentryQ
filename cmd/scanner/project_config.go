package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"SentryQ/utils"

	"gopkg.in/yaml.v3"
)

// ProjectConfig is the sentryq.yaml / .sentryq.yaml file schema.
// Place this file in the root of the repository being scanned.
// CLI flags always take precedence; config file fills in unset flags.
//
// Example sentryq.yaml:
//
//	fail-on: critical
//	max-high: 5
//	enable-ai: true
//	ai-model: qwen2.5-coder:7b
//	webhook: https://hooks.slack.com/services/T00/B00/TOKEN
//	ignore-paths:
//	  - vendor/
//	  - "**/*.min.js"
type ProjectConfig struct {
	// Policy gates
	FailOn      string `yaml:"fail-on"`
	MaxCritical int    `yaml:"max-critical"`
	MaxHigh     int    `yaml:"max-high"`
	MaxMedium   int    `yaml:"max-medium"`
	MaxLow      int    `yaml:"max-low"`
	MaxTotal    int    `yaml:"max-total"`

	// AI settings
	EnableAI       bool   `yaml:"enable-ai"`
	EnableEnsemble bool   `yaml:"enable-ensemble"`
	AIModel        string `yaml:"ai-model"`
	JudgeModel     string `yaml:"judge-model"`
	OllamaHost     string `yaml:"ollama-host"`

	// Incremental scan
	ChangedOnly bool   `yaml:"changed-only"`
	BaseBranch  string `yaml:"base-branch"`

	// Integrations
	Webhook       string `yaml:"webhook"`
	PRProvider    string `yaml:"pr-provider"`
	PRRepo        string `yaml:"pr-repo"`
	PRNumber      int    `yaml:"pr-number"`
	MaxPRComments int    `yaml:"max-pr-comments"`

	// Output
	SBOMOut string `yaml:"sbom"`
}

// loadProjectConfig reads sentryq.yaml (or .sentryq.yaml / .yml variants)
// from the target directory. Returns nil if no config file exists.
func loadProjectConfig(targetDir string) *ProjectConfig {
	candidates := []string{
		filepath.Join(targetDir, "sentryq.yaml"),
		filepath.Join(targetDir, "sentryq.yml"),
		filepath.Join(targetDir, ".sentryq.yaml"),
		filepath.Join(targetDir, ".sentryq.yml"),
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// Default numeric policy fields to -1 ("no limit") so an absent key
		// in the YAML doesn't accidentally override the real default of -1.
		cfg := ProjectConfig{
			MaxCritical:   -1,
			MaxHigh:       -1,
			MaxMedium:     -1,
			MaxLow:        -1,
			MaxTotal:      -1,
			MaxPRComments: -1,
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			utils.LogWarn(fmt.Sprintf("sentryq.yaml: parse error (%v) — ignoring config file", err))
			continue
		}
		utils.LogInfo(fmt.Sprintf("📋 Project config loaded from %s", path))
		return &cfg
	}
	return nil
}

// applyProjectConfig overlays config-file values onto the flag variables for
// flags that were NOT explicitly provided on the command line.
// Call this after flag.Parse() and after targetDir is known.
func applyProjectConfig(
	cfg *ProjectConfig,
	failOn *string,
	maxCritical, maxHigh, maxMedium, maxLow, maxTotal *int,
	enableAI, enableEnsemble *bool,
	aiModel, judgeModel, ollamaHost *string,
	changedOnly *bool, baseBranch *string,
	webhookURLs, prProvider, prRepo *string,
	prNumber, maxPRComments *int,
	sbomOut *string,
) {
	if cfg == nil {
		return
	}

	// Collect flags that the user explicitly set on the command line.
	explicit := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	// apply sets *dst = src only when the flag was not explicitly provided
	// and src is non-zero / non-empty.
	applyStr := func(name string, dst *string, src string) {
		if !explicit[name] && src != "" {
			*dst = src
		}
	}
	applyInt := func(name string, dst *int, src int) {
		if !explicit[name] && src != -1 {
			*dst = src
		}
	}
	applyBool := func(name string, dst *bool, src bool) {
		if !explicit[name] && src {
			*dst = true
		}
	}

	applyStr("fail-on", failOn, cfg.FailOn)
	applyInt("max-critical", maxCritical, cfg.MaxCritical)
	applyInt("max-high", maxHigh, cfg.MaxHigh)
	applyInt("max-medium", maxMedium, cfg.MaxMedium)
	applyInt("max-low", maxLow, cfg.MaxLow)
	applyInt("max-total", maxTotal, cfg.MaxTotal)
	applyBool("enable-ai", enableAI, cfg.EnableAI)
	applyBool("enable-ensemble", enableEnsemble, cfg.EnableEnsemble)
	applyStr("ai-model", aiModel, cfg.AIModel)
	applyStr("judge-model", judgeModel, cfg.JudgeModel)
	applyStr("ollama-host", ollamaHost, cfg.OllamaHost)
	applyBool("changed-only", changedOnly, cfg.ChangedOnly)
	applyStr("base-branch", baseBranch, cfg.BaseBranch)
	applyStr("webhook", webhookURLs, cfg.Webhook)
	applyStr("pr-provider", prProvider, cfg.PRProvider)
	applyStr("pr-repo", prRepo, cfg.PRRepo)
	if !explicit["pr-number"] && cfg.PRNumber != 0 {
		*prNumber = cfg.PRNumber
	}
	if !explicit["max-pr-comments"] && cfg.MaxPRComments != -1 && cfg.MaxPRComments != 0 {
		*maxPRComments = cfg.MaxPRComments
	}
	applyStr("sbom", sbomOut, cfg.SBOMOut)
}
