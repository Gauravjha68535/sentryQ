package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProjectConfigNotFound(t *testing.T) {
	dir := t.TempDir()
	cfg := loadProjectConfig(dir)
	if cfg != nil {
		t.Error("expected nil when no sentryq.yaml exists")
	}
}

func TestLoadProjectConfigBasic(t *testing.T) {
	dir := t.TempDir()
	yaml := `
fail-on: critical
max-critical: 0
max-high: 5
enable-ai: true
ai-model: qwen2.5-coder:7b
webhook: https://hooks.example.com/sentryq
`
	if err := os.WriteFile(filepath.Join(dir, "sentryq.yaml"), []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := loadProjectConfig(dir)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.FailOn != "critical" {
		t.Errorf("FailOn = %q, want critical", cfg.FailOn)
	}
	if cfg.MaxCritical != 0 {
		t.Errorf("MaxCritical = %d, want 0", cfg.MaxCritical)
	}
	if cfg.MaxHigh != 5 {
		t.Errorf("MaxHigh = %d, want 5", cfg.MaxHigh)
	}
	if !cfg.EnableAI {
		t.Error("EnableAI should be true")
	}
	if cfg.AIModel != "qwen2.5-coder:7b" {
		t.Errorf("AIModel = %q, want qwen2.5-coder:7b", cfg.AIModel)
	}
	if cfg.Webhook != "https://hooks.example.com/sentryq" {
		t.Errorf("Webhook = %q", cfg.Webhook)
	}
}

func TestLoadProjectConfigYmlExtension(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sentryq.yml"), []byte("fail-on: high\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := loadProjectConfig(dir)
	if cfg == nil {
		t.Fatal("expected non-nil config for .yml extension")
	}
	if cfg.FailOn != "high" {
		t.Errorf("FailOn = %q, want high", cfg.FailOn)
	}
}

func TestLoadProjectConfigDotPrefix(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".sentryq.yaml"), []byte("max-total: 100\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := loadProjectConfig(dir)
	if cfg == nil {
		t.Fatal("expected non-nil config for .sentryq.yaml")
	}
	if cfg.MaxTotal != 100 {
		t.Errorf("MaxTotal = %d, want 100", cfg.MaxTotal)
	}
}

func TestLoadProjectConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sentryq.yaml"), []byte("{{invalid: [yaml"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := loadProjectConfig(dir)
	// Invalid YAML should be ignored (returns nil), not panic
	if cfg != nil {
		t.Error("invalid YAML should return nil")
	}
}

func TestLoadProjectConfigDefaultsMaxValues(t *testing.T) {
	dir := t.TempDir()
	// A config that only sets fail-on — max-* fields should remain -1
	if err := os.WriteFile(filepath.Join(dir, "sentryq.yaml"), []byte("fail-on: high\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := loadProjectConfig(dir)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	// Absent max-* fields should be -1 (no limit), not 0
	if cfg.MaxCritical != -1 {
		t.Errorf("MaxCritical should default to -1 when absent, got %d", cfg.MaxCritical)
	}
	if cfg.MaxHigh != -1 {
		t.Errorf("MaxHigh should default to -1 when absent, got %d", cfg.MaxHigh)
	}
}

func TestLoadProjectConfigAllFields(t *testing.T) {
	dir := t.TempDir()
	yaml := `
fail-on: medium
max-critical: 0
max-high: 3
max-medium: 10
max-low: -1
max-total: 50
enable-ai: true
enable-ensemble: false
ai-model: llama3:8b
judge-model: llama3:70b
ollama-host: 192.168.1.10:11434
changed-only: true
base-branch: develop
webhook: https://hooks.example.com/test
pr-provider: github
pr-repo: owner/repo
pr-number: 42
max-pr-comments: 10
sbom: sbom-output.json
`
	if err := os.WriteFile(filepath.Join(dir, "sentryq.yaml"), []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := loadProjectConfig(dir)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	checks := map[string]bool{
		"FailOn=medium":          cfg.FailOn == "medium",
		"MaxCritical=0":          cfg.MaxCritical == 0,
		"MaxHigh=3":              cfg.MaxHigh == 3,
		"MaxMedium=10":           cfg.MaxMedium == 10,
		"MaxTotal=50":            cfg.MaxTotal == 50,
		"EnableAI=true":          cfg.EnableAI,
		"AIModel=llama3:8b":      cfg.AIModel == "llama3:8b",
		"JudgeModel=llama3:70b":  cfg.JudgeModel == "llama3:70b",
		"OllamaHost set":         cfg.OllamaHost == "192.168.1.10:11434",
		"ChangedOnly=true":       cfg.ChangedOnly,
		"BaseBranch=develop":     cfg.BaseBranch == "develop",
		"PRProvider=github":      cfg.PRProvider == "github",
		"PRNumber=42":            cfg.PRNumber == 42,
		"MaxPRComments=10":       cfg.MaxPRComments == 10,
		"SBOMOut set":            cfg.SBOMOut == "sbom-output.json",
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("field check failed: %s", name)
		}
	}
}
