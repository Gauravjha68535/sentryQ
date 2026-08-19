package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"SentryQ/ai"
	"SentryQ/reporter"
	"SentryQ/utils"
)

// ollamaStatusCache holds the last Ollama reachability result so that
// /api/status does not make a live HTTP call on every frontend poll.
var ollamaStatusCache struct {
	sync.Mutex
	status    string
	checkedAt time.Time
}

const ollamaStatusTTL = 10 * time.Second

// getOllamaStatus returns a cached Ollama reachability result, refreshing at most
// once per ollamaStatusTTL to avoid blocking every /api/status request.
func getOllamaStatus(host string) string {
	ollamaStatusCache.Lock()
	defer ollamaStatusCache.Unlock()
	if time.Since(ollamaStatusCache.checkedAt) < ollamaStatusTTL {
		return ollamaStatusCache.status
	}
	status := "unreachable"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/api/version", host))
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			status = "connected"
		}
	}
	ollamaStatusCache.status = status
	ollamaStatusCache.checkedAt = time.Now()
	return status
}

// settingsData is the canonical settings schema shared by the runtime struct,
// disk serialisation (loadSettings/saveSettings), and the API response.
// Defining it once eliminates the three identical anonymous structs that
// previously existed in appSettings, loadSettings, and saveSettings.
type settingsData struct {
	AIProvider    string `json:"ai_provider"`
	DefaultModel  string `json:"default_model"`
	OllamaHost    string `json:"ollama_host"`
	LMStudioHost  string `json:"lmstudio_host"`
	LMStudioModel string `json:"lmstudio_model"`
	CustomAPIURL  string `json:"custom_api_url"`
	CustomAPIKey  string `json:"custom_api_key"`
	CustomModel   string `json:"custom_model"`
	ClaudeAPIKey  string `json:"claude_api_key"`
	ClaudeModel   string `json:"claude_model"`
	GeminiAPIKey  string `json:"gemini_api_key"`
	GeminiModel   string `json:"gemini_model"`
	WebhookURLs   string `json:"webhook_urls"`
}

var (
	startTime    time.Time
	settingsPath string
	appSettings  = struct {
		sync.RWMutex
		settingsData
	}{
		settingsData: settingsData{
			AIProvider:   "ollama",
			DefaultModel: "qwen2.5-coder:7b",
			OllamaHost:   "localhost:11434",
			LMStudioHost: "localhost:1234",
			ClaudeModel:  "claude-sonnet-4-6",
			GeminiModel:  "gemini-2.0-flash",
		},
	}
)

func loadSettings() {
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		var s settingsData
		if err := json.Unmarshal(data, &s); err == nil {
			// Environment variables take precedence over stored keys so that
			// users can inject credentials via the process environment without
			// ever writing them to disk.
			if envKey := os.Getenv("SENTRYQ_CUSTOM_API_KEY"); envKey != "" {
				s.CustomAPIKey = envKey
			}
			if envKey := os.Getenv("SENTRYQ_CLAUDE_API_KEY"); envKey != "" {
				s.ClaudeAPIKey = envKey
			}
			if envKey := os.Getenv("SENTRYQ_GEMINI_API_KEY"); envKey != "" {
				s.GeminiAPIKey = envKey
			}

			appSettings.Lock()
			if s.AIProvider != "" {
				appSettings.AIProvider = s.AIProvider
			}
			if s.DefaultModel != "" {
				appSettings.DefaultModel = s.DefaultModel
			}
			if s.OllamaHost != "" {
				appSettings.OllamaHost = s.OllamaHost
			}
			if s.LMStudioHost != "" {
				appSettings.LMStudioHost = s.LMStudioHost
			}
			appSettings.LMStudioModel = s.LMStudioModel
			appSettings.CustomAPIURL = s.CustomAPIURL
			appSettings.CustomAPIKey = s.CustomAPIKey
			appSettings.CustomModel = s.CustomModel
			appSettings.ClaudeAPIKey = s.ClaudeAPIKey
			if s.ClaudeModel != "" {
				appSettings.ClaudeModel = s.ClaudeModel
			}
			appSettings.GeminiAPIKey = s.GeminiAPIKey
			if s.GeminiModel != "" {
				appSettings.GeminiModel = s.GeminiModel
			}
			appSettings.WebhookURLs = s.WebhookURLs
			appSettings.Unlock()

			// Apply all provider configs to the AI package
			ai.SetActiveProvider(s.AIProvider)
			if s.CustomAPIURL != "" {
				ai.SetCustomEndpoint(s.CustomAPIURL, s.CustomAPIKey, s.CustomModel)
			}
			ai.SetLMStudioConfig(s.LMStudioHost, s.LMStudioModel)
			ai.SetClaudeConfig(s.ClaudeAPIKey, s.ClaudeModel)
			ai.SetGeminiConfig(s.GeminiAPIKey, s.GeminiModel)
		}
	} else {
		// Settings file doesn't exist yet — still honour env-var overrides.
		appSettings.Lock()
		if envKey := os.Getenv("SENTRYQ_CUSTOM_API_KEY"); envKey != "" {
			appSettings.CustomAPIKey = envKey
		}
		if envKey := os.Getenv("SENTRYQ_CLAUDE_API_KEY"); envKey != "" {
			appSettings.ClaudeAPIKey = envKey
		}
		if envKey := os.Getenv("SENTRYQ_GEMINI_API_KEY"); envKey != "" {
			appSettings.GeminiAPIKey = envKey
		}
		appSettings.Unlock()
	}
}

// recordMLFeedback records a user triage decision into the ML FP history file
// so the MLFPReducer can learn from it on future scans.
// Only "false_positive" and "resolved" statuses are meaningful signals;
// "open" and "ignored" are skipped since they carry no FP/TP information.
func recordMLFeedback(f reporter.Finding, status string) {
	isFP := status == "false_positive"
	isTP := status == "resolved"
	if !isFP && !isTP {
		return
	}

	mlCacheDir := ".sentryq-ml-cache"
	if homeDir, err := os.UserHomeDir(); err == nil {
		mlCacheDir = filepath.Join(homeDir, ".sentryq", "ml-cache")
	}

	reducer := ai.NewFPHistoryCache(mlCacheDir)
	if err := reducer.LoadHistory(); err != nil {
		utils.LogWarn("ML feedback: failed to load history: " + err.Error())
		return
	}
	reducer.AddFeedback(f.RuleID, f.FilePath, f.Severity, isFP, "")
	if err := reducer.SaveHistory(); err != nil {
		utils.LogWarn("ML feedback: failed to save history: " + err.Error())
	}
}

// secureWriteFile writes data to path with owner-only permissions.
//
// Unix: uses os.WriteFile with mode 0600 — the OS enforces the permission bits.
//
// Windows: os.WriteFile permission bits are not enforced by NTFS, so we use an
// atomic write pattern:
//  1. Write data to a temporary file in the same directory.
//  2. Apply a restrictive ACL to the temp file via icacls (owner full control,
//     inheritance removed).
//  3. Rename the temp file to the final path — on Windows, os.Rename on the same
//     volume is atomic and replaces the destination.
//
// This guarantees the final file is never visible to other users with default ACLs.
func secureWriteFile(path string, data []byte) error {
	if runtime.GOOS == "windows" {
		dir := filepath.Dir(path)
		tmp, err := os.CreateTemp(dir, ".sentryq-tmp-*.json")
		if err != nil {
			return err
		}
		tmpPath := tmp.Name()
		removeTmp := func() { os.Remove(tmpPath) }

		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			removeTmp()
			return err
		}
		tmp.Close()

		// Apply restrictive ACL before exposing under the final name.
		if username := os.Getenv("USERNAME"); username != "" {
			if err := exec.Command(
				"icacls", tmpPath,
				"/inheritance:r",
				"/grant:r", username+":F",
			).Run(); err != nil {
				utils.LogWarn(fmt.Sprintf("secureWriteFile: icacls failed for %s: %v — file may be accessible to other users", tmpPath, err))
			}
		}

		// Atomic replace: rename is on the same drive so this is a single metadata op.
		if err := os.Rename(tmpPath, path); err != nil {
			removeTmp()
			return err
		}
		return nil
	}
	// Unix/macOS: the OS enforces 0600 permission bits directly.
	return os.WriteFile(path, data, 0600)
}

func saveSettings() error {
	// Hold the read lock for the full duration of marshal + file write so that
	// a concurrent PUT /api/settings cannot update appSettings between the
	// snapshot and the disk write (which would silently revert the new values).
	appSettings.RLock()
	defer appSettings.RUnlock()

	s := appSettings.settingsData

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		utils.LogError("Failed to serialize settings", err)
		return err
	}
	// Ensure parent directory exists (first run, or settings moved to home dir).
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0700); err != nil {
		utils.LogError("Failed to create settings directory", err)
		return err
	}
	// secureWriteFile uses 0600 on Unix; on Windows it additionally calls
	// icacls to restrict the ACL to the current user (os.WriteFile alone
	// does not enforce permission bits on Windows NTFS).
	if err := secureWriteFile(settingsPath, data); err != nil {
		utils.LogError("Failed to save settings", err)
		return err
	}
	return nil
}
