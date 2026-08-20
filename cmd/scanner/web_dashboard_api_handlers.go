package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"SentryQ/ai"
	"SentryQ/reporter"
)

func handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		var s settingsData
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}

		var providerChanged bool
		func() {
			appSettings.Lock()
			defer appSettings.Unlock()
			if s.AIProvider != "" {
				appSettings.AIProvider = s.AIProvider
				providerChanged = true
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
			if s.LMStudioModel != "" {
				appSettings.LMStudioModel = s.LMStudioModel
			}
			// Only overwrite credentials when non-empty (empty = "do not change")
			if s.CustomAPIURL != "" {
				appSettings.CustomAPIURL = s.CustomAPIURL
			}
			if s.CustomAPIKey != "" {
				appSettings.CustomAPIKey = s.CustomAPIKey
			}
			if s.CustomModel != "" {
				appSettings.CustomModel = s.CustomModel
			}
			if s.ClaudeAPIKey != "" {
				appSettings.ClaudeAPIKey = s.ClaudeAPIKey
			}
			if s.ClaudeModel != "" {
				appSettings.ClaudeModel = s.ClaudeModel
			}
			if s.GeminiAPIKey != "" {
				appSettings.GeminiAPIKey = s.GeminiAPIKey
			}
			if s.GeminiModel != "" {
				appSettings.GeminiModel = s.GeminiModel
			}
			// WebhookURLs: always overwrite (empty = cleared)
			appSettings.WebhookURLs = s.WebhookURLs
		}()

		// Apply side-effects outside the lock
		if providerChanged {
			ai.SetActiveProvider(s.AIProvider)
		}
		if s.CustomAPIURL != "" {
			ai.SetCustomEndpoint(s.CustomAPIURL, s.CustomAPIKey, s.CustomModel)
		}
		if s.LMStudioHost != "" || s.LMStudioModel != "" {
			appSettings.RLock()
			ai.SetLMStudioConfig(appSettings.LMStudioHost, appSettings.LMStudioModel)
			appSettings.RUnlock()
		}
		if s.ClaudeAPIKey != "" || s.ClaudeModel != "" {
			appSettings.RLock()
			ai.SetClaudeConfig(appSettings.ClaudeAPIKey, appSettings.ClaudeModel)
			appSettings.RUnlock()
		}
		if s.GeminiAPIKey != "" || s.GeminiModel != "" {
			appSettings.RLock()
			ai.SetGeminiConfig(appSettings.GeminiAPIKey, appSettings.GeminiModel)
			appSettings.RUnlock()
		}

		if err := saveSettings(); err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to persist settings: " + err.Error()})
			return
		}
		httpJSON(w, http.StatusOK, map[string]string{"status": "saved"})
		return
	}

	appSettings.RLock()
	defer appSettings.RUnlock()
	maskedCustomKey := ""
	if len(appSettings.CustomAPIKey) > 0 {
		maskedCustomKey = "***"
	}
	maskedClaudeKey := ""
	if len(appSettings.ClaudeAPIKey) > 0 {
		maskedClaudeKey = "***"
	}
	maskedGeminiKey := ""
	if len(appSettings.GeminiAPIKey) > 0 {
		maskedGeminiKey = "***"
	}
	httpJSON(w, http.StatusOK, map[string]interface{}{
		"ai_provider":         appSettings.AIProvider,
		"default_model":       appSettings.DefaultModel,
		"ollama_host":         appSettings.OllamaHost,
		"lmstudio_host":       appSettings.LMStudioHost,
		"lmstudio_model":      appSettings.LMStudioModel,
		"custom_api_url":      appSettings.CustomAPIURL,
		"custom_api_key":      maskedCustomKey,
		"custom_api_key_set":  len(appSettings.CustomAPIKey) > 0,
		"custom_model":        appSettings.CustomModel,
		"claude_api_key":      maskedClaudeKey,
		"claude_api_key_set":  len(appSettings.ClaudeAPIKey) > 0,
		"claude_model":        appSettings.ClaudeModel,
		"gemini_api_key":      maskedGeminiKey,
		"gemini_api_key_set":  len(appSettings.GeminiAPIKey) > 0,
		"gemini_model":        appSettings.GeminiModel,
		"webhook_urls":        appSettings.WebhookURLs,
	})
}

func handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Check Ollama — use cached result to avoid blocking every status poll.
	appSettings.RLock()
	host := appSettings.OllamaHost
	appSettings.RUnlock()
	ollamaStatus := getOllamaStatus(host)

	goVersion := runtime.Version()

	gitStatus := "not found"
	if _, err := exec.LookPath(getGitBin()); err == nil {
		gitStatus = "available"
	}

	httpJSON(w, http.StatusOK, map[string]interface{}{
		"version":     reporter.Version,
		"ollama":      ollamaStatus,
		"ollama_host": host,
		"go_version":  goVersion,
		"git":         gitStatus,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"memory_mb":   m.Alloc / 1024 / 1024,
		"uptime":      time.Since(startTime).Round(time.Second).String(),
	})
}

// isAllowedOllamaHost returns true if the host (host:port or bare host) is a
// loopback address. This prevents the ?host= query parameter from being used as
// an SSRF vector to reach internal network services or cloud metadata endpoints.
func isAllowedOllamaHost(host string) bool {
	h := host
	if strings.Contains(host, ":") {
		var err error
		h, _, err = net.SplitHostPort(host)
		if err != nil {
			return false
		}
	}
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	// Allow optional host parameter to fetch models from a different Ollama instance.
	// Restrict to loopback addresses to prevent SSRF via crafted ?host= values.
	host := r.URL.Query().Get("host")
	if host != "" && !isAllowedOllamaHost(host) {
		http.Error(w, "Invalid host: only loopback addresses are permitted", http.StatusBadRequest)
		return
	}
	if host == "" {
		appSettings.RLock()
		host = appSettings.OllamaHost
		appSettings.RUnlock()
	}

	models := ai.GetInstalledModels(host)
	if models == nil {
		models = []string{}
	}

	httpJSON(w, http.StatusOK, map[string]interface{}{
		"models": models,
	})
}

func handleCustomEndpointTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Provider string `json:"provider"`
		URL      string `json:"url"`
		APIKey   string `json:"api_key"`
		Model    string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var ok bool
	var msg string
	switch req.Provider {
	case "claude":
		ok, msg = ai.TestClaudeEndpoint(req.APIKey, req.Model)
	case "gemini":
		ok, msg = ai.TestGeminiEndpoint(req.APIKey, req.Model)
	default: // openai, lmstudio, or any OpenAI-compatible
		if req.URL == "" || req.Model == "" {
			httpJSON(w, http.StatusOK, map[string]interface{}{
				"success": false,
				"message": "URL and model name are required",
			})
			return
		}
		// SSRF guard: reject private/reserved IP ranges.
		// handleCustomEndpointModels has the same guard; both must be consistent.
		if err := rejectPrivateURL(req.URL); err != nil {
			http.Error(w, "Invalid URL: "+err.Error(), http.StatusBadRequest)
			return
		}
		ok, msg = ai.TestOpenAIEndpoint(req.URL, req.APIKey, req.Model)
	}

	httpJSON(w, http.StatusOK, map[string]interface{}{
		"success": ok,
		"message": msg,
	})
}

func handleCustomEndpointModels(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")

	// Hardcoded model lists for cloud providers
	switch provider {
	case "claude":
		httpJSON(w, http.StatusOK, map[string]interface{}{"models": ai.KnownClaudeModels})
		return
	case "gemini":
		httpJSON(w, http.StatusOK, map[string]interface{}{"models": ai.KnownGeminiModels})
		return
	}

	rawURL := r.URL.Query().Get("url")
	// Prefer the Authorization header to avoid exposing the key in URLs (which appear in
	// server logs, browser history, and proxy logs). Fall back to the query param for
	// backward compatibility with older frontend versions.
	apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if apiKey == "" {
		apiKey = r.URL.Query().Get("api_key")
	}

	if rawURL == "" {
		httpJSON(w, http.StatusOK, map[string]interface{}{
			"models": []string{},
			"error":  "URL parameter is required",
		})
		return
	}

	// SSRF guard: reject private/reserved IP ranges so this endpoint cannot
	// be used to probe cloud metadata (169.254.x.x) or internal services.
	if err := rejectPrivateURL(rawURL); err != nil {
		http.Error(w, "Invalid URL: "+err.Error(), http.StatusBadRequest)
		return
	}

	models, err := ai.ListOpenAIModels(rawURL, apiKey)
	if err != nil {
		httpJSON(w, http.StatusOK, map[string]interface{}{
			"models": []string{},
			"error":  err.Error(),
		})
		return
	}
	if models == nil {
		models = []string{}
	}

	httpJSON(w, http.StatusOK, map[string]interface{}{
		"models": models,
	})
}
