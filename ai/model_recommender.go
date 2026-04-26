package ai

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"SentryQ/utils"
)

type OllamaTagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

// GetInstalledModels fetches the list of locally installed models from Ollama.
// If host is empty, it uses the global ollamaBaseURL.
func GetInstalledModels(host string) []string {
	baseURL := host
	if baseURL == "" {
		baseURL = GetOllamaBaseURL()
	} else if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(baseURL + "/api/tags")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var tags OllamaTagsResponse
	if err := json.Unmarshal(body, &tags); err != nil {
		return nil
	}

	var installed []string
	for _, m := range tags.Models {
		installed = append(installed, m.Name)
	}
	return installed
}

// GetDefaultModel dynamically determines the best default model based on what is installed.
// Returns an empty string if Ollama is unreachable or has no generative models, and logs a
// warning so callers produce a clear error rather than a cryptic "model '' not found".
func GetDefaultModel() string {
	installed := GetInstalledModels("")

	// Filter out embedding models (e.g., nomic-embed-text) that cannot handle
	// chat/generation prompts. Sending a security analysis prompt to an
	// embedding model produces garbled or empty output.
	var generative []string
	for _, m := range installed {
		lower := strings.ToLower(m)
		if strings.Contains(lower, "embed") {
			continue
		}
		generative = append(generative, m)
	}

	if len(generative) > 0 {
		utils.LogInfo("Auto-selected Ollama model: " + generative[0])
		return generative[0]
	}

	if len(installed) > 0 {
		// All models are embedding-only — still try the first one but warn
		utils.LogWarn("Only embedding models found in Ollama. AI analysis may produce garbled output. Recommended: ollama pull qwen2.5-coder:7b")
		return installed[0]
	}

	utils.LogWarn("No Ollama models found. Start Ollama and pull a model first, e.g.: ollama pull qwen2.5-coder:7b")
	return ""
}
