package ai

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
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

// GetDefaultModel dynamically determines the best default model based on what is installed
func GetDefaultModel() string {
	installed := GetInstalledModels("")

	// If the user has explicitly installed models, try to pick the best one
	if len(installed) > 0 {
		return installed[0]
	}

	// Fallback if Ollama isn't running or no models installed
	return ""
}
