package ai

import (
	"QWEN_SCR_24_FEB_2026/utils"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ModelRecommendation struct {
	Name        string
	Size        string
	RAMRequired string
	Speed       string
	Accuracy    string
	Description string
	FitsRAM     bool // NEW: Indicates if model fits available RAM
	Installed   bool // NEW: Indicates if model is currently installed
}

type OllamaTagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

// GetInstalledModels fetches the list of locally installed models from Ollama
func GetInstalledModels() []string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(GetOllamaBaseURL() + "/api/tags")
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
	installed := GetInstalledModels()

	// If the user has explicitly installed models, try to pick the best one
	if len(installed) > 0 {
		return installed[0]
	}

	// Fallback if Ollama isn't running or no models installed
	return ""
}

func GetModelRecommendations(ram *utils.RAMInfo) []ModelRecommendation {
	allModels := []ModelRecommendation{
		{Name: "deepseek-r1:7b", Size: "7B", RAMRequired: "8GB", Speed: "Fast", Accuracy: "Excellent", Description: "Advanced reasoning model"},
		{Name: "deepseek-coder:6.7b", Size: "6.7B", RAMRequired: "8GB", Speed: "Fast", Accuracy: "Excellent", Description: "Specialized for code analysis"},
		{Name: "deepseek-coder:1.3b", Size: "1.3B", RAMRequired: "2GB", Speed: "Very Fast", Accuracy: "Moderate", Description: "Ultra-lightweight"},
		{Name: "codeqwen:7b", Size: "7B", RAMRequired: "8GB", Speed: "Fast", Accuracy: "Very Good", Description: "Strong general-purpose code understanding"},
		{Name: "qwen2.5-coder:7b", Size: "7B", RAMRequired: "8GB", Speed: "Fast", Accuracy: "Excellent", Description: "State-of-the-art coding capabilities"},
		{Name: "llama3.1:8b", Size: "8B", RAMRequired: "10GB", Speed: "Medium", Accuracy: "Excellent", Description: "Balanced performance for code security"},
		{Name: "mistral:7b-instruct", Size: "7B", RAMRequired: "8GB", Speed: "Fast", Accuracy: "Very Good", Description: "Efficient instruction-following"},
		{Name: "codellama:7b-instruct", Size: "7B", RAMRequired: "8GB", Speed: "Fast", Accuracy: "Very Good", Description: "Code-specialized Llama variant"},
		{Name: "starcoder2:7b", Size: "7B", RAMRequired: "8GB", Speed: "Fast", Accuracy: "Very Good", Description: "Trained on 600+ programming languages"},
		{Name: "phi3:mini", Size: "3.8B", RAMRequired: "4GB", Speed: "Very Fast", Accuracy: "Good", Description: "Lightweight for low-RAM systems"},
		{Name: "wizardcoder:7b", Size: "7B", RAMRequired: "8GB", Speed: "Fast", Accuracy: "Very Good", Description: "Fine-tuned for code generation"},
		{Name: "llama3.1:13b", Size: "13B", RAMRequired: "16GB", Speed: "Medium", Accuracy: "Best", Description: "Highest accuracy for validation"},
	}

	installed := GetInstalledModels()
	installedMap := make(map[string]bool)
	for _, m := range installed {
		installedMap[m] = true
	}

	availableThreshold := ram.AvailableGB * 0.8

	// Create final list starting with installed models
	var finalModels []ModelRecommendation

	// First, add ALL actually installed models (even if not in our hardcoded list)
	for _, inst := range installed {
		found := false
		for i := range allModels {
			// Compare exact or without :tag
			if allModels[i].Name == inst || strings.Split(allModels[i].Name, ":")[0] == strings.Split(inst, ":")[0] {
				model := allModels[i]
				model.Name = inst
				model.Installed = true
				ramReq := 0
				fmt.Sscanf(model.RAMRequired, "%dGB", &ramReq)
				model.FitsRAM = float64(ramReq) <= availableThreshold
				finalModels = append(finalModels, model)
				found = true
				break
			}
		}

		// If an installed model isn't in our list, add it generically
		if !found {
			finalModels = append(finalModels, ModelRecommendation{
				Name:        inst,
				Size:        "Unknown",
				RAMRequired: "Unknown",
				Speed:       "Unknown",
				Accuracy:    "Unknown",
				Description: "Locally installed model",
				FitsRAM:     true, // Assume it fits if they installed it
				Installed:   true,
			})
		}
	}

	// Then add remaining generic recommendations ONLY if no models are installed
	if len(installed) == 0 {
		for _, model := range allModels {
			if !installedMap[model.Name] {
				model.Installed = false
				ramReq := 0
				fmt.Sscanf(model.RAMRequired, "%dGB", &ramReq)
				model.FitsRAM = float64(ramReq) <= availableThreshold
				finalModels = append(finalModels, model)
			}
		}
	}

	return finalModels
}
