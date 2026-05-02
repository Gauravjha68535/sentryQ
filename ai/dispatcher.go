package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

)

// GenerateOptions contains common parameters for AI generation across all providers.
type GenerateOptions struct {
	Model       string
	Prompt      string
	Temperature float32
	NumPredict  int
	OllamaHost  string // Optional: overrides global if provided
}

// Generate dispatches an AI generation request to the currently active provider.
func Generate(ctx context.Context, opts GenerateOptions) (string, error) {
	provider := GetActiveProvider()
	
	genOpts := map[string]interface{}{
		"temperature": opts.Temperature,
		"num_predict": opts.NumPredict,
	}
	if opts.NumPredict == 0 {
		genOpts["num_predict"] = 8192
	}

	var outputStr string

	switch provider {
	case ProviderOpenAI:
		customURL, customKey, customMdl := GetCustomEndpoint()
		useModel := customMdl
		if useModel == "" {
			useModel = opts.Model
		}
		fullText, err := GenerateViaOpenAI(ctx, customURL, customKey, useModel, opts.Prompt, genOpts)
		if err != nil {
			return "", fmt.Errorf("OpenAI request failed: %v", err)
		}
		outputStr = fullText

	case ProviderLMStudio:
		lmsURL, lmsMdl := GetLMStudioConfig()
		useModel := lmsMdl
		if useModel == "" {
			useModel = opts.Model
		}
		fullText, err := GenerateViaOpenAI(ctx, lmsURL, "", useModel, opts.Prompt, genOpts)
		if err != nil {
			return "", fmt.Errorf("LM Studio request failed: %v", err)
		}
		outputStr = fullText

	case ProviderClaude:
		claudeKey, claudeMdl := GetClaudeConfig()
		fullText, err := GenerateViaClaude(ctx, claudeKey, claudeMdl, opts.Prompt, genOpts)
		if err != nil {
			return "", fmt.Errorf("Claude request failed: %v", err)
		}
		outputStr = fullText

	case ProviderGemini:
		geminiKey, geminiMdl := GetGeminiConfig()
		fullText, err := GenerateViaGemini(ctx, geminiKey, geminiMdl, opts.Prompt, genOpts)
		if err != nil {
			return "", fmt.Errorf("Gemini request failed: %v", err)
		}
		outputStr = fullText

	default: // ProviderOllama
		reqBody := OllamaAPIRequest{
			Model:  opts.Model,
			Prompt: opts.Prompt,
			Stream: false,
			Options: map[string]interface{}{
				"num_ctx":     4096,
				"num_predict": opts.NumPredict,
				"temperature": opts.Temperature,
			},
			KeepAlive: "15m",
		}
		
		if opts.NumPredict == 0 {
			reqBody.Options["num_predict"] = 1024
		}

		reqJSON, err := json.Marshal(reqBody)
		if err != nil {
			return "", fmt.Errorf("failed to marshal request: %v", err)
		}

		baseURL := GetOllamaBaseURL()
		if opts.OllamaHost != "" {
			if strings.HasPrefix(opts.OllamaHost, "http://") || strings.HasPrefix(opts.OllamaHost, "https://") {
				baseURL = opts.OllamaHost
			} else {
				baseURL = "http://" + opts.OllamaHost
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/api/generate", bytes.NewBuffer(reqJSON))
		if err != nil {
			return "", fmt.Errorf("failed to create request: %v", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := aiHTTPClient.Do(httpReq)
		if err != nil {
			return "", fmt.Errorf("ollama API request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()              //nolint:errcheck
			return "", fmt.Errorf("ollama API returned status %d", resp.StatusCode)
		}

		body, readErr := readOllamaResponse(resp.Body)
		resp.Body.Close() //nolint:errcheck
		if readErr != nil {
			return "", fmt.Errorf("failed to read Ollama response: %v", readErr)
		}

		outputStr = body
	}

	return strings.TrimSpace(outputStr), nil
}
