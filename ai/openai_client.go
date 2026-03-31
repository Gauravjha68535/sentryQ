package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────
//  Provider Configuration
// ──────────────────────────────────────────────────────────

// Provider types
const (
	ProviderOllama = "ollama"
	ProviderOpenAI = "openai"
)

var (
	providerMu    sync.RWMutex
	activeProvider = ProviderOllama

	customAPIURL   string
	customAPIKey   string
	customModel    string
)

// SetActiveProvider switches the global AI backend.
func SetActiveProvider(provider string) {
	providerMu.Lock()
	defer providerMu.Unlock()
	if provider == ProviderOpenAI || provider == ProviderOllama {
		activeProvider = provider
	}
}

// GetActiveProvider returns the current provider.
func GetActiveProvider() string {
	providerMu.RLock()
	defer providerMu.RUnlock()
	return activeProvider
}

// SetCustomEndpoint configures the custom OpenAI-compatible endpoint.
func SetCustomEndpoint(url, apiKey, model string) {
	providerMu.Lock()
	defer providerMu.Unlock()
	customAPIURL = strings.TrimRight(url, "/")
	customAPIKey = apiKey
	customModel = model
}

// GetCustomEndpoint returns the current custom endpoint config.
func GetCustomEndpoint() (url, apiKey, model string) {
	providerMu.RLock()
	defer providerMu.RUnlock()
	return customAPIURL, customAPIKey, customModel
}

// ──────────────────────────────────────────────────────────
//  OpenAI-Compatible API Types
// ──────────────────────────────────────────────────────────

// OpenAIMessage is a single message in the OpenAI chat format.
type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAICompletionRequest is the request body for /v1/chat/completions.
type OpenAICompletionRequest struct {
	Model              string                 `json:"model"`
	Messages           []OpenAIMessage        `json:"messages"`
	Temperature        float64                `json:"temperature,omitempty"`
	MaxTokens          int                    `json:"max_tokens,omitempty"`
	Stream             bool                   `json:"stream"`
	ChatTemplateKwargs map[string]interface{} `json:"chat_template_kwargs,omitempty"`
}

// OpenAICompletionResponse is the response from /v1/chat/completions.
type OpenAICompletionResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// OpenAIModelsResponse is the response from /v1/models.
type OpenAIModelsResponse struct {
	Data []struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
	} `json:"data"`
}

// ──────────────────────────────────────────────────────────
//  OpenAI-Compatible API Functions
// ──────────────────────────────────────────────────────────

// GenerateViaOpenAI sends a prompt to an OpenAI-compatible /v1/chat/completions endpoint
// and returns the assistant response text. Includes retry logic with exponential backoff.
func GenerateViaOpenAI(ctx context.Context, baseURL, apiKey, model, prompt string, options map[string]interface{}) (string, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/chat/completions"

	temp := 0.0
	if v, ok := options["temperature"]; ok {
		if t, ok := v.(float64); ok {
			temp = t
		}
	}

	maxTokens := 8192
	if v, ok := options["num_predict"]; ok {
		if t, ok := v.(int); ok {
			maxTokens = t
		}
	}

	reqBody := OpenAICompletionRequest{
		Model: model,
		Messages: []OpenAIMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: temp,
		MaxTokens:   maxTokens,
		Stream:      false,
		ChatTemplateKwargs: map[string]interface{}{
			"enable_thinking": false,
		},
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal OpenAI request: %v", err)
	}

	const maxRetries = 3
	client := &http.Client{Timeout: 35 * time.Minute}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return "", fmt.Errorf("scan interrupted")
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqJSON))
		if err != nil {
			return "", fmt.Errorf("failed to create OpenAI request: %v", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if apiKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			if strings.Contains(err.Error(), "context canceled") {
				return "", fmt.Errorf("scan interrupted")
			}
			// Retry on transient network errors (connection reset, timeout, EOF)
			if attempt < maxRetries && isRetryableError(err) {
				// Exponential backoff with ±1 s jitter to avoid thundering herd
				backoff := time.Duration(1<<uint(attempt+1))*time.Second +
					time.Duration(rand.Int63n(int64(time.Second)))
				time.Sleep(backoff)
				continue
			}
			return "", fmt.Errorf("OpenAI API request failed: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return "", fmt.Errorf("failed to read OpenAI response body: %v", err)
		}

		// Retry on server-side transient errors (502, 503, 429)
		if attempt < maxRetries && (resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 429) {
			backoff := time.Duration(1<<uint(attempt+1))*time.Second +
				time.Duration(rand.Int63n(int64(time.Second)))
			time.Sleep(backoff)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("OpenAI API error (status %d): %s", resp.StatusCode, string(body))
		}

		var completionResp OpenAICompletionResponse
		if err := json.Unmarshal(body, &completionResp); err != nil {
			return "", fmt.Errorf("failed to parse OpenAI response: %v", err)
		}

		if completionResp.Error != nil {
			return "", fmt.Errorf("OpenAI API error: %s", completionResp.Error.Message)
		}

		if len(completionResp.Choices) == 0 {
			return "", fmt.Errorf("OpenAI API returned no choices")
		}

		return completionResp.Choices[0].Message.Content, nil
	}

	return "", fmt.Errorf("OpenAI API request failed after %d retries", maxRetries+1)
}

// isRetryableError checks if a network error is transient and worth retrying.
func isRetryableError(err error) bool {
	errMsg := err.Error()
	retryablePatterns := []string{
		"connection reset by peer",
		"connection refused",
		"EOF",
		"context deadline exceeded",
		"i/o timeout",
		"broken pipe",
		"no such host",
		"TLS handshake timeout",
	}
	for _, pattern := range retryablePatterns {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}
	return false
}

// GenerateChatViaOpenAI sends a multi-turn chat conversation to an OpenAI-compatible endpoint.
func GenerateChatViaOpenAI(ctx context.Context, baseURL, apiKey, model string, messages []ChatMessage) (*ChatResponse, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/chat/completions"

	// Convert ChatMessage to OpenAIMessage
	var oaiMessages []OpenAIMessage
	for _, m := range messages {
		oaiMessages = append(oaiMessages, OpenAIMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	reqBody := OpenAICompletionRequest{
		Model:       model,
		Messages:    oaiMessages,
		Temperature: 0.7,
		MaxTokens:   16384,
		Stream:      false,
		ChatTemplateKwargs: map[string]interface{}{
			"enable_thinking": false,
		},
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OpenAI chat request: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAI chat request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OpenAI chat API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenAI chat response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI chat API error (status %d): %s", resp.StatusCode, string(body))
	}

	var completionResp OpenAICompletionResponse
	if err := json.Unmarshal(body, &completionResp); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAI chat response: %v", err)
	}

	if len(completionResp.Choices) == 0 {
		return nil, fmt.Errorf("OpenAI chat API returned no choices")
	}

	return &ChatResponse{
		Model: completionResp.Model,
		Message: ChatMessage{
			Role:    "assistant",
			Content: completionResp.Choices[0].Message.Content,
		},
		Done: true,
	}, nil
}

// TestOpenAIEndpoint makes a lightweight test call to verify connectivity.
func TestOpenAIEndpoint(baseURL, apiKey, model string) (bool, string) {
	url := strings.TrimRight(baseURL, "/") + "/v1/chat/completions"

	reqBody := OpenAICompletionRequest{
		Model: model,
		Messages: []OpenAIMessage{
			{Role: "user", Content: "Reply with exactly: OK"},
		},
		Temperature: 0.0,
		MaxTokens:   10,
		Stream:      false,
	}

	reqJSON, _ := json.Marshal(reqBody)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqJSON))
	if err != nil {
		return false, fmt.Sprintf("Failed to create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return false, fmt.Sprintf("Connection failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("API returned status %d: %s", resp.StatusCode, truncateForUI(string(body), 200))
	}

	var completionResp OpenAICompletionResponse
	if err := json.Unmarshal(body, &completionResp); err != nil {
		return false, fmt.Sprintf("Invalid response format: %v", err)
	}

	if completionResp.Error != nil {
		return false, fmt.Sprintf("API error: %s", completionResp.Error.Message)
	}

	if len(completionResp.Choices) == 0 {
		return false, "API returned no choices"
	}

	return true, fmt.Sprintf("Connected! Model: %s", completionResp.Model)
}

// ListOpenAIModels fetches the list of available models from an OpenAI-compatible endpoint.
func ListOpenAIModels(baseURL, apiKey string) ([]string, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/models"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create models request: %v", err)
	}
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("models request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read models response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("models API error (status %d): %s", resp.StatusCode, string(body))
	}

	var modelsResp OpenAIModelsResponse
	if err := json.Unmarshal(body, &modelsResp); err != nil {
		return nil, fmt.Errorf("failed to parse models response: %v", err)
	}

	var models []string
	for _, m := range modelsResp.Data {
		models = append(models, m.ID)
	}
	return models, nil
}

// truncateForUI truncates a string for user-facing messages.
func truncateForUI(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
