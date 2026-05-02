package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	claudeMu     sync.RWMutex
	claudeAPIKey string
	claudeModel  string
)

// SetClaudeConfig stores the Anthropic API key and model name.
func SetClaudeConfig(apiKey, model string) {
	claudeMu.Lock()
	defer claudeMu.Unlock()
	claudeAPIKey = apiKey
	claudeModel = model
}

// GetClaudeConfig returns the current Anthropic API key and model name.
func GetClaudeConfig() (apiKey, model string) {
	claudeMu.RLock()
	defer claudeMu.RUnlock()
	return claudeAPIKey, claudeModel
}

// KnownClaudeModels is the current set of available Claude models.
var KnownClaudeModels = []string{
	"claude-opus-4-7",
	"claude-sonnet-4-6",
	"claude-haiku-4-5-20251001",
}

// ──────────────────────────────────────────────────────────
//  Anthropic API types
// ──────────────────────────────────────────────────────────

type claudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Messages  []claudeMessage `json:"messages"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ──────────────────────────────────────────────────────────
//  Claude API Functions
// ──────────────────────────────────────────────────────────

const claudeAPIURL = "https://api.anthropic.com/v1/messages"
const claudeAPIVersion = "2023-06-01"

// GenerateViaClaude sends a prompt to the Anthropic Claude API and returns the response text.
func GenerateViaClaude(ctx context.Context, apiKey, model, prompt string, options map[string]interface{}) (string, error) {
	if apiKey == "" {
		return "", fmt.Errorf("claude API key is required")
	}
	if model == "" {
		model = "claude-sonnet-4-6"
	}

	maxTokens := 8192
	if v, ok := options["num_predict"]; ok {
		if t, ok := v.(int); ok {
			maxTokens = t
		}
	}

	reqBody := claudeRequest{
		Model:     model,
		MaxTokens: maxTokens,
		Messages:  []claudeMessage{{Role: "user", Content: prompt}},
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Claude request: %v", err)
	}

	const maxRetries = 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return "", fmt.Errorf("scan interrupted")
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", claudeAPIURL, bytes.NewBuffer(reqJSON))
		if err != nil {
			return "", fmt.Errorf("failed to create Claude request: %v", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("x-api-key", apiKey)
		httpReq.Header.Set("anthropic-version", claudeAPIVersion)

		resp, err := aiHTTPClient.Do(httpReq)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", fmt.Errorf("scan interrupted")
			}
			if attempt < maxRetries && isRetryableError(err) {
				backoff := time.Duration(1<<uint(attempt+1))*time.Second + cryptoRandDuration(time.Second)
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return "", fmt.Errorf("scan interrupted")
				}
				continue
			}
			return "", fmt.Errorf("Claude API request failed: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		if err != nil {
			return "", fmt.Errorf("failed to read Claude response: %v", err)
		}

		// 429 = rate limit, 529 = overloaded — retry with backoff
		if attempt < maxRetries && (resp.StatusCode == 429 || resp.StatusCode == 529) {
			backoff := time.Duration(1<<uint(attempt+1))*time.Second + cryptoRandDuration(time.Second)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return "", fmt.Errorf("scan interrupted")
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("Claude API error (status %d): %s", resp.StatusCode, truncateForUI(string(body), 300))
		}

		var claudeResp claudeResponse
		if err := json.Unmarshal(body, &claudeResp); err != nil {
			return "", fmt.Errorf("failed to parse Claude response: %v", err)
		}
		if claudeResp.Error != nil {
			return "", fmt.Errorf("Claude API error: %s", claudeResp.Error.Message)
		}
		for _, block := range claudeResp.Content {
			if block.Type == "text" {
				return block.Text, nil
			}
		}
		return "", fmt.Errorf("Claude API returned no text content")
	}

	return "", fmt.Errorf("Claude API request failed after %d retries", maxRetries+1)
}

// TestClaudeEndpoint makes a lightweight test call to verify the Claude API key.
func TestClaudeEndpoint(apiKey, model string) (bool, string) {
	if apiKey == "" {
		return false, "API key is required"
	}
	if model == "" {
		model = "claude-haiku-4-5-20251001"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	text, err := GenerateViaClaude(ctx, apiKey, model, "Reply with exactly: OK", map[string]interface{}{"num_predict": 10})
	if err != nil {
		return false, fmt.Sprintf("Connection failed: %v", err)
	}
	return true, fmt.Sprintf("Connected! Model: %s — %s", model, strings.TrimSpace(text))
}
