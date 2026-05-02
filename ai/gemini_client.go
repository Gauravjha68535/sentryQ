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
	geminiMu     sync.RWMutex
	geminiAPIKey string
	geminiModel  string
)

// SetGeminiConfig stores the Google Gemini API key and model name.
func SetGeminiConfig(apiKey, model string) {
	geminiMu.Lock()
	defer geminiMu.Unlock()
	geminiAPIKey = apiKey
	geminiModel = model
}

// GetGeminiConfig returns the current Gemini API key and model name.
func GetGeminiConfig() (apiKey, model string) {
	geminiMu.RLock()
	defer geminiMu.RUnlock()
	return geminiAPIKey, geminiModel
}

// KnownGeminiModels is the current set of available Gemini models.
var KnownGeminiModels = []string{
	"gemini-2.0-flash",
	"gemini-2.5-flash-preview-04-17",
	"gemini-2.5-pro-preview-05-06",
	"gemini-1.5-pro",
	"gemini-1.5-flash",
}

// ──────────────────────────────────────────────────────────
//  Google Gemini API types
// ──────────────────────────────────────────────────────────

type geminiRequest struct {
	Contents         []geminiContent         `json:"contents"`
	GenerationConfig *geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	Temperature     float64 `json:"temperature,omitempty"`
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ──────────────────────────────────────────────────────────
//  Gemini API Functions
// ──────────────────────────────────────────────────────────

const geminiAPIBase = "https://generativelanguage.googleapis.com/v1beta/models"

// GenerateViaGemini sends a prompt to the Google Gemini API and returns the response text.
func GenerateViaGemini(ctx context.Context, apiKey, model, prompt string, options map[string]interface{}) (string, error) {
	if apiKey == "" {
		return "", fmt.Errorf("gemini API key is required")
	}
	if model == "" {
		model = "gemini-2.0-flash"
	}

	maxTokens := 8192
	if v, ok := options["num_predict"]; ok {
		if t, ok := v.(int); ok {
			maxTokens = t
		}
	}

	reqBody := geminiRequest{
		Contents: []geminiContent{{Parts: []geminiPart{{Text: prompt}}}},
		GenerationConfig: &geminiGenerationConfig{
			Temperature:     0.0,
			MaxOutputTokens: maxTokens,
		},
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Gemini request: %v", err)
	}

	url := fmt.Sprintf("%s/%s:generateContent?key=%s", geminiAPIBase, model, apiKey)

	const maxRetries = 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return "", fmt.Errorf("scan interrupted")
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqJSON))
		if err != nil {
			return "", fmt.Errorf("failed to create Gemini request: %v", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

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
			return "", fmt.Errorf("Gemini API request failed: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck
		if err != nil {
			return "", fmt.Errorf("failed to read Gemini response: %v", err)
		}

		// 429 = quota exceeded, 503 = overloaded — retry with backoff
		if attempt < maxRetries && (resp.StatusCode == 429 || resp.StatusCode == 503) {
			backoff := time.Duration(1<<uint(attempt+1))*time.Second + cryptoRandDuration(time.Second)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return "", fmt.Errorf("scan interrupted")
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("Gemini API error (status %d): %s", resp.StatusCode, truncateForUI(string(body), 300))
		}

		var geminiResp geminiResponse
		if err := json.Unmarshal(body, &geminiResp); err != nil {
			return "", fmt.Errorf("failed to parse Gemini response: %v", err)
		}
		if geminiResp.Error != nil {
			return "", fmt.Errorf("Gemini API error: %s", geminiResp.Error.Message)
		}
		if len(geminiResp.Candidates) == 0 {
			return "", fmt.Errorf("Gemini API returned no candidates")
		}

		var sb strings.Builder
		for _, part := range geminiResp.Candidates[0].Content.Parts {
			sb.WriteString(part.Text)
		}
		return sb.String(), nil
	}

	return "", fmt.Errorf("Gemini API request failed after %d retries", maxRetries+1)
}

// TestGeminiEndpoint makes a lightweight test call to verify the Gemini API key.
func TestGeminiEndpoint(apiKey, model string) (bool, string) {
	if apiKey == "" {
		return false, "API key is required"
	}
	if model == "" {
		model = "gemini-2.0-flash"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	text, err := GenerateViaGemini(ctx, apiKey, model, "Reply with exactly: OK", map[string]interface{}{"num_predict": 10})
	if err != nil {
		return false, fmt.Sprintf("Connection failed: %v", err)
	}
	return true, fmt.Sprintf("Connected! Model: %s — %s", model, strings.TrimSpace(text))
}
