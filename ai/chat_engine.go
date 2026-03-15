package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ChatMessage represents a single message in a chat conversation
type ChatMessage struct {
	Role    string `json:"role"` // system, user, assistant
	Content string `json:"content"`
}

// ChatRequest is the request body for the Ollama chat API
type ChatRequest struct {
	Model     string                 `json:"model"`
	Messages  []ChatMessage          `json:"messages"`
	Stream    bool                   `json:"stream"`
	Options   map[string]interface{} `json:"options,omitempty"`
	KeepAlive string                 `json:"keep_alive,omitempty"`
}

// ChatResponse is the response from the Ollama chat API
type ChatResponse struct {
	Model         string      `json:"model"`
	CreatedAt     time.Time   `json:"created_at"`
	Message       ChatMessage `json:"message"`
	Done          bool        `json:"done"`
	TotalDuration int64       `json:"total_duration"`
}

// GenerateChatResponse handles non-streaming chat requests to Ollama
func GenerateChatResponse(modelName string, messages []ChatMessage) (*ChatResponse, error) {
	apiURL := GetOllamaBaseURL() + "/api/chat"

	reqBody := ChatRequest{
		Model:    modelName,
		Messages: messages,
		Stream:   false,
		Options: map[string]interface{}{
			"temperature": 0.7,
			"num_ctx":     8192,
		},
		KeepAlive: "10m",
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal chat request: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(globalCtx, "POST", apiURL, bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 5 * time.Minute,
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama chat API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ollama API returned status %d", resp.StatusCode)
	}

	var chatResp ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, fmt.Errorf("failed to decode chat response: %v", err)
	}

	return &chatResp, nil
}
