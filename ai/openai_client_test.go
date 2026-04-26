package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetActiveProvider(t *testing.T) {
	orig := GetActiveProvider()
	defer SetActiveProvider(orig)

	SetActiveProvider(ProviderOpenAI)
	if GetActiveProvider() != ProviderOpenAI {
		t.Errorf("expected %s, got %s", ProviderOpenAI, GetActiveProvider())
	}
}

func TestSetCustomEndpoint(t *testing.T) {
	u, a, m := GetCustomEndpoint()
	defer SetCustomEndpoint(u, a, m)

	SetCustomEndpoint("http://custom.com/v1", "key1", "mod1")
	u2, a2, m2 := GetCustomEndpoint()
	if u2 != "http://custom.com/v1" || a2 != "key1" || m2 != "mod1" {
		t.Errorf("expected custom configuration, got %s %s %s", u2, a2, m2)
	}
}

func TestCryptoRandDuration(t *testing.T) {
	max := 1500 * time.Millisecond
	
	// Check distribution bounds
	for i := 0; i < 100; i++ {
		d := cryptoRandDuration(max)
		if d < 0 || d >= max {
			t.Errorf("duration %v out of bounds [0, %v)", d, max)
		}
	}
}

func TestIsRetryableError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("connection reset by peer"), true},
		{fmt.Errorf("EOF"), true},
		{fmt.Errorf("i/o timeout"), true},
		{fmt.Errorf("broken pipe"), true},
		{fmt.Errorf("TLS handshake timeout"), true},
		{fmt.Errorf("Some other non-retryable error"), false},
	}
	
	for _, c := range cases {
		if got := isRetryableError(c.err); got != c.want {
			t.Errorf("isRetryableError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestGenerateViaOpenAI_Success(t *testing.T) {
	mockResponse := `{
		"choices": [{
			"message": {
				"content": "successfully generated text"
			}
		}]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(mockResponse))
	}))
	defer srv.Close()

	resp, err := GenerateViaOpenAI(context.Background(), srv.URL, "testkey", "gpt-4", "system prompt", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp != "successfully generated text" {
		t.Errorf("unexpected response: %s", resp)
	}
}

func TestTestOpenAIEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock the completion response
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"model": "gpt-4",
			"choices": [{
				"message": {
					"content": "OK"
				}
			}]
		}`))
	}))
	defer srv.Close()

	ok, errMsg := TestOpenAIEndpoint(srv.URL, "test-key", "gpt-4")
	if !ok {
		t.Errorf("expected no error, got %v", errMsg)
	}
}

func TestListOpenAIModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"id": "gpt-4"},
				{"id": "gpt-3.5-turbo"},
			},
		})
	}))
	defer srv.Close()

	models, err := ListOpenAIModels(srv.URL, "test-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(models) != 2 || models[0] != "gpt-4" {
		t.Errorf("unexpected models returned: %v", models)
	}
}
