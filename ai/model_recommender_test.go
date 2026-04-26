package ai

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestGetInstalledModels_Success(t *testing.T) {
	mockResponse := `{
		"models": [
			{"name": "llama3:latest"},
			{"name": "mistral:latest"},
			{"name": "nomic-embed-text:latest"}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(mockResponse))
	}))
	defer srv.Close()

	models := GetInstalledModels(srv.URL)
	expected := []string{"llama3:latest", "mistral:latest", "nomic-embed-text:latest"}
	
	if !reflect.DeepEqual(models, expected) {
		t.Errorf("expected models %v, got %v", expected, models)
	}
}

func TestGetInstalledModels_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	models := GetInstalledModels(srv.URL)
	if len(models) != 0 {
		t.Errorf("expected empty models list on error, got %v", models)
	}
}

func TestGetDefaultModelFallback(t *testing.T) {
	// Let's just test that GetDefaultModel doesn't panic
	// Since we don't have the actual internal list in this test, we just call it.
	model := GetDefaultModel()
	if model == "" {
		t.Log("GetDefaultModel returned empty string (no models available)")
	}
}
