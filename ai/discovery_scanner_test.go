package ai

import (
	"encoding/json"
	"testing"
)

func TestFlexInt_UnmarshalJSON(t *testing.T) {
	var testStruct struct {
		Line FlexInt `json:"line"`
	}

	jsonInt := `{"line": 42}`
	err := json.Unmarshal([]byte(jsonInt), &testStruct)
	if err != nil {
		t.Fatalf("unexpected error parsing normal int: %v", err)
	}
	if int(testStruct.Line) != 42 {
		t.Errorf("expected 42, got %d", int(testStruct.Line))
	}

	jsonArray := `{"line": [42, 43]}`
	err = json.Unmarshal([]byte(jsonArray), &testStruct)
	if err != nil {
		t.Fatalf("unexpected error parsing array int: %v", err)
	}
	if int(testStruct.Line) != 42 {
		t.Errorf("expected 42 (first of array), got %d", int(testStruct.Line))
	}
}

func TestOllamaHostConfig(t *testing.T) {
	orig := GetOllamaBaseURL()
	defer SetOllamaHost(orig)

	SetOllamaHost("my-custom-host:11434")
	if GetOllamaBaseURL() != "http://my-custom-host:11434" {
		t.Errorf("expected host to be mapped correctly, got %s", GetOllamaBaseURL())
	}
}
