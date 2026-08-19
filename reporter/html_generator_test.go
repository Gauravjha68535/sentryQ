package reporter

import "testing"

func TestNormalizeOWASP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"N/A", "N/A"},
		{"n/a", "n/a"},
		{"A01:2021-Broken Access Control", "A01:2021-Broken Access Control"},
		{"A03:2021", "A03:2021"},
		{"OWASP A01 Broken Access Control", "N/A"},
		{"A10:2021", "A10:2021"},
		{"A10:2021 - Server-Side Request Forgery", "A10:2021-Server-Side Request Forgery"},
	}
	for _, tt := range tests {
		got := NormalizeOWASP(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeOWASP(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeCWE(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"N/A", "N/A"},
		{"CWE-89", "CWE-89"},
		{"CWE-89: SQL Injection", "CWE-89"},
		{"CWE-79 Cross-site Scripting", "CWE-79"},
		{"arbitrary text", "N/A"},
		{"CWE-22", "CWE-22"},
	}
	for _, tt := range tests {
		got := NormalizeCWE(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeCWE(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAggregateCWE(t *testing.T) {
	findings := []Finding{
		{CWE: "CWE-89: SQL Injection"},
		{CWE: "CWE-89"},
		{CWE: "CWE-79"},
		{CWE: "N/A"},
		{CWE: ""},
	}
	result := aggregateCWE(findings)

	if len(result) != 2 {
		t.Fatalf("expected 2 CWE entries, got %d", len(result))
	}
	// CWE-89 should be first (count 2)
	if result[0].Key != "CWE-89" || result[0].Count != 2 {
		t.Errorf("expected CWE-89 count=2, got key=%s count=%d", result[0].Key, result[0].Count)
	}
	if result[1].Key != "CWE-79" || result[1].Count != 1 {
		t.Errorf("expected CWE-79 count=1, got key=%s count=%d", result[1].Key, result[1].Count)
	}
}
