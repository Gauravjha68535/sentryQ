package reporter

import (
	"strings"
	"testing"
)

func TestCSVSafeInjectionPrevention(t *testing.T) {
	cases := []struct {
		name  string
		input string
		safe  bool // true = should NOT start with the trigger char
	}{
		{"formula eq",    "=CMD|'/c calc'!A0", true},
		{"formula plus",  "+cmd|'/c calc'!A0", true},
		{"formula minus", "-1+1", true},
		{"formula at",    "@SUM(A1)", true},
		{"tab prefix",    "\tcell", true},
		{"cr prefix",     "\rcell", true},
		{"plain text",    "SQL Injection", false},
		{"empty",         "", false},
		{"safe number",   "42", false},
		{"url safe",      "https://example.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := csvSafe(tc.input)
			if tc.safe {
				if !strings.HasPrefix(got, "'") {
					t.Errorf("csvSafe(%q) = %q: expected leading quote to neutralise formula trigger", tc.input, got)
				}
			} else {
				if strings.HasPrefix(got, "'") {
					t.Errorf("csvSafe(%q) = %q: unexpected leading quote on safe input", tc.input, got)
				}
			}
		})
	}
}

func TestCSVSafePreservesContent(t *testing.T) {
	// The prefix quote should be added but the rest of the content intact
	out := csvSafe("=evil")
	if out != "'=evil" {
		t.Errorf("csvSafe(=evil) = %q, want \"'=evil\"", out)
	}
}

func TestFindingToRowLength(t *testing.T) {
	f := Finding{
		SrNo:      1,
		IssueName: "SQL Injection",
		FilePath:  "src/db.go",
		Severity:  "critical",
	}
	row := findingToRow(f)
	const expectedCols = 18
	if len(row) != expectedCols {
		t.Errorf("findingToRow returned %d columns, want %d", len(row), expectedCols)
	}
}
