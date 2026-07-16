package main

import (
	"fmt"
	"strings"

	"SentryQ/reporter"
)

// DiffResult is the result of comparing two scans.
type DiffResult struct {
	ScanA      string           `json:"scan_a"`
	ScanB      string           `json:"scan_b"`
	New        []reporter.Finding `json:"new"`        // in B but not in A
	Fixed      []reporter.Finding `json:"fixed"`      // in A but not in B
	Persisting []reporter.Finding `json:"persisting"` // in both
	Summary    DiffSummary       `json:"summary"`
}

type DiffSummary struct {
	TotalA     int `json:"total_a"`
	TotalB     int `json:"total_b"`
	NewCount   int `json:"new"`
	FixedCount int `json:"fixed"`
	Persisting int `json:"persisting"`
	// Net change in critical/high counts
	CriticalDelta int `json:"critical_delta"`
	HighDelta     int `json:"high_delta"`
}

// DiffScans compares findings between two scan IDs and returns a structured diff.
func DiffScans(scanIDA, scanIDB string) (*DiffResult, error) {
	findingsA, err := GetFindingsForScan(scanIDA)
	if err != nil {
		return nil, fmt.Errorf("failed to load scan %s: %w", scanIDA, err)
	}
	findingsB, err := GetFindingsForScan(scanIDB)
	if err != nil {
		return nil, fmt.Errorf("failed to load scan %s: %w", scanIDB, err)
	}

	// Key: RuleID + FilePath + normalised line
	keyOf := func(f reporter.Finding) string {
		return fmt.Sprintf("%s|%s|%s", f.RuleID, f.FilePath, normaliseLineRef(f.LineNumber))
	}

	setA := make(map[string]reporter.Finding, len(findingsA))
	for _, f := range findingsA {
		setA[keyOf(f)] = f
	}
	setB := make(map[string]reporter.Finding, len(findingsB))
	for _, f := range findingsB {
		setB[keyOf(f)] = f
	}

	result := &DiffResult{ScanA: scanIDA, ScanB: scanIDB}

	for k, f := range setB {
		if _, inA := setA[k]; inA {
			result.Persisting = append(result.Persisting, f)
		} else {
			result.New = append(result.New, f)
		}
	}
	for k, f := range setA {
		if _, inB := setB[k]; !inB {
			result.Fixed = append(result.Fixed, f)
		}
	}

	countSev := func(findings []reporter.Finding, sev string) int {
		n := 0
		for _, f := range findings {
			if strings.ToLower(f.Severity) == sev {
				n++
			}
		}
		return n
	}

	result.Summary = DiffSummary{
		TotalA:        len(findingsA),
		TotalB:        len(findingsB),
		NewCount:      len(result.New),
		FixedCount:    len(result.Fixed),
		Persisting:    len(result.Persisting),
		CriticalDelta: countSev(findingsB, "critical") - countSev(findingsA, "critical"),
		HighDelta:     countSev(findingsB, "high") - countSev(findingsA, "high"),
	}

	return result, nil
}

// PrintDiff renders a human-readable diff to stdout.
func PrintDiff(d *DiffResult) {
	fmt.Printf("\n┌─ Scan Diff: %s → %s\n", d.ScanA[:8], d.ScanB[:8])
	fmt.Printf("│  Total findings: %d → %d\n", d.Summary.TotalA, d.Summary.TotalB)
	fmt.Printf("│  🆕 New:        %d\n", d.Summary.NewCount)
	fmt.Printf("│  ✅ Fixed:      %d\n", d.Summary.FixedCount)
	fmt.Printf("│  ♻️  Persisting: %d\n", d.Summary.Persisting)
	sign := "+"
	if d.Summary.CriticalDelta < 0 {
		sign = ""
	}
	fmt.Printf("│  Critical Δ:    %s%d   High Δ: %s%d\n",
		sign, d.Summary.CriticalDelta,
		sign, d.Summary.HighDelta,
	)
	fmt.Println("└─────────────────────────────────────────────────────")

	if len(d.New) > 0 {
		fmt.Printf("\n🆕 New findings (%d):\n", len(d.New))
		for _, f := range d.New {
			fmt.Printf("  [%s] %s — %s:%s\n", strings.ToUpper(f.Severity), f.IssueName, f.FilePath, f.LineNumber)
		}
	}
	if len(d.Fixed) > 0 {
		fmt.Printf("\n✅ Fixed findings (%d):\n", len(d.Fixed))
		for _, f := range d.Fixed {
			fmt.Printf("  [%s] %s — %s:%s\n", strings.ToUpper(f.Severity), f.IssueName, f.FilePath, f.LineNumber)
		}
	}
}

// normaliseLineRef strips ranges like "42-45" to just "42" for fuzzy matching.
func normaliseLineRef(ref string) string {
	return strings.SplitN(ref, "-", 2)[0]
}
