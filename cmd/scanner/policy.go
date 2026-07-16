package main

import (
	"fmt"
	"os"
	"strings"

	"SentryQ/reporter"
)

// PolicyConfig holds CI gate thresholds supplied via CLI flags or env vars.
type PolicyConfig struct {
	FailOn      string // severity level that triggers immediate failure ("critical","high","medium","low")
	MaxCritical int    // -1 = no limit
	MaxHigh     int
	MaxMedium   int
	MaxLow      int
	MaxTotal    int
}

// DefaultPolicyConfig returns a permissive policy (nothing fails by default).
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		MaxCritical: -1,
		MaxHigh:     -1,
		MaxMedium:   -1,
		MaxLow:      -1,
		MaxTotal:    -1,
	}
}

// PolicyViolation describes a single broken policy gate.
type PolicyViolation struct {
	Gate    string
	Actual  int
	Limit   int
	Message string
}

// EvaluatePolicy checks findings against the policy and returns any violations.
// An empty slice means the policy passed.
func EvaluatePolicy(findings []reporter.Finding, p PolicyConfig) []PolicyViolation {
	counts := map[string]int{}
	for _, f := range findings {
		if f.Status == "false_positive" || f.Status == "ignored" {
			continue
		}
		counts[strings.ToLower(f.Severity)]++
		counts["total"]++
	}

	var violations []PolicyViolation

	// --fail-on: any finding at this severity or above triggers a failure
	if p.FailOn != "" {
		order := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
		threshold := order[strings.ToLower(p.FailOn)]
		for sev, n := range counts {
			if n > 0 && order[sev] >= threshold {
				violations = append(violations, PolicyViolation{
					Gate:    "--fail-on " + p.FailOn,
					Actual:  n,
					Limit:   0,
					Message: fmt.Sprintf("%d %s finding(s) found (fail-on: %s)", n, sev, p.FailOn),
				})
			}
		}
	}

	check := func(gate string, actual, limit int) {
		if limit >= 0 && actual > limit {
			violations = append(violations, PolicyViolation{
				Gate:    gate,
				Actual:  actual,
				Limit:   limit,
				Message: fmt.Sprintf("%s count %d exceeds limit %d", gate, actual, limit),
			})
		}
	}

	check("max-critical", counts["critical"], p.MaxCritical)
	check("max-high", counts["high"], p.MaxHigh)
	check("max-medium", counts["medium"], p.MaxMedium)
	check("max-low", counts["low"], p.MaxLow)
	check("max-total", counts["total"], p.MaxTotal)

	return violations
}

// PrintPolicyResult prints the policy evaluation result and returns the exit code.
// 0 = pass, 1 = policy violated.
func PrintPolicyResult(violations []PolicyViolation) int {
	if len(violations) == 0 {
		fmt.Println("✅ Policy check PASSED — all gates within limits.")
		return 0
	}

	fmt.Fprintln(os.Stderr, "\n❌ Policy check FAILED:")
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "   • %s\n", v.Message)
	}
	return 1
}
