package main

import (
	"fmt"
	"strings"

	"SentryQ/reporter"
)

// evaluatePolicyGate checks scan findings against configured policy thresholds,
// broadcasts a PASS/FAIL event to the websocket, and returns any policy violations
// so callers can forward them to webhooks.
func evaluatePolicyGate(scanID string, cfg WebScanConfig, findings []reporter.Finding) []PolicyViolation {
	severityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

	hasPolicy := cfg.PolicyFailOn != "" || cfg.MaxCritical >= 0 || cfg.MaxHigh >= 0 || cfg.MaxMedium >= 0 || cfg.MaxLow >= 0 || cfg.MaxTotal >= 0
	if !hasPolicy {
		return nil
	}

	var violations []PolicyViolation

	// Count severities
	counts := map[string]int{}
	for _, f := range findings {
		if f.Status != "false_positive" && f.Status != "ignored" {
			counts[strings.ToLower(f.Severity)]++
		}
	}
	total := 0
	for _, v := range counts {
		total += v
	}

	addViolation := func(gate, msg string, actual, limit int) {
		violations = append(violations, PolicyViolation{Gate: gate, Actual: actual, Limit: limit, Message: msg})
	}

	// PolicyFailOn: fail if any finding meets or exceeds the threshold severity
	if cfg.PolicyFailOn != "" {
		threshold := severityOrder[strings.ToLower(cfg.PolicyFailOn)]
		for sev, cnt := range counts {
			if cnt > 0 && severityOrder[sev] >= threshold {
				addViolation("fail-on "+cfg.PolicyFailOn,
					fmt.Sprintf("%d %s finding(s) at or above '%s' threshold", cnt, sev, cfg.PolicyFailOn), cnt, 0)
			}
		}
	}

	if cfg.MaxCritical >= 0 && counts["critical"] > cfg.MaxCritical {
		addViolation("max-critical", fmt.Sprintf("critical count %d exceeds limit %d", counts["critical"], cfg.MaxCritical), counts["critical"], cfg.MaxCritical)
	}
	if cfg.MaxHigh >= 0 && counts["high"] > cfg.MaxHigh {
		addViolation("max-high", fmt.Sprintf("high count %d exceeds limit %d", counts["high"], cfg.MaxHigh), counts["high"], cfg.MaxHigh)
	}
	if cfg.MaxMedium >= 0 && counts["medium"] > cfg.MaxMedium {
		addViolation("max-medium", fmt.Sprintf("medium count %d exceeds limit %d", counts["medium"], cfg.MaxMedium), counts["medium"], cfg.MaxMedium)
	}
	if cfg.MaxLow >= 0 && counts["low"] > cfg.MaxLow {
		addViolation("max-low", fmt.Sprintf("low count %d exceeds limit %d", counts["low"], cfg.MaxLow), counts["low"], cfg.MaxLow)
	}
	if cfg.MaxTotal >= 0 && total > cfg.MaxTotal {
		addViolation("max-total", fmt.Sprintf("total findings %d exceeds limit %d", total, cfg.MaxTotal), total, cfg.MaxTotal)
	}

	if len(violations) > 0 {
		var msgs []string
		for _, v := range violations {
			msgs = append(msgs, v.Message)
		}
		wsHub.BroadcastLog(scanID, fmt.Sprintf("❌ POLICY GATE FAILED: %s", strings.Join(msgs, "; ")), "error")
	} else {
		wsHub.BroadcastLog(scanID, "✅ POLICY GATE PASSED: all thresholds satisfied", "success")
	}
	return violations
}

