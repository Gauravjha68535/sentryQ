package main

import (
	"fmt"
	"strings"

	"SentryQ/reporter"
)

// evaluatePolicyGate checks scan findings against configured policy thresholds
// and broadcasts a PASS or FAIL event to the websocket.
func evaluatePolicyGate(scanID string, cfg WebScanConfig, findings []reporter.Finding, criticalCount, highCount int) {
	severityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

	hasPolicy := cfg.PolicyFailOn != "" || cfg.MaxCritical >= 0 || cfg.MaxHigh >= 0 || cfg.MaxMedium >= 0 || cfg.MaxLow >= 0 || cfg.MaxTotal >= 0
	if !hasPolicy {
		return
	}

	violated := false
	var reasons []string

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

	// PolicyFailOn: fail if any finding meets or exceeds the threshold severity
	if cfg.PolicyFailOn != "" {
		threshold := severityOrder[strings.ToLower(cfg.PolicyFailOn)]
		for sev, cnt := range counts {
			if cnt > 0 && severityOrder[sev] >= threshold {
				violated = true
				reasons = append(reasons, fmt.Sprintf("%d %s finding(s) at or above '%s' threshold", cnt, sev, cfg.PolicyFailOn))
			}
		}
	}

	// MaxCritical
	if cfg.MaxCritical >= 0 && counts["critical"] > cfg.MaxCritical {
		violated = true
		reasons = append(reasons, fmt.Sprintf("critical count %d exceeds limit %d", counts["critical"], cfg.MaxCritical))
	}
	// MaxHigh
	if cfg.MaxHigh >= 0 && counts["high"] > cfg.MaxHigh {
		violated = true
		reasons = append(reasons, fmt.Sprintf("high count %d exceeds limit %d", counts["high"], cfg.MaxHigh))
	}
	// MaxMedium
	if cfg.MaxMedium >= 0 && counts["medium"] > cfg.MaxMedium {
		violated = true
		reasons = append(reasons, fmt.Sprintf("medium count %d exceeds limit %d", counts["medium"], cfg.MaxMedium))
	}
	// MaxLow — was missing from hasPolicy guard AND evaluation body
	if cfg.MaxLow >= 0 && counts["low"] > cfg.MaxLow {
		violated = true
		reasons = append(reasons, fmt.Sprintf("low count %d exceeds limit %d", counts["low"], cfg.MaxLow))
	}
	// MaxTotal
	if cfg.MaxTotal >= 0 && total > cfg.MaxTotal {
		violated = true
		reasons = append(reasons, fmt.Sprintf("total findings %d exceeds limit %d", total, cfg.MaxTotal))
	}

	if violated {
		msg := fmt.Sprintf("❌ POLICY GATE FAILED: %s", strings.Join(reasons, "; "))
		wsHub.BroadcastLog(scanID, msg, "error")
	} else {
		wsHub.BroadcastLog(scanID, "✅ POLICY GATE PASSED: all thresholds satisfied", "success")
	}
}

