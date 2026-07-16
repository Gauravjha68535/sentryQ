package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// WebhookPayload is the JSON body sent to every configured webhook URL.
type WebhookPayload struct {
	Event      string            `json:"event"`       // "scan.completed" | "scan.failed" | "policy.violated"
	ScanID     string            `json:"scan_id"`
	Target     string            `json:"target"`
	Status     string            `json:"status"`
	Timestamp  string            `json:"timestamp"`
	Summary    WebhookSummary    `json:"summary"`
	PolicyFail []PolicyViolation `json:"policy_violations,omitempty"`
	SentryQURL string            `json:"sentryq_url,omitempty"`
}

type WebhookSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// FireWebhooks sends the payload to all configured webhook URLs (fire-and-forget).
// Each URL is tried once; failures are logged but never propagate to the caller.
func FireWebhooks(urls []string, scanID, target, status string, findings []reporter.Finding, violations []PolicyViolation) {
	if len(urls) == 0 {
		return
	}

	summary := WebhookSummary{}
	for _, f := range findings {
		if f.Status == "false_positive" || f.Status == "ignored" {
			continue
		}
		summary.Total++
		switch strings.ToLower(f.Severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Info++
		}
	}

	event := "scan.completed"
	if status == "failed" {
		event = "scan.failed"
	} else if len(violations) > 0 {
		event = "policy.violated"
	}

	payload := WebhookPayload{
		Event:      event,
		ScanID:     scanID,
		Target:     target,
		Status:     status,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Summary:    summary,
		PolicyFail: violations,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		utils.LogError("webhook: failed to marshal payload", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, rawURL := range urls {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}
		go func(url string) {
			req, err := http.NewRequest("POST", url, bytes.NewReader(body))
			if err != nil {
				utils.LogWarn(fmt.Sprintf("webhook: invalid URL %s: %v", url, err))
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "SentryQ/"+reporter.Version)
			req.Header.Set("X-SentryQ-Event", event)

			resp, err := client.Do(req)
			if err != nil {
				utils.LogWarn(fmt.Sprintf("webhook: POST to %s failed: %v", url, err))
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 300 {
				utils.LogWarn(fmt.Sprintf("webhook: %s returned HTTP %d", url, resp.StatusCode))
				return
			}
			utils.LogInfo(fmt.Sprintf("webhook: notified %s (HTTP %d)", url, resp.StatusCode))
		}(rawURL)
	}
}
