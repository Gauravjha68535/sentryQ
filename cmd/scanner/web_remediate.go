package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"SentryQ/ai"
)


// handleFindingRemediate handles POST /api/scan/:id/finding/:findingId/remediate
// It calls the active AI provider to generate a targeted code fix for the finding.
func handleFindingRemediate(w http.ResponseWriter, r *http.Request, scanID, findingIDStr string) {
	findingID, err := strconv.Atoi(findingIDStr)
	if err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid finding ID"})
		return
	}

	finding, err := GetFindingByID(scanID, findingID)
	if err != nil {
		httpJSON(w, http.StatusNotFound, map[string]string{"error": "finding not found"})
		return
	}

	prompt := buildRemediationPrompt(finding.IssueName, finding.Severity, finding.CWE,
		finding.FilePath, finding.CodeSnippet, finding.Remediation, finding.Description)

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	appSettings.RLock()
	model := appSettings.DefaultModel
	ollamaHost := appSettings.OllamaHost
	appSettings.RUnlock()

	raw, err := ai.Generate(ctx, ai.GenerateOptions{
		Model:      model,
		Prompt:     prompt,
		OllamaHost: ollamaHost,
	})
	if err != nil {
		httpJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": fmt.Sprintf("AI unavailable: %v", err),
		})
		return
	}

	fix, explanation := parseRemediationResponse(raw)
	httpJSON(w, http.StatusOK, map[string]string{
		"fix":         fix,
		"explanation": explanation,
		"raw":         raw,
	})
}

// buildRemediationPrompt constructs a focused prompt for AI-powered code remediation.
func buildRemediationPrompt(issueName, severity, cwe, filePath, codeSnippet, remediation, description string) string {
	var b strings.Builder

	b.WriteString("You are a senior security engineer reviewing a vulnerability finding.\n\n")
	fmt.Fprintf(&b, "VULNERABILITY: %s\n", issueName)
	if severity != "" {
		fmt.Fprintf(&b, "SEVERITY: %s\n", strings.ToUpper(severity))
	}
	if cwe != "" {
		fmt.Fprintf(&b, "CWE: %s\n", cwe)
	}
	if filePath != "" {
		fmt.Fprintf(&b, "FILE: %s\n", filePath)
	}
	if description != "" {
		fmt.Fprintf(&b, "DESCRIPTION: %s\n", description)
	}
	if remediation != "" {
		fmt.Fprintf(&b, "GUIDANCE: %s\n", remediation)
	}

	if codeSnippet != "" {
		b.WriteString("\nVULNERABLE CODE:\n```\n")
		b.WriteString(codeSnippet)
		b.WriteString("\n```\n")
	}

	b.WriteString(`
Respond with EXACTLY these two sections and nothing else:

## FIXED CODE
[The corrected version of the code above. Same scope — do not rewrite unrelated parts.]

## EXPLANATION
[One to two sentences: what changed and why it fixes the vulnerability.]
`)
	return b.String()
}

// parseRemediationResponse splits the AI response into fix and explanation sections.
func parseRemediationResponse(raw string) (fix, explanation string) {
	raw = strings.TrimSpace(raw)

	fixIdx := indexSection(raw, "## FIXED CODE")
	explIdx := indexSection(raw, "## EXPLANATION")

	switch {
	case fixIdx >= 0 && explIdx >= 0 && explIdx > fixIdx:
		fixPart := strings.TrimSpace(raw[fixIdx+len("## FIXED CODE"):explIdx])
		fix = stripCodeFences(fixPart)
		explanation = strings.TrimSpace(raw[explIdx+len("## EXPLANATION"):])

	case fixIdx >= 0:
		fix = stripCodeFences(strings.TrimSpace(raw[fixIdx+len("## FIXED CODE"):]))
		explanation = ""

	default:
		// AI didn't follow the format — return raw as fix
		fix = raw
		explanation = ""
	}
	return
}

func indexSection(s, header string) int {
	idx := strings.Index(strings.ToUpper(s), strings.ToUpper(header))
	return idx
}

func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	// Remove leading ```lang or ``` fence
	if strings.HasPrefix(s, "```") {
		s = s[3:]
		if nl := strings.Index(s, "\n"); nl >= 0 {
			s = s[nl+1:]
		}
	}
	// Remove trailing ```
	if strings.HasSuffix(s, "```") {
		s = s[:len(s)-3]
	}
	return strings.TrimSpace(s)
}
