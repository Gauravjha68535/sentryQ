package ai

import (
	"SentryQ/reporter"
	"SentryQ/utils"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ValidationResult struct {
	TaintSourceIdentified      bool    `json:"taint_source_identified"`
	SanitizerOrMitigationFound bool    `json:"sanitizer_or_mitigation_found"`
	SinkIsReachable            bool    `json:"sink_is_reachable"`
	IsTruePositive             bool    `json:"is_true_positive"`
	Confidence                 float64 `json:"confidence"`
	Explanation                string  `json:"explanation"`
	SuggestedFix               string  `json:"suggested_fix"`
	SeverityAdjustment         string  `json:"severity_adjustment"`
	ExploitPoC                 string  `json:"exploit_poc"`
}

// ValidateFinding sends a single finding to the AI model for validation
func ValidateFinding(ctx context.Context, modelName string, finding reporter.Finding, fileContent string, relatedFilesContext string) (*ValidationResult, error) {
	// Detect if this is a test file
	isTestFile := false
	testIndicators := []string{"_test.", ".test.", ".spec.", "/test/", "/tests/", "/__tests__/", "/mock/", "/fixture/"}
	lowerPath := strings.ToLower(finding.FilePath)
	for _, indicator := range testIndicators {
		if strings.Contains(lowerPath, indicator) {
			isTestFile = true
			break
		}
	}

	testFileNote := ""
	if isTestFile {
		testFileNote = "\n⚠️ NOTE: This file is a TEST file. Test files commonly contain hardcoded credentials, insecure configurations, and mock data for testing purposes. These are almost always FALSE POSITIVES unless the test itself is deployed to production.\n"
	}

	crossFileNote := ""
	if relatedFilesContext != "" {
		crossFileNote = "\nRELATED CROSS-FILE CONTEXT (Dependencies, imports, or callers):\n" + relatedFilesContext + "\n"
	}

	prompt := fmt.Sprintf(`You are a Senior Security Code Reviewer.
Your task is to validate a potential vulnerability found by an automated scanner.
DETERMINE if this is a TRUE POSITIVE (real, exploitable issue) or a FALSE POSITIVE (non-issue / noise).

VULNERABILITY DETAILS:
- Issue: %s
- File: %s
- Line: %s
- Severity: %s
- Description: %s
- Initial Remediation: %s
%s

CODE CONTEXT (Full File or Primary Snippet):
%s
%s
VALIDATION STEPS:
1.  TAINT ANALYSIS: Map the flow from Source (user-input) to Sink (dangerous function). Is there a clear, unvalidated path?
2.  CONFIGURATION & SECRETS: Note that Hardcoded Secrets, Missing Security Headers, CORS misconfigurations, and Weak/Default passwords DO NOT require user input to be dangerous. Flag them as True Positives if present.
3.  FILTER ANALYSIS: Does the code have sanitization (e.g., regex, escaping)? If YES, could it be insufficient?
4.  ENVIRONMENT CHECK: Is this a dev-only tool or a real production vulnerability?
5.  IMPACT ESTIMATION: What is the worst-case scenario?

OUTPUT:
- Start with a <thinking> tag for step-by-step analysis.
- End with a JSON object.
- If no vulnerability is present, set is_true_positive to false.

INSTRUCTIONS:
- Be thorough but fair. Do NOT dismiss Configuration/Secret vulnerabilities just because there is "no user input".
- Do NOT generate git diffs or code blocks in suggested_fix. Describe the fix in plain text.
- Do NOT flag standard DevOps/Infra commands as vulnerabilities.
- Provide a clear 'exploit_poc' field with the HTTP request, curl command, or payload. Use 'N/A' if the issue is not externally triggerable.

Return ONLY a valid JSON object in the final part of your response:
{
  "taint_source_identified": true/false,
  "sanitizer_or_mitigation_found": true/false,
  "sink_is_reachable": true/false,
  "is_true_positive": true/false,
  "confidence": 0.0-1.0,
  "explanation": "Your analysis summary.",
  "suggested_fix": "Describe the fix in plain text.",
  "severity_adjustment": "critical/high/medium/low/info or same",
  "exploit_poc": "Proof of concept or N/A."
}`,
		finding.IssueName,
		finding.FilePath,
		finding.LineNumber,
		finding.Severity,
		finding.Description,
		finding.Remediation,
		testFileNote,
		fileContent,
		crossFileNote)

	// Dispatch based on active provider
	var outputStr string

	if GetActiveProvider() == ProviderOpenAI {
		customURL, customKey, customMdl := GetCustomEndpoint()
		useModel := customMdl
		if useModel == "" {
			useModel = modelName
		}
		valCtx, valCancel := context.WithTimeout(ctx, 10*time.Minute)
		defer valCancel()
		fullText, err := GenerateViaOpenAI(valCtx, customURL, customKey, useModel, prompt, map[string]interface{}{
			"temperature": 0.0,
			"num_predict": 16384,
		})
		if err != nil {
			return nil, fmt.Errorf("OpenAI validation request failed: %v", err)
		}
		outputStr = strings.TrimSpace(fullText)
	} else {
		// Use Ollama HTTP API instead of CLI subprocess
		reqBody := OllamaAPIRequest{
			Model:  modelName,
			Prompt: prompt,
			Stream: false,
			Options: map[string]interface{}{
				"num_ctx":     4096,
				"num_predict": 1024,
				"temperature": 0.0,
			},
			KeepAlive: "15m",
		}

		reqJSON, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %v", err)
		}

		valCtx, valCancel := context.WithTimeout(ctx, 10*time.Minute)
		defer valCancel()

		httpReq, err := http.NewRequestWithContext(valCtx, "POST", ollamaAPIURL, bytes.NewBuffer(reqJSON))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		client := &http.Client{
			Timeout: 12 * time.Minute,
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("ollama API request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("ollama API returned status %d", resp.StatusCode)
		}

		fullText, readErr := readOllamaResponse(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read Ollama response: %v", readErr)
		}
		outputStr = strings.TrimSpace(fullText)
	}

	outputStr = strings.TrimPrefix(outputStr, "```json")
	outputStr = strings.TrimPrefix(outputStr, "```")
	outputStr = strings.TrimSuffix(outputStr, "```")
	outputStr = strings.TrimSpace(outputStr)

	var result ValidationResult
	// Extract JSON from response using common utility
	jsonStr := utils.ExtractJSON(outputStr)

	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		// Try EscapeUnescapedQuotes repair
		repairedJSON := utils.EscapeUnescapedQuotes(jsonStr)
		if err2 := json.Unmarshal([]byte(repairedJSON), &result); err2 != nil {
			// Fallback: mark as uncertain instead of fabricating a strong result
			result = ValidationResult{
				IsTruePositive:     true,
				Confidence:         0.5,
				Explanation:        "AI validation response could not be parsed. Keeping finding as precaution.",
				SuggestedFix:       finding.Remediation,
				SeverityAdjustment: "same",
				ExploitPoC:         "N/A",
			}
		}
	}

	// Sanity-check: if confidence parsed as 0, it's likely a parse issue — set to 0.5
	if result.Confidence == 0 && result.IsTruePositive {
		result.Confidence = 0.5
	}

	return &result, nil
}

func countCriticalHighMedium(findings []reporter.Finding) int {
	count := 0
	for _, f := range findings {
		// Count anything that IS NOT explicitly low/info (this catches missing/empty severities too)
		if f.Severity != "low" && f.Severity != "info" {
			count++
		}
	}
	return count
}

func getCodeSnippet(fileContents map[string]string, filePath string, lineNumber string) string {
	content, ok := fileContents[filePath]
	if !ok {
		return ""
	}

	lines := strings.Split(utils.NormalizeNewlines(content), "\n")

	// For small files (≤500 lines), send the entire file for maximum context
	if len(lines) <= 500 {
		snippet := ""
		for i, line := range lines {
			snippet += fmt.Sprintf("%d: %s\n", i+1, line)
		}
		return snippet
	}

	// For larger files, use ±150 lines around the finding (300 lines total)
	var start, end int
	fmt.Sscanf(lineNumber, "%d", &start)
	end = start

	for i, c := range lineNumber {
		if c == '-' {
			fmt.Sscanf(lineNumber[i+1:], "%d", &end)
			break
		}
	}

	contextStart := max(0, start-150)
	contextEnd := min(len(lines), end+150)

	snippet := ""
	for i := contextStart; i < contextEnd && i < len(lines); i++ {
		snippet += fmt.Sprintf("%d: %s\n", i+1, lines[i])
	}

	return snippet
}
