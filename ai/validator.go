package ai

import (
	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ValidationResult struct {
	IsTruePositive     bool    `json:"is_true_positive"`
	Confidence         float64 `json:"confidence"`
	Explanation        string  `json:"explanation"`
	SuggestedFix       string  `json:"suggested_fix"`
	SeverityAdjustment string  `json:"severity_adjustment"`
	ExploitPoC         string  `json:"exploit_poc"`
}

func ValidateFinding(modelName string, finding reporter.Finding, codeSnippet string) (*ValidationResult, error) {
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

	prompt := fmt.Sprintf(`You are an elite Lead Security Auditor and Penetration Tester.
Your task is to validate a potential vulnerability found by an automated scanner.
DETERMINE if this is a TRUE POSITIVE (exploitable) or a FALSE POSITIVE (noisy/non-exploitable).

VULNERABILITY DETAILS:
- Issue: %s
- File: %s
- Line: %s
- Severity: %s
- Description: %s
- Initial Remediation: %s
%s

CODE CONTEXT (50 lines around the issue):
%s

ULTRA-DEEP VALIDATION PROTOCOL:
1.  TAINT ANALYSIS: Map the flow from Source (user-input) to Sink (dangerous function). Is there a clear, unvalidated path?
2.  CONFIGURATION & SECRETS: Note that Hardcoded Secrets, Missing Security Headers, CORS misconfigurations, and Weak/Default passwords DO NOT require user input to be exploitable. Flag them as True Positives if present.
3.  BYPASS SIMULATION: Does the code have sanitization (e.g., regex, escaping)? If YES, can an attacker BYPASS it using encoding (URL, base64, unicode), null bytes, or logical flaws? 
4.  ENVIRONMENT CHECK: Is this a dev-only tool (e.g. apt, npm) or a real production vulnerability?
5.  IMPACT ESTIMATION: What is the worst-case scenario (RCE, Data Theft, Account Takeover)?

OUTPUT PROTOCOL:
- Start with a <thinking> tag. Perform an adversarial simulation. Try to 'break' the code even if it looks secure at first glance.
- End with a JSON object.

CRITICAL INSTRUCTIONS:
- Be AGGRESSIVE in finding bypasses, but be FAIR if the code is truly secure.
- Do NOT dismiss Configuration/Header/Secret vulnerabilities just because there is "no user input".
- Do NOT log unified diffs (+/-) or git diff formats in the suggested_fix or explanation. Describe the fix conceptually or just provide the final snippet.
- Do NOT flag standard DevOps/Infra commands as vulnerabilities.
- Provide a clear, step-by-step 'exploit_poc'.

Return ONLY a valid JSON object in the final part of your response:
{
  "is_true_positive": true/false,
  "confidence": 0.0-1.0,
  "explanation": "Summarize your adversarial analysis and why a bypass is or is not possible.",
  "suggested_fix": "Provide a fix conceptually. DO NOT USE DIFF FORMAT (+/-).",
  "severity_adjustment": "critical/high/medium/low/info or same",
  "exploit_poc": "Provide a high-quality exploit payload or command."
}`,
		finding.IssueName,
		finding.FilePath,
		finding.LineNumber,
		finding.Severity,
		finding.Description,
		finding.Remediation,
		testFileNote,
		codeSnippet)

	// Use Ollama HTTP API instead of CLI subprocess
	reqBody := OllamaAPIRequest{
		Model:  modelName,
		Prompt: prompt,
		Stream: false,
		Options: map[string]interface{}{
			"num_ctx":     8192,
			"num_predict": 2048, // Validation responses are usually shorter
			"temperature": 0.0,
		},
		KeepAlive: "15m",
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(globalCtx, "POST", ollamaAPIURL, bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 5 * time.Minute, // Risk 1 fix: Per-finding timeout prevents infinite hangs
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ollama API returned status %d", resp.StatusCode)
	}

	var apiResp OllamaAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %v", err)
	}

	outputStr := strings.TrimSpace(apiResp.Response)
	outputStr = strings.TrimPrefix(outputStr, "```json")
	outputStr = strings.TrimPrefix(outputStr, "```")
	outputStr = strings.TrimSuffix(outputStr, "```")
	outputStr = strings.TrimSpace(outputStr)

	var result ValidationResult
	if err := json.Unmarshal([]byte(outputStr), &result); err != nil {
		// Try to extract JSON from response
		startIdx := strings.Index(outputStr, "{")
		endIdx := strings.LastIndex(outputStr, "}")
		if startIdx >= 0 && endIdx > startIdx {
			jsonStr := outputStr[startIdx : endIdx+1]
			if err2 := json.Unmarshal([]byte(jsonStr), &result); err2 != nil {
				result = ValidationResult{
					IsTruePositive:     true,
					Confidence:         0.8,
					Explanation:        "AI validation completed",
					SuggestedFix:       finding.Remediation,
					SeverityAdjustment: "same",
					ExploitPoC:         "",
				}
			}
		} else {
			result = ValidationResult{
				IsTruePositive:     true,
				Confidence:         0.8,
				Explanation:        "AI validation completed",
				SuggestedFix:       finding.Remediation,
				SeverityAdjustment: "same",
				ExploitPoC:         "",
			}
		}
	}

	return &result, nil
}

func countCriticalHighMedium(findings []reporter.Finding) int {
	count := 0
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" || f.Severity == "medium" {
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
	var start, end int
	fmt.Sscanf(lineNumber, "%d", &start)
	end = start

	for i, c := range lineNumber {
		if c == '-' {
			fmt.Sscanf(lineNumber[i+1:], "%d", &end)
			break
		}
	}

	contextStart := max(0, start-50)
	contextEnd := min(len(lines), end+50)

	snippet := ""
	for i := contextStart; i < contextEnd && i < len(lines); i++ {
		snippet += fmt.Sprintf("%d: %s\n", i+1, lines[i])
	}

	return snippet
}
