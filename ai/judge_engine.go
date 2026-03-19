package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
)

// JudgeFinding is a lightweight representation of a finding for feeding to the Judge LLM
type JudgeFinding struct {
	ID          int    `json:"id"`
	Source      string `json:"source"` // "static" or "ai"
	IssueName   string `json:"issue_name"`
	File        string `json:"file"`
	Line        string `json:"line"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	CWE         string `json:"cwe,omitempty"`
}

// JudgeVerdict is the expected response structure from the Judge LLM
type JudgeVerdict struct {
	Findings []JudgeVerdictItem `json:"findings"`
}

// JudgeVerdictItem represents one Judge decision on a group of findings
type JudgeVerdictItem struct {
	MasterID       int    `json:"master_id"`
	DuplicateIDs   []int  `json:"duplicate_ids"`
	Verdict        string `json:"verdict"` // "keep", "drop", "merge"
	Reason         string `json:"reason"`
	Severity       string `json:"final_severity,omitempty"`
	SimplifiedName string `json:"simplified_name,omitempty"`
}

const maxJudgeBatchSize = 10 // Small batches prevent remote LLM timeouts with reasoning models

// JudgeFindings takes two independent reports (static and AI) and uses a Judge LLM
// to deduplicate, remove false positives, and merge them into one master report.
func JudgeFindings(staticFindings []reporter.Finding, aiFindings []reporter.Finding, judgeModel string, judgeOllamaHost string) ([]reporter.Finding, error) {
	if len(staticFindings) == 0 && len(aiFindings) == 0 {
		return []reporter.Finding{}, nil
	}

	utils.LogInfo(fmt.Sprintf("⚖️  Judge LLM starting review: %d static + %d AI findings using model %s",
		len(staticFindings), len(aiFindings), judgeModel))

	// Only judge static findings from files that also have AI findings (massive speedup)
	aiFiles := make(map[string]bool)
	for _, f := range aiFindings {
		aiFiles[f.FilePath] = true
	}
	var relevantStatic []reporter.Finding
	var passThroughStatic []reporter.Finding
	for _, f := range staticFindings {
		if aiFiles[f.FilePath] {
			relevantStatic = append(relevantStatic, f)
		} else {
			passThroughStatic = append(passThroughStatic, f)
		}
	}
	utils.LogInfo(fmt.Sprintf("⚖️  Filtering: %d static findings overlap with AI files, %d pass through directly",
		len(relevantStatic), len(passThroughStatic)))

	// Configure Ollama host for the judge if different
	originalHost := GetOllamaBaseURL()
	if judgeOllamaHost != "" {
		SetOllamaHost(judgeOllamaHost)
		defer SetOllamaHost(strings.TrimPrefix(strings.TrimPrefix(originalHost, "http://"), "https://"))
	}

	// Build ID-indexed maps for both sets
	findingByID := make(map[int]reporter.Finding)
	var allJudge []JudgeFinding
	idCounter := 1

	for _, f := range relevantStatic {
		findingByID[idCounter] = f
		allJudge = append(allJudge, JudgeFinding{
			ID:          idCounter,
			Source:      "static",
			IssueName:   f.IssueName,
			File:        f.FilePath,
			Line:        f.LineNumber,
			Severity:    f.Severity,
			Description: truncateString(f.Description, 200),
			CWE:         f.CWE,
		})
		idCounter++
	}

	for _, f := range aiFindings {
		findingByID[idCounter] = f
		allJudge = append(allJudge, JudgeFinding{
			ID:          idCounter,
			Source:      "ai",
			IssueName:   f.IssueName,
			File:        f.FilePath,
			Line:        f.LineNumber,
			Severity:    f.Severity,
			Description: truncateString(f.Description, 200),
			CWE:         f.CWE,
		})
		idCounter++
	}

	// Batch the findings if too many
	var allVerdicts []JudgeVerdictItem
	batches := batchJudgeFindings(allJudge, maxJudgeBatchSize)

	for batchIdx, batch := range batches {
		utils.LogInfo(fmt.Sprintf("⚖️  Judge batch %d/%d (%d findings)...", batchIdx+1, len(batches), len(batch)))

		verdicts, err := runJudgeBatch(batch, judgeModel)
		if err != nil {
			utils.LogWarn(fmt.Sprintf("Judge batch %d failed: %v — keeping all findings in batch", batchIdx+1, err))
			// On failure, keep all findings from this batch as-is
			for _, jf := range batch {
				allVerdicts = append(allVerdicts, JudgeVerdictItem{
					MasterID: jf.ID,
					Verdict:  "keep",
					Reason:   "Judge evaluation failed; retained as-is",
				})
			}
			continue
		}
		allVerdicts = append(allVerdicts, verdicts...)
	}

	// Apply verdicts
	var finalFindings []reporter.Finding
	droppedIDs := make(map[int]bool)
	mergedIDs := make(map[int]bool)

	for _, v := range allVerdicts {
		if v.Verdict == "drop" {
			droppedIDs[v.MasterID] = true
			for _, d := range v.DuplicateIDs {
				droppedIDs[d] = true
			}
			continue
		}

		// Mark duplicates as merged
		for _, d := range v.DuplicateIDs {
			mergedIDs[d] = true
		}

		if f, ok := findingByID[v.MasterID]; ok {
			// Override severity if the Judge specified one
			if v.Severity != "" {
				f.Severity = v.Severity
			}

			// Clean up the issue name if Judge provided a simplified one
			if v.SimplifiedName != "" {
				f.IssueName = v.SimplifiedName
			}

			// If the master is a static finding but a duplicate is an AI finding,
			// prefer the AI description for richer context
			for _, dupID := range v.DuplicateIDs {
				if dup, ok := findingByID[dupID]; ok {
					if dup.AiValidated == "Yes" {
						f.AiValidated = "Yes"
					}
					// Merge sources
					if !strings.Contains(f.Source, dup.Source) {
						f.Source = f.Source + ", " + dup.Source
					}
				}
			}

			finalFindings = append(finalFindings, f)
			mergedIDs[v.MasterID] = true
		}
	}

	// Catch-all: any finding not mentioned in verdicts gets kept
	for id, f := range findingByID {
		if !droppedIDs[id] && !mergedIDs[id] {
			finalFindings = append(finalFindings, f)
		}
	}

	// Add back all static findings from files without AI findings (they bypass the judge)
	finalFindings = append(finalFindings, passThroughStatic...)

	utils.LogInfo(fmt.Sprintf("⚖️  Judge complete: %d judged + %d pass-through → %d final findings (%d dropped, %d merged)",
		len(relevantStatic)+len(aiFindings), len(passThroughStatic), len(finalFindings),
		len(droppedIDs), len(mergedIDs)-len(finalFindings)+len(passThroughStatic)))

	return finalFindings, nil
}

// runJudgeBatch sends a single batch of findings to the Judge LLM
func runJudgeBatch(findings []JudgeFinding, modelName string) ([]JudgeVerdictItem, error) {
	findingsJSON, _ := json.MarshalIndent(findings, "", "  ")

	// Create a fresh context for this judge request - don't reuse potentially cancelled context
	judgeCtx, judgeCancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer judgeCancel()

	prompt := fmt.Sprintf(`You are a Supreme Security Auditor and Judge. You have received findings from TWO independent security scanners that analyzed the same codebase:

1. **Static Scanner** (source: "static") — regex patterns, AST parsing, taint analysis, dependency checks
2. **AI Scanner** (source: "ai") — LLM-based code analysis and vulnerability discovery

Your job is to produce a FINAL, deduplicated, high-precision verdict.

## RULES:
1. **DUPLICATES**: If both scanners found the same vulnerability type in the same file on the same or adjacent lines (±5 lines), they are DUPLICATES. Pick the one with the richer description as "master_id" and list the other as "duplicate_ids".
2. **FALSE POSITIVES**: If a finding is clearly a false positive (e.g., a test file, a comment, dead code, or a safe usage pattern), mark its verdict as "drop".
3. **UNIQUE FINDINGS**: If a finding is unique to one scanner and appears valid, keep it. Verdict: "keep".
4. **SEVERITY ADJUSTMENT**: If the combined evidence from both scanners suggests the severity should change, set "final_severity".
5. **SIMPLIFIED NAME**: For ALL kept findings, you MUST provide a "simplified_name". Convert raw or technical rule IDs (like "java-dangerous-runtime-exec", "js-json-escape") into human-readable, standard vulnerability categories (e.g., "Command Injection", "SQL Injection", "Cross-Site Scripting (XSS)", "Hardcoded Secret", "Path Traversal").
6. **PRIORITIZE AI DESCRIPTIONS**: When merging, prefer the AI scanner's description since it provides deeper context.

## INPUT FINDINGS:
%s

## OUTPUT FORMAT (strict JSON, no markdown):
{
  "findings": [
    {
      "master_id": 1,
      "duplicate_ids": [5],
      "verdict": "keep",
      "reason": "Both scanners detected SQL injection on line 42. Merged.",
      "final_severity": "critical",
      "simplified_name": "SQL Injection"
    },
    {
      "master_id": 3,
      "duplicate_ids": [],
      "verdict": "drop",
      "reason": "False positive: variable is sanitized before use on line 50."
    }
  ]
}

IMPORTANT: Every finding ID from the input MUST appear exactly once — either as a master_id or inside a duplicate_ids array. Do not skip any.`, string(findingsJSON))

	reqBody := OllamaAPIRequest{
		Model:  modelName,
		Prompt: prompt,
		Stream: false,
		Options: map[string]interface{}{
			"num_ctx":     32768,
			"num_predict": 8192,
			"temperature": 0.0,
		},
	}

	reqJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(judgeCtx, "POST", ollamaAPIURL, bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create judge request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 20 * time.Minute, // Remote 32b+ models processing 40 findings need 10-20 min
	}
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "context canceled") {
			return nil, fmt.Errorf("judge evaluation interrupted")
		}
		return nil, fmt.Errorf("judge LLM request failed: %v", err)
	}
	defer resp.Body.Close()

	var apiResp OllamaAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode judge response: %v", err)
	}

	outputStr := strings.TrimSpace(apiResp.Response)

	// Extract JSON block using common utility
	jsonStr := utils.ExtractJSON(outputStr)

	var verdict JudgeVerdict
	if err := json.Unmarshal([]byte(jsonStr), &verdict); err != nil {
		return nil, fmt.Errorf("failed to parse judge verdict: %v", err)
	}

	return verdict.Findings, nil
}

// batchJudgeFindings splits findings into batches of maxSize
func batchJudgeFindings(findings []JudgeFinding, maxSize int) [][]JudgeFinding {
	if len(findings) <= maxSize {
		return [][]JudgeFinding{findings}
	}

	var batches [][]JudgeFinding
	for i := 0; i < len(findings); i += maxSize {
		end := i + maxSize
		if end > len(findings) {
			end = len(findings)
		}
		batches = append(batches, findings[i:end])
	}
	return batches
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
