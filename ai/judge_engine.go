package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"SentryQ/reporter"
	"SentryQ/utils"
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

const maxJudgeBatchSize = 5 // Small batches prevent remote LLM timeouts with reasoning models

// JudgeFindings takes two independent reports (static and AI) and uses a Judge LLM
// to deduplicate, remove false positives, and merge them into one master report.
func JudgeFindings(ctx context.Context, staticFindings []reporter.Finding, aiFindings []reporter.Finding, judgeModel string, judgeOllamaHost string) ([]reporter.Finding, error) {
	if len(staticFindings) == 0 && len(aiFindings) == 0 {
		return []reporter.Finding{}, nil
	}

	utils.LogInfo(fmt.Sprintf("⚖️  Judge LLM starting review: %d static + %d AI findings using model %s",
		len(staticFindings), len(aiFindings), judgeModel))

	// Both static and AI findings are sent to the Judge in full so it can evaluate all static findings
	// including those in files where AI didn't natively discover anything.

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

	for _, f := range staticFindings {
		findingByID[idCounter] = f
		allJudge = append(allJudge, JudgeFinding{
			ID:          idCounter,
			Source:      "static",
			IssueName:   f.IssueName,
			File:        f.FilePath,
			Line:        f.LineNumber,
			Severity:    f.Severity,
			Description: truncateString(f.Description, 4000),
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
			Description: truncateString(f.Description, 4000),
			CWE:         f.CWE,
		})
		idCounter++
	}

	// Batch the findings if too many
	var allVerdicts []JudgeVerdictItem
	batches := batchJudgeFindings(allJudge, maxJudgeBatchSize)

	for batchIdx, batch := range batches {
		utils.LogInfo(fmt.Sprintf("⚖️  Judge batch %d/%d (%d findings)...", batchIdx+1, len(batches), len(batch)))

		verdicts, err := runJudgeBatch(ctx, batch, judgeModel)
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

			// Finding was explicitly kept by AI Judge, meaning it passed AI validation
			if f.AiValidated != "Yes" && !strings.Contains(f.AiValidated, "Discovered") {
				f.AiValidated = "Yes"
			}
			if f.AiReasoning == "" && v.Reason != "" {
				f.AiReasoning = "AI Judge: " + v.Reason
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

	utils.LogInfo(fmt.Sprintf("⚖️  Judge complete: %d judged → %d final findings (%d dropped, %d merged)",
		len(staticFindings)+len(aiFindings), len(finalFindings),
		len(droppedIDs), len(mergedIDs)))

	return finalFindings, nil
}

// runJudgeBatch sends a single batch of findings to the Judge LLM
func runJudgeBatch(ctx context.Context, findings []JudgeFinding, modelName string) ([]JudgeVerdictItem, error) {
	findingsJSON, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize findings for judge: %w", err)
	}

	// Create a fresh context for this judge request
	// 15 minutes max for full batch response (large models + long batches)
	judgeCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	prompt := fmt.Sprintf(`You are a Supreme Security Auditor and Judge. You have received findings from TWO independent security scanners that analyzed the same codebase:

1. **Static Scanner** (source: "static") — regex patterns, AST parsing, taint analysis, dependency checks
2. **AI Scanner** (source: "ai") — LLM-based code analysis and vulnerability discovery

Your job is to produce a FINAL, deduplicated, high-precision verdict.

## RULES:
1. **DUPLICATES**: If both scanners found the same vulnerability type in the same file on the same or adjacent lines (±5 lines), they are DUPLICATES. Pick the one with the richer description as "master_id" and list the other as "duplicate_ids".
2. **FALSE POSITIVES**: If a finding is clearly a false positive (e.g., a test file, a comment, dead code, or a safe usage pattern), mark its verdict as "drop".
3. **FALSE POSITIVE AVOIDANCE**: Do NOT keep findings that flag safe parameterized queries ('?', '$1'), secure RNGs ('crypto.randomBytes'), or safe document properties ('textContent') as vulnerable. Mark them as "drop".
4. **UNIQUE FINDINGS**: If a finding is unique to one scanner and appears valid, keep it. Verdict: "keep".
5. **SEVERITY ADJUSTMENT**: If the combined evidence from both scanners suggests the severity should change, set "final_severity".
6. **SIMPLIFIED NAME**: For ALL kept findings, you MUST provide a "simplified_name". Convert raw or technical rule IDs into human-readable, standard vulnerability categories (e.g., "Command Injection", "SQL Injection", "XSS", "Hardcoded Secret").
7. **PRIORITIZE AI DESCRIPTIONS**: When merging, prefer the AI scanner's description since it provides deeper context.

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

	var outputStr string

	// Dispatch based on active provider
	if GetActiveProvider() == ProviderOpenAI {
		customURL, customKey, customMdl := GetCustomEndpoint()
		useModel := customMdl
		if useModel == "" {
			useModel = modelName
		}
		fullText, err := GenerateViaOpenAI(judgeCtx, customURL, customKey, useModel, prompt, map[string]interface{}{
			"temperature": 0.0,
			"num_predict": 8192,
		})
		if err != nil {
			if strings.Contains(err.Error(), "context canceled") || strings.Contains(err.Error(), "scan interrupted") {
				return nil, fmt.Errorf("judge evaluation interrupted")
			}
			return nil, fmt.Errorf("judge LLM request failed: %v", err)
		}
		outputStr = strings.TrimSpace(fullText)
	} else {
		reqJSON, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize judge request body: %w", err)
		}

		req, err := http.NewRequestWithContext(judgeCtx, "POST", ollamaAPIURL, bytes.NewBuffer(reqJSON))
		if err != nil {
			return nil, fmt.Errorf("failed to create judge request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{
			Timeout: 20 * time.Minute,
		}
		resp, err := client.Do(req)
		if err != nil {
			if strings.Contains(err.Error(), "context canceled") {
				return nil, fmt.Errorf("judge evaluation interrupted")
			}
			return nil, fmt.Errorf("judge LLM request failed: %v", err)
		}
		defer resp.Body.Close()

		fullText, readErr := readOllamaResponse(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read judge response: %v", readErr)
		}
		outputStr = strings.TrimSpace(fullText)
	}

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
