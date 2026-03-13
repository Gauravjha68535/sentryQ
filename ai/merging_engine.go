package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"QWEN_SCR_24_FEB_2026/reporter"

	"github.com/fatih/color"
)

// ConsolidateFindings takes static and ai findings and merges them using LLM intelligence
func ConsolidateFindings(staticFindings []reporter.Finding, aiFindings []reporter.Finding, modelName string) ([]reporter.Finding, error) {
	if len(staticFindings) == 0 && len(aiFindings) == 0 {
		return []reporter.Finding{}, nil
	}

	color.Cyan("🧠 Consolidating %d Static and %d AI findings using %s...", len(staticFindings), len(aiFindings), modelName)

	// Prepare the findings for the LLM
	// We'll send a simplified version to save tokens
	type SimplifiedFinding struct {
		ID          int    `json:"id"`
		Type        string `json:"type"` // "static" or "ai"
		IssueName   string `json:"issue_name"`
		File        string `json:"file"`
		Line        string `json:"line"`
		Description string `json:"description"`
	}

	var allSimplified []SimplifiedFinding
	idCount := 1

	for _, f := range staticFindings {
		allSimplified = append(allSimplified, SimplifiedFinding{
			ID:          idCount,
			Type:        "static",
			IssueName:   f.IssueName,
			File:        f.FilePath,
			Line:        f.LineNumber,
			Description: f.Description,
		})
		idCount++
	}

	for _, f := range aiFindings {
		allSimplified = append(allSimplified, SimplifiedFinding{
			ID:          idCount,
			Type:        "ai",
			IssueName:   f.IssueName,
			File:        f.FilePath,
			Line:        f.LineNumber,
			Description: f.Description,
		})
		idCount++
	}

	findingsJSON, _ := json.MarshalIndent(allSimplified, "", "  ")

	prompt := fmt.Sprintf(`You are an elite Security Orchestrator. You have two lists of security findings: one from a Static Rule Engine and one from an AI Discovery Engine.
Your goal is to semantically MERGE these two lists into one final, deduplicated masterpiece.

RULES FOR MERGING:
1. IDENTIFY DUPLICATES: If both engines found the same issue (e.g. SQL Injection) on the same line or very close lines in the same file, they are the SAME issue.
2. PRIORITIZE AI CONTENT: When merging a duplicate, ALWAYS use the "ai" version's description and issue name, as the AI has deeper context.
3. PRESERVE UNIQUE ISSUES: If an issue appears only in the Static list or only in the AI list, keep it.
4. CORRELATE: If multiple static rules point to the same root cause, group them into one comprehensive finding.

INPUT FINDINGS:
%s

OUTPUT PROTOCOL:
Return a JSON object containing a list of the IDs that should be kept in the final report. For merged items, specify which ID is the "Master" and which are "Duplicates".

Respond ONLY with valid JSON:
{
  "merged_findings": [
    {
      "master_id": 5,
      "duplicate_ids": [1], 
      "reason": "Both identified the same SQL injection sink on line 42."
    },
    {
      "master_id": 2,
      "duplicate_ids": [],
      "reason": "Unique static rule finding."
    }
  ]
}`, string(findingsJSON))

	reqBody := OllamaAPIRequest{
		Model:  modelName,
		Prompt: prompt,
		Stream: false,
		Options: map[string]interface{}{
			"num_ctx":     8192,
			"num_predict": 4096,
			"temperature": 0.0,
		},
		KeepAlive: "5m",
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(ollamaAPIURL, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp OllamaAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	// Extract JSON
	outputStr := strings.TrimSpace(apiResp.Response)
	startIdx := strings.Index(outputStr, "{")
	endIdx := strings.LastIndex(outputStr, "}")
	if startIdx < 0 || endIdx <= startIdx {
		return nil, fmt.Errorf("invalid response from merger LLM")
	}
	jsonStr := outputStr[startIdx : endIdx+1]

	type MergeDecision struct {
		MergedFindings []struct {
			MasterID     int   `json:"master_id"`
			DuplicateIDs []int `json:"duplicate_ids"`
		} `json:"merged_findings"`
	}

	var decision MergeDecision
	if err := json.Unmarshal([]byte(jsonStr), &decision); err != nil {
		return nil, fmt.Errorf("failed to parse merge decision: %v", err)
	}

	// Map findings back to IDs
	findingByID := make(map[int]reporter.Finding)
	idCount = 1
	for _, f := range staticFindings {
		findingByID[idCount] = f
		idCount++
	}
	for _, f := range aiFindings {
		findingByID[idCount] = f
		idCount++
	}

	var finalFindings []reporter.Finding
	addedIDs := make(map[int]bool)

	for _, m := range decision.MergedFindings {
		if f, ok := findingByID[m.MasterID]; ok {
			finalFindings = append(finalFindings, f)
			addedIDs[m.MasterID] = true
			for _, dupID := range m.DuplicateIDs {
				addedIDs[dupID] = true
			}
		}
	}

	// Safety check: Add any missing IDs that the LLM might have forgotten
	for id, f := range findingByID {
		if !addedIDs[id] {
			finalFindings = append(finalFindings, f)
		}
	}

	color.HiGreen("✅ Consolidation complete. Final unique finding count: %d", len(finalFindings))
	return finalFindings, nil
}
