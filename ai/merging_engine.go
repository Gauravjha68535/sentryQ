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
// ConsolidateFindings takes static and ai findings and merges them using LLM intelligence
func ConsolidateFindings(staticFindings []reporter.Finding, aiFindings []reporter.Finding, modelName string) ([]reporter.Finding, error) {
	if len(staticFindings) == 0 && len(aiFindings) == 0 {
		return []reporter.Finding{}, nil
	}

	color.Cyan("🧠 Consolidating %d Static and %d AI findings using %s...", len(staticFindings), len(aiFindings), modelName)

	// Prepare simplified findings for LLM
	type SimplifiedFinding struct {
		ID          int    `json:"id"`
		Type        string `json:"type"`
		IssueName   string `json:"issue_name"`
		File        string `json:"file"`
		Line        string `json:"line"`
		Description string `json:"description"`
	}

	var allSimplified []SimplifiedFinding
	idCount := 1
	for _, f := range staticFindings {
		allSimplified = append(allSimplified, SimplifiedFinding{ID: idCount, Type: "static", IssueName: f.IssueName, File: f.FilePath, Line: f.LineNumber, Description: f.Description})
		idCount++
	}
	for _, f := range aiFindings {
		allSimplified = append(allSimplified, SimplifiedFinding{ID: idCount, Type: "ai", IssueName: f.IssueName, File: f.FilePath, Line: f.LineNumber, Description: f.Description})
		idCount++
	}

	findingsJSON, _ := json.Marshal(allSimplified)
	prompt := fmt.Sprintf(`You are an elite Security Orchestrator and Senior Auditor. 
You have two lists of security findings: one from a Static Rule Engine and one from an AI Discovery Engine.
Your goal is to semantically MERGE these two lists into one final, deduplicated, high-precision report.

SEMANTIC DEDUPLICATION STRATEGY:
1. IDENTIFY DUPLICATES: If both engines found the same issue (e.g. SQL Injection) on the same line or very close lines in the same file, they are the SAME issue.
2. SINK OVERLAP: If multiple rules fire on the same dangerous function call (e.g. 'eval()', 'cursor.execute()'), they are the SAME issue.
3. FLOW OVERLAP: If multiple rules track the same data flow but trigger at different points (source vs sink), group them into the sink finding.
4. PRIORITIZE AI CONTENT: When merging a duplicate, ALWAYS use the "ai" version's description and issue name, as the AI has deeper context.

INPUT FINDINGS:
%s

OUTPUT PROTOCOL:
Return a JSON object containing a list of merged_findings.
For each group of duplicates, pick a "Master" ID and list the others as "Duplicate IDs".
Provide a brief "Reason" for the merge.

{
  "merged_findings": [
    {
      "master_id": 5,
      "duplicate_ids": [1], 
      "reason": "Both identified the same root cause on line 42."
    },
    {
      "master_id": 2,
      "duplicate_ids": [],
      "reason": "Unique finding."
    }
  ]
}`, string(findingsJSON))

	reqBody := OllamaAPIRequest{
		Model:   modelName,
		Prompt:  prompt,
		Stream:  false,
		Options: map[string]interface{}{"num_ctx": 16384, "num_predict": 4096, "temperature": 0.0},
	}

	reqJSON, _ := json.Marshal(reqBody)
	resp, err := http.Post(ollamaAPIURL, "application/json", bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiResp OllamaAPIResponse
	json.NewDecoder(resp.Body).Decode(&apiResp)
	outputStr := strings.TrimSpace(apiResp.Response)

	// Extract JSON block
	startIdx := strings.Index(outputStr, "{")
	endIdx := strings.LastIndex(outputStr, "}")
	if startIdx < 0 || endIdx <= startIdx {
		return nil, fmt.Errorf("invalid response from merger LLM")
	}

	var decision struct {
		MergedFindings []struct {
			MasterID     int   `json:"master_id"`
			DuplicateIDs []int `json:"duplicate_ids"`
		} `json:"merged_findings"`
	}
	json.Unmarshal([]byte(outputStr[startIdx:endIdx+1]), &decision)

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
			// Persist AI validation status
			isAiValidated := (f.AiValidated == "Yes")
			if !isAiValidated {
				for _, dupID := range m.DuplicateIDs {
					if dup, ok := findingByID[dupID]; ok && dup.AiValidated == "Yes" {
						isAiValidated = true
						break
					}
				}
			}
			if isAiValidated {
				f.AiValidated = "Yes"
			}
			finalFindings = append(finalFindings, f)
			addedIDs[m.MasterID] = true
			for _, d := range m.DuplicateIDs {
				addedIDs[d] = true
			}
		}
	}

	// Catch-all for missed IDs
	for id, f := range findingByID {
		if !addedIDs[id] {
			finalFindings = append(finalFindings, f)
		}
	}

	color.HiGreen("✅ Consolidation complete. Final unique finding count: %d", len(finalFindings))
	return finalFindings, nil
}
