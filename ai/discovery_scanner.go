package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"

	"github.com/fatih/color"
)

var aiHTTPClient = &http.Client{
	Timeout: 35 * time.Minute, // Must exceed the per-request context timeout (30m)
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
}

func init() {
}

// FlexInt handles AI models returning line_number as either int (42) or array ([14, 20, 26]).
// When an array is returned, we take the first element.
type FlexInt int

func (fi *FlexInt) UnmarshalJSON(data []byte) error {
	// Try int first
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*fi = FlexInt(n)
		return nil
	}
	// Try array of ints
	var arr []int
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		*fi = FlexInt(arr[0])
		return nil
	}
	// Default to 0
	*fi = 0
	return nil
}

// DiscoveryFinding represents a single vulnerability found by AI
type DiscoveryFinding struct {
	IssueName        string  `json:"issue_name"`
	Severity         string  `json:"severity"`
	LineNumber       FlexInt `json:"line_number"`
	Description      string  `json:"description"`
	Remediation      string  `json:"remediation"`
	ExploitPoC       string  `json:"exploit_poc"`
	CWE              string  `json:"cwe"`
	OWASP            string  `json:"owasp"`
	Confidence       float64 `json:"confidence"`
	FixedCodeSnippet string  `json:"fixed_code_snippet"`
}

// DiscoveryResponse is the expected JSON response from the AI
type DiscoveryResponse struct {
	Vulnerabilities []DiscoveryFinding `json:"vulnerabilities"`
}

// supportedDiscoveryExtensions lists file extensions the AI discovery engine will scan
var supportedDiscoveryExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".go": true, ".java": true,
	".rb": true, ".php": true, ".cs": true, ".c": true, ".cpp": true,
	".h": true, ".sh": true, ".bash": true, ".sql": true,
	".dockerfile": true, ".tf": true, ".hcl": true,
	".env": true, ".config": true, ".properties": true,
}

// buildProjectContext generates a compact project tree + extracted imports for multi-vector AI context.
// This helps the AI understand the project architecture, not just the isolated file.
func buildProjectContext(targetDir string, filesToScan []string) string {
	var sb strings.Builder
	sb.WriteString("PROJECT CONTEXT (for architectural awareness):\n")

	// 1. Build compact directory tree (max 80 entries)
	sb.WriteString("\n--- Directory Structure ---\n")
	dirs := map[string]int{}
	for _, f := range filesToScan {
		rel, _ := filepath.Rel(targetDir, f)
		if rel == "" {
			rel = filepath.Base(f)
		}
		dir := filepath.Dir(rel)
		dirs[dir]++
	}
	count := 0
	for dir, n := range dirs {
		if count >= 80 {
			sb.WriteString("  ... (truncated)\n")
			break
		}
		sb.WriteString(fmt.Sprintf("  %s/ (%d files)\n", dir, n))
		count++
	}

	// 2. Extract imports / includes from the first 30 lines of nearby files (max 10 files)
	sb.WriteString("\n--- Key Imports (sampled) ---\n")
	sampled := 0
	for _, f := range filesToScan {
		if sampled >= 10 {
			break
		}
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := strings.Split(string(content), "\n")
		maxLines := 30
		if len(lines) < maxLines {
			maxLines = len(lines)
		}
		rel, _ := filepath.Rel(targetDir, f)
		importLines := []string{}
		for _, line := range lines[:maxLines] {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") ||
				strings.HasPrefix(trimmed, "require(") || strings.HasPrefix(trimmed, "#include") ||
				strings.HasPrefix(trimmed, "using ") || strings.HasPrefix(trimmed, "package ") {
				importLines = append(importLines, trimmed)
			}
		}
		if len(importLines) > 0 {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", rel, strings.Join(importLines, " | ")))
			sampled++
		}
	}

	result := sb.String()
	// Cap context to prevent prompt bloat (max 3000 chars)
	if len(result) > 3000 {
		result = result[:3000] + "\n  ... (context truncated)\n"
	}
	return result
}

// maxFileSize is the maximum file size (in bytes) to send to AI (avoid overloading context)
const maxFileSize = 150000

// ollamaAPIURL is the Ollama REST API endpoint (configurable for remote hosts)
var ollamaAPIURL = "http://localhost:11434/api/generate"

// ollamaBaseURL stores the base URL without the /api/generate path
var ollamaBaseURL = "http://localhost:11434"

// SetOllamaHost configures the Ollama API endpoint to use a specific host:port.
func SetOllamaHost(hostPort string) {
	if hostPort == "" {
		return
	}
	ollamaBaseURL = "http://" + hostPort
	ollamaAPIURL = ollamaBaseURL + "/api/generate"
}

// GetOllamaBaseURL returns the current Ollama base URL (e.g. "http://192.168.1.42:11434")
func GetOllamaBaseURL() string {
	return ollamaBaseURL
}

// OllamaAPIRequest is the request body for the Ollama generate API
type OllamaAPIRequest struct {
	Model     string                 `json:"model"`
	Prompt    string                 `json:"prompt"`
	Stream    bool                   `json:"stream"`
	Options   map[string]interface{} `json:"options,omitempty"`
	KeepAlive string                 `json:"keep_alive,omitempty"`
}

// OllamaAPIResponse is the response from the Ollama generate API
type OllamaAPIResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// readOllamaResponse reads an Ollama API response body, handling BOTH:
// 1. Non-streaming: a single JSON object with the full response
// 2. Streaming: line-delimited JSON objects with individual tokens (some servers ignore stream:false)
// It concatenates all .Response fields and returns the full text.
func readOllamaResponse(body io.Reader) (string, error) {
	decoder := json.NewDecoder(body)
	var fullResponse strings.Builder
	decoded := false

	for {
		var chunk OllamaAPIResponse
		if err := decoder.Decode(&chunk); err != nil {
			if err == io.EOF {
				break
			}
			// If we already got some content, return what we have
			if decoded {
				break
			}
			return "", fmt.Errorf("failed to decode Ollama response: %w", err)
		}
		decoded = true
		fullResponse.WriteString(chunk.Response)
		if chunk.Done {
			break
		}
	}

	if !decoded {
		return "", fmt.Errorf("empty response from Ollama")
	}

	return fullResponse.String(), nil
}

const maxChunkLines = 2000
const chunkOverlap = 50

// DiscoverVulnerabilities scans a single file using AI to find vulnerabilities via sliding window chunking.
// projectContext is an optional string containing the project tree and imports for multi-vector context.
func DiscoverVulnerabilities(ctx context.Context, modelName string, filePath string, content string, projectContext ...string) ([]DiscoveryFinding, error) {
	lines := strings.Split(utils.NormalizeNewlines(content), "\n")
	totalLines := len(lines)

	var allFindings []DiscoveryFinding

	if totalLines == 0 {
		return nil, nil
	}

	for startLine := 0; startLine < totalLines; startLine += (maxChunkLines - chunkOverlap) {
		endLine := startLine + maxChunkLines
		if endLine > totalLines {
			endLine = totalLines
		}

		chunkLines := lines[startLine:endLine]
		chunkContent := strings.Join(chunkLines, "\n")

		if len(chunkContent) > maxFileSize {
			chunkContent = chunkContent[:maxFileSize] + "\n// ... [truncated horizontal minified blob] ..."
		}

		codeBlock := fmt.Sprintf("```\n// File: %s (Lines %d to %d)\n%s\n```", filePath, startLine+1, endLine, chunkContent)

		ext := strings.ToLower(filepath.Ext(filePath))
		langSpecific := ""
		switch ext {
		case ".go":
			langSpecific = "GO-SPECIFIC: Look for insecure use of 'unsafe', lack of mutex locks in concurrent maps, and improper error handling in critical CSP flows."
		case ".js", ".ts", ".jsx", ".tsx":
			langSpecific = "JS-SPECIFIC: Look for Prototype Pollution, insecure use of 'innerHTML' or 'eval()', and client-side storage of PII without encryption."
		case ".py":
			langSpecific = "PYTHON-SPECIFIC: Look for insecure deserialization (pickle/yaml), command injection in 'os.system' or 'subprocess', and use of 'assert' for security checks."
		case ".c", ".cpp", ".h", ".hpp":
			langSpecific = "C/C++-SPECIFIC: Look for buffer overflows (strcpy/gets), memory leaks, use-after-free, and integer overflows in memory allocation (malloc/calloc)."
		case ".java":
			langSpecific = "JAVA-SPECIFIC: Look for Insecure Deserialization, XXE in XML parsers, and Log4Shell-style injection points."
		case ".php":
			langSpecific = "PHP-SPECIFIC: Look for unserialize() vulnerabilities, local file inclusion (LFI) via 'include/require', and SQLi in legacy 'mysql_' functions."
		}

		prompt := fmt.Sprintf("You are an Expert Security Auditor and Code Analysis System.\n"+
			"Your mission: Perform a comprehensive security review of the provided code to identify vulnerabilities and suggest defensive improvements. Be thorough and analytical.\n\n"+
			"File Context: %s\n"+
			"%s\n\n", filePath, codeBlock)

		// Inject project context if available (Multi-Vector Context Injection)
		if len(projectContext) > 0 && projectContext[0] != "" {
			prompt += fmt.Sprintf("%s\n\n", projectContext[0])
		}

		prompt += fmt.Sprintf("SECURITY ANALYSIS SCOPE:\n"+
			"1.  ACCESS CONTROL VULNERABILITIES: IDOR, missing authorization checks, horizontal/vertical privilege escalation, and flaws in session management.\n"+
			"2.  INJECTION RISKS: SQL Injection, OS Command Injection, Template Injection (SSTI), NoSQL Injection, and LDAP/XPath Injection.\n"+
			"3.  DATA PROCESSING & LOGIC: Insecure Deserialization, Prototype Pollution, XXE, and Business Logic flaws.\n"+
			"4.  SERVER-SIDE REQUEST FORGERY (SSRF): Vulnerabilities that allow internal network access or metadata service exploitation.\n\n"+
			"IMPORTANT: Focus ONLY on exploitable code-level bugs with clear impact. Do NOT flag missing infrastructure controls (e.g. rate limiting, security headers) as vulnerabilities.\n\n"+
			"FALSE POSITIVE AVOIDANCE:\n"+
			"- Do NOT flag parameterized queries (e.g., using `?` or `$1`) as SQL Injection.\n"+
			"- Do NOT flag secure RNGs (`crypto.randomBytes`, `secrets.token_hex`, `os.urandom`) as Weak Randomness. Only flag predictable math libraries (`Math.random()`, `rand()`).\n"+
			"- Do NOT flag `textContent` or `innerText` as XSS. Only flag `innerHTML`, `dangerouslySetInnerHTML`, or raw unescaped template outputs.\n"+
			"- Do NOT flag environment variables (`process.env.SECRET`) as Hardcoded Secrets. Only flag literal string secrets.\n\n"+
			"ANALYSIS METHODOLOGY:\n"+
			"- TAINT-FLOW TRACKING: Trace untrusted user input from entry points (Sources) to sensitive operations (Sinks). Flag if no proper validation or sanitization is present.\n"+
			"- VULNERABILITY ASSESSMENT: Evaluate how inputs could be manipulated to cause unintended behavior.\n"+
			"- LANGUAGE-SPECIFIC ARCHETYPES: %s\n\n"+
			"TAXONOMY & ACCURACY:\n"+
			"- Assign correct CWE IDs based on the root cause.\n"+
			"- Classify client-side issues (DOM XSS, etc.) as CWE-79 (Cross-Site Scripting).\n"+
			"- Classify server-side code execution via eval() as CWE-94/CWE-95.\n\n", langSpecific) +
			"FORMATTING & OUTPUT:\n"+
			"- Start with a <thinking> tag for step-by-step analysis.\n"+
			"- Provide the final result ONLY in valid JSON format.\n"+
			"- If no vulnerabilities are found, return '{\"vulnerabilities\": []}' in the JSON section.\n"+
			"- Remediation must be plain text explanation, NO code diffs.\n\n"+
			"JSON STRUCTURE:\n"+
			"{\n"+
			"  \"vulnerabilities\": [\n"+
			"    {\n"+
			"      \"issue_name\": \"Brief title of vulnerability\",\n"+
			"      \"severity\": \"critical/high/medium/low/info\",\n"+
			"      \"line_number\": 42,\n"+
			"      \"description\": \"Detailed explanation of the vulnerability\",\n"+
			"      \"remediation\": \"How to fix the vulnerability\",\n"+
			"      \"exploit_poc\": \"Example exploit payload or N/A\",\n"+
			"      \"cwe\": \"CWE-XX\",\n"+
			"      \"owasp\": \"AXX:2021\",\n"+
			"      \"confidence\": 0.95\n"+
			"    }\n"+
			"  ],\n"+
			"  \"needs_context\": [\"optional/path/to/related_file.go\"]\n"+
			"}"

		// --- Agentic Iterative Search Loop ---
		// Allow the AI to request related files (up to 1 deeper iteration)
		maxAgenticLoops := 2
		var aiError error
		var reqCtx context.Context
		var reqCancel context.CancelFunc

		var jsonContent string
		var outputStr string

		for loopIdx := 0; loopIdx < maxAgenticLoops; loopIdx++ {
			reqBody := OllamaAPIRequest{
				Model:  modelName,
				Prompt: prompt,
				Stream: false,
				Options: map[string]interface{}{
					"num_ctx":     16384,
					"num_predict": 4096,
					"temperature": 0.0,
				},
				KeepAlive: "15m",
			}

			reqJSON, err := json.Marshal(reqBody)
			if err != nil {
				return nil, err
			}

			reqCtx, reqCancel = context.WithTimeout(ctx, 30*time.Minute)
			req, err := http.NewRequestWithContext(reqCtx, "POST", ollamaAPIURL, bytes.NewBuffer(reqJSON))
			if err != nil {
				reqCancel()
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := aiHTTPClient.Do(req)
			if err != nil {
				reqCancel()
				if strings.Contains(err.Error(), "context canceled") {
					return nil, fmt.Errorf("scan interrupted")
				}
				return nil, fmt.Errorf("API request failed: %w", err)
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				reqCancel()
				return nil, fmt.Errorf("Ollama API error (Status %d): %s", resp.StatusCode, string(body))
			}

			fullText, readErr := readOllamaResponse(resp.Body)
			resp.Body.Close()
			reqCancel() // Cleanup immediately after parsing

			if readErr != nil {
				return nil, fmt.Errorf("Ollama response read error: %w", readErr)
			}

			outputStr = fullText
			jsonContent = utils.ExtractJSON(outputStr)
			if jsonContent == "" {
				aiError = fmt.Errorf("No JSON found")
				break
			}

			// Check if the AI wants more context
			type AgenticResponse struct {
				NeedsContext []string `json:"needs_context"`
			}
			var agenticResp AgenticResponse
			err = json.Unmarshal([]byte(jsonContent), &agenticResp)

			// If no context needed OR we're on the last loop, break and parse findings
			if err != nil || len(agenticResp.NeedsContext) == 0 || loopIdx == maxAgenticLoops-1 {
				break
			}

			// Agentic Search: Fetch requested files
			var contextAdditions strings.Builder
			contextAdditions.WriteString("\n\n--- AGENTIC SEARCH RESULTS ---\nYou requested additional context. Here are the contents:\n")
			for _, reqFile := range agenticResp.NeedsContext {
				// Prevent traversal above project root (rough heuristic)
				cleanPath := filepath.Clean(reqFile)
				if !strings.Contains(cleanPath, "..") {
					// Use filepath.Dir(filePath) or just try blindly since we don't know the exact project root here
					// Better: search relative to the file being scanned
					dir := filepath.Dir(filePath)
					targetPath := filepath.Join(dir, cleanPath)
					content, err := os.ReadFile(targetPath)
					if err == nil {
						snippet := string(content)
						if len(snippet) > 8000 {
							snippet = snippet[:8000] + "\n... (truncated)"
						}
						contextAdditions.WriteString(fmt.Sprintf("\n// File: %s\n```\n%s\n```\n", reqFile, snippet))
					} else {
						contextAdditions.WriteString(fmt.Sprintf("\n// File: %s (NOT FOUND)\n", reqFile))
					}
				}
			}
			prompt += contextAdditions.String()
			prompt += "\nNow, provide your FINAL analysis of the original file vulnerabilities:\n"
		}
		
		if aiError != nil {
			utils.LogWarn(fmt.Sprintf("AI parsing error for %s: %v", filePath, aiError))
			continue
		}

		// DEBUG: Log full raw response (truncated for readability)
		if len(outputStr) > 0 {
			logSnippet := outputStr
			if len(logSnippet) > 500 {
				logSnippet = logSnippet[:500] + "... (truncated)"
			}
			utils.LogInfo(fmt.Sprintf("Full AI Response for %s:\n\n%s\n\n", filePath, logSnippet))
		} else {
			utils.LogWarn(fmt.Sprintf("AI returned empty response for %s", filePath))
		}

		var response DiscoveryResponse

		if os.Getenv("AI_DEBUG") == "true" {
			fmt.Printf("\n[DEBUG] Raw AI output for %s:\n%s\n", filePath, outputStr)
		}

		if err2 := json.Unmarshal([]byte(jsonContent), &response); err2 == nil {
			for i := range response.Vulnerabilities {
				response.Vulnerabilities[i].LineNumber += FlexInt(startLine)
				if response.Vulnerabilities[i].LineNumber > FlexInt(totalLines) {
					response.Vulnerabilities[i].LineNumber = FlexInt(totalLines)
				}
			}
			allFindings = append(allFindings, response.Vulnerabilities...)
		} else {
			// Fallback 1: Try escaping unescaped quotes (AI outputs code with " inside JSON strings)
			repaired := utils.EscapeUnescapedQuotes(jsonContent)
			if err3 := json.Unmarshal([]byte(repaired), &response); err3 == nil {
				utils.LogInfo(fmt.Sprintf("Recovered JSON for %s after escaping unescaped quotes", filePath))
				for i := range response.Vulnerabilities {
					response.Vulnerabilities[i].LineNumber += FlexInt(startLine)
					if response.Vulnerabilities[i].LineNumber > FlexInt(totalLines) {
						response.Vulnerabilities[i].LineNumber = FlexInt(totalLines)
					}
				}
				allFindings = append(allFindings, response.Vulnerabilities...)
			} else {
				// Fallback 2: Try RepairJSON for truncation issues
				repaired2 := utils.RepairJSON(repaired)
				if err4 := json.Unmarshal([]byte(repaired2), &response); err4 == nil {
					utils.LogInfo(fmt.Sprintf("Recovered JSON for %s after full repair", filePath))
					for i := range response.Vulnerabilities {
						response.Vulnerabilities[i].LineNumber += FlexInt(startLine)
						if response.Vulnerabilities[i].LineNumber > FlexInt(totalLines) {
							response.Vulnerabilities[i].LineNumber = FlexInt(totalLines)
						}
					}
					allFindings = append(allFindings, response.Vulnerabilities...)
				} else {
					utils.LogWarn(fmt.Sprintf("Failed to parse AI JSON for %s: %v", filePath, err2))
					if os.Getenv("AI_DEBUG") != "true" {
						preview := jsonContent
						if len(preview) > 200 { preview = preview[:200] + "..." }
						utils.LogInfo(fmt.Sprintf("Corrupted JSON fragment: %s", preview))
					}
				}
			}
		}

		if endLine == totalLines {
			break
		}
	}

	return allFindings, nil
}

// RunAIDiscovery scans all supported files in a directory using AI-powered discovery concurrently.
func RunAIDiscovery(ctx context.Context, modelName string, targetDir string, logCallback ...func(msg string, level string)) []reporter.Finding {

	// Helper to send logs to UI if a callback was provided
	uiLog := func(msg, level string) {
		if len(logCallback) > 0 && logCallback[0] != nil {
			logCallback[0](msg, level)
		}
	}

	var allFindings []reporter.Finding
	var filesToScan []string

	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		for _, skip := range []string{"node_modules", "vendor", ".git", "__pycache__", "venv", ".venv", "dist", "build", ".idea", ".vscode"} {
			if strings.Contains(path, string(os.PathSeparator)+skip+string(os.PathSeparator)) {
				return nil
			}
		}

		ext := strings.ToLower(filepath.Ext(path))
		baseName := strings.ToLower(filepath.Base(path))

		if baseName == ".scanner-ai-stats.json" || baseName == ".threat-intel-cache.json" {
			return nil
		}

		isSupported := supportedDiscoveryExtensions[ext]
		if !isSupported {
			switch baseName {
			case "dockerfile", "makefile", "vagrantfile", "gemfile", "rakefile":
				isSupported = true
			}
		}

		if isSupported {
			if info.Size() > 50 && info.Size() < 10000000 {
				filesToScan = append(filesToScan, path)
			}
		}
		return nil
	})

	totalFiles := len(filesToScan)
	if totalFiles == 0 {
		utils.LogInfo("No supported files found for AI discovery")
		return allFindings
	}

	color.Cyan("\n╔═══════════════════════════════════════════════════════════╗")
	color.Cyan("║         🧠 AI VULNERABILITY DISCOVERY ENGINE              ║")
	color.Cyan("╠═══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Model:    %-45s ║\n", modelName)
	fmt.Printf("║  Files:    %-45d ║\n", totalFiles)
	color.Cyan("╚═══════════════════════════════════════════════════════════╝\n")
	fmt.Println()

	uiLog(fmt.Sprintf("Prepared %d files for AI Discovery", totalFiles), "info")

	startTime := time.Now()

	// Synchronization & Metrics
	var (
		mu              sync.Mutex
		filesProcessed  int
		filesWithIssues int
		totalDiscovered int
		errorCount      int
	)

	numWorkers := 2 // Reduced from 4 to 2 for reasoning models to prevent local thrashing
	if totalFiles < numWorkers {
		numWorkers = totalFiles
	}
	if numWorkers == 0 {
		return allFindings
	}

	type scanJob struct {
		filePath string
		index    int
	}

	// Build context once for all files
	projectContext := buildProjectContext(targetDir, filesToScan)

	jobs := make(chan scanJob, totalFiles)
	results := make(chan []reporter.Finding, totalFiles)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for job := range jobs {
			if ctx.Err() != nil {
				results <- nil
				continue
			}

			content, err := os.ReadFile(job.filePath)
			if err != nil {
				mu.Lock()
				errorCount++
				filesProcessed++
				mu.Unlock()
				results <- nil
				continue
			}

			// Smart Skipping: Skip very short files or pure boilerplate
			if len(strings.TrimSpace(string(content))) < 150 {
				mu.Lock()
				filesProcessed++
				mu.Unlock()
				results <- nil
				continue
			}

			// Perform Discovery using the shared project context
			vulns, scanErr := DiscoverVulnerabilities(ctx, modelName, job.filePath, string(content), projectContext)

			// UI Updates
			mu.Lock()
			if scanErr != nil {
				errorCount++
			} else if len(vulns) > 0 {
				filesWithIssues++
				totalDiscovered += len(vulns)
			}
			filesProcessed++
			currProcessed := filesProcessed
			currDiscovered := totalDiscovered
			mu.Unlock()

			// Print UI (Locked to prevent garbled text)
			relPath, _ := filepath.Rel(targetDir, job.filePath)
			if relPath == "" {
				relPath = filepath.Base(job.filePath)
			}
			elapsed := time.Since(startTime)
			eta := "calculating..."
			if currProcessed > 0 {
				avgPerFile := elapsed / time.Duration(currProcessed)
				remaining := avgPerFile * time.Duration(totalFiles-currProcessed)
				eta = remaining.Round(time.Second).String()
			}

			mu.Lock()
			fmt.Printf("\r\033[K")
			color.HiBlack("  [%d/%d] ", currProcessed, totalFiles)
			color.HiWhite("Scanning: ")
			color.HiCyan("%s ", relPath)
			color.HiBlack("| %d found | ⏱ %s | ETA: %s", currDiscovered, elapsed.Round(time.Second), eta)
			if scanErr != nil && scanErr.Error() != "scan interrupted" {
				fmt.Printf("\n")
				color.Yellow("    ⚠ Error: %v (Skipping file)\n", scanErr)
			} else if currProcessed == totalFiles {
				fmt.Printf("\n")
			}
			mu.Unlock()

			// Map findings
			var mappedFindings []reporter.Finding
			if scanErr == nil && len(vulns) > 0 {
				for _, v := range vulns {
					mappedFindings = append(mappedFindings, reporter.Finding{
						Source:      "ai-discovery",
						IssueName:   v.IssueName,
						Severity:    strings.ToLower(v.Severity),
						FilePath:    job.filePath,
						LineNumber:  fmt.Sprintf("%d", int(v.LineNumber)),
						Description: v.Description,
						Remediation: v.Remediation,
						ExploitPoC:  v.ExploitPoC,
						CWE:         v.CWE,
						OWASP:       v.OWASP,
						AiReasoning: v.Description,
						AiValidated: "Discovered by AI",
						FixedCode:   v.FixedCodeSnippet,
						Confidence:  v.Confidence,
					})
				}
			}
			results <- mappedFindings
		}
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go worker()
	}

	for i, filePath := range filesToScan {
		jobs <- scanJob{filePath: filePath, index: i}
	}
	close(jobs)

	wg.Wait()
	close(results)

	for res := range results {
		if res != nil {
			allFindings = append(allFindings, res...)
		}
	}

	// Final check
	if ctx.Err() != nil {
		color.Yellow("\n  ⚠ Scan interrupted by user")
	}

	fmt.Println()
	color.Cyan("\n═══════════════════════════════════════════════════════")
	color.Green("✓ AI Discovery Complete")
	color.White("  Files Processed:  %d", filesProcessed)
	if errorCount > 0 {
		color.Yellow("  Errors / Skipped: %d", errorCount)
	}
	color.White("  Vulnerable Files: %d", filesWithIssues)
	color.HiRed("  Total Discovered: %d vulnerabilities", totalDiscovered)
	color.Cyan("═══════════════════════════════════════════════════════\n")

	return allFindings
}
