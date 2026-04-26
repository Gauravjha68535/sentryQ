package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SentryQ/reporter"
	"SentryQ/utils"

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
	VulnerableCode   string  `json:"vulnerable_code"` // Exact short code fragment the AI flagged (used to anchor snippet to real line)
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
	// Cap context to prevent prompt bloat (max 10000 chars)
	if len(result) > 10000 {
		result = result[:10000] + "\n  ... (context cap reached)\n"
	}
	return result
}

// maxFileSize is the maximum file size (in bytes) to send to AI (avoid overloading context)
const maxFileSize = 150000

// ollamaMu guards ollamaAPIURL and ollamaBaseURL against concurrent access
// from multiple simultaneous scans each potentially using a different Ollama host.
var ollamaMu sync.RWMutex

// ollamaAPIURL is the Ollama REST API endpoint (configurable for remote hosts)
var ollamaAPIURL = "http://localhost:11434/api/generate"

// ollamaBaseURL stores the base URL without the /api/generate path
var ollamaBaseURL = "http://localhost:11434"

// SetOllamaHost configures the Ollama API endpoint to use a specific host:port.
func SetOllamaHost(hostPort string) {
	if hostPort == "" {
		return
	}
	ollamaMu.Lock()
	defer ollamaMu.Unlock()
	ollamaBaseURL = "http://" + hostPort
	ollamaAPIURL = ollamaBaseURL + "/api/generate"
}

// GetOllamaBaseURL returns the current Ollama base URL (e.g. "http://192.168.1.42:11434")
func GetOllamaBaseURL() string {
	ollamaMu.RLock()
	defer ollamaMu.RUnlock()
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

// doOllamaRequest sends a POST to the Ollama generate API and returns the full
// text response. It owns the response body lifecycle — the body is always closed
// before returning, even if a panic occurs inside readOllamaResponse.
func doOllamaRequest(ctx context.Context, reqJSON []byte) (string, error) {
	ollamaMu.RLock()
	apiURL := ollamaAPIURL
	ollamaMu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(reqJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := aiHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readBodyErr := io.ReadAll(resp.Body)
		if readBodyErr != nil {
			return "", fmt.Errorf("ollama API error (status %d): <failed to read response body: %v>", resp.StatusCode, readBodyErr)
		}
		return "", fmt.Errorf("ollama API error (status %d): %s", resp.StatusCode, string(body))
	}

	return readOllamaResponse(resp.Body)
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
// scanRoot is the top-level directory being scanned; it's used to bound agentic file requests.
func DiscoverVulnerabilities(ctx context.Context, modelName string, filePath string, content string, projectContext ...string) ([]DiscoveryFinding, error) {
	lines := strings.Split(utils.NormalizeNewlines(content), "\n")
	totalLines := len(lines)

	var allFindings []DiscoveryFinding

	if totalLines == 0 {
		return nil, nil
	}

	for startLine := 0; startLine < totalLines; startLine += (maxChunkLines - chunkOverlap) {
		if ctx.Err() != nil {
			return allFindings, ctx.Err()
		}
		endLine := startLine + maxChunkLines
		if endLine > totalLines {
			endLine = totalLines
		}

		chunkLines := lines[startLine:endLine]

		var b strings.Builder
		b.WriteString("```\n")
		b.WriteString(fmt.Sprintf("// File: %s (Lines %d to %d)\n", filePath, startLine+1, endLine))
		var charCount int
		for i, l := range chunkLines {
			lineText := fmt.Sprintf("%d: %s\n", startLine+i+1, l)
			if charCount+len(lineText) > maxFileSize {
				b.WriteString("// ... [truncated horizontal minified blob] ...\n")
				break
			}
			b.WriteString(lineText)
			charCount += len(lineText)
		}
		b.WriteString("```")
		codeBlock := b.String()

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
			"- CRITICAL: Do NOT use placeholders, ellipses (...), or pseudo-code inside the JSON. The JSON array must be fully populated and strictly parsable exactly as written. Do not use '[...]' to abbreviate.\n"+
			"- If no vulnerabilities are found, return '{\"vulnerabilities\": []}' in the JSON section.\n"+
			"- Remediation must be plain text explanation, NO code diffs.\n\n"+
			"JSON STRUCTURE:\n"+
			"{\n"+
			"  \"vulnerabilities\": [\n"+
			"    {\n"+
			"      \"issue_name\": \"Brief title of vulnerability\",\n"+
			"      \"severity\": \"critical/high/medium/low/info\",\n"+
			"      \"line_number\": 42,\n"+
			"      \"vulnerable_code\": \"Exact verbatim code fragment from that line (max 120 chars, no paraphrasing)\",\n"+
			"      \"description\": \"Detailed explanation of the vulnerability\",\n"+
			"      \"remediation\": \"How to fix the vulnerability\",\n"+
			"      \"exploit_poc\": \"Example exploit payload or N/A\",\n"+
			"      \"cwe\": \"CWE-XX\",\n"+
			"      \"owasp\": \"AXX:2021-ShortName (MUST be exactly this format, e.g. A03:2021-Injection — no other text)\",\n"+
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
			if ctx.Err() != nil {
				break
			}
			var fullText string
			var readErr error

			// Dispatch based on active provider
			if GetActiveProvider() == ProviderOpenAI {
				customURL, customKey, customMdl := GetCustomEndpoint()
				useModel := customMdl
				if useModel == "" {
					useModel = modelName
				}
				reqCtx, reqCancel = context.WithTimeout(ctx, 30*time.Minute)
				fullText, readErr = GenerateViaOpenAI(reqCtx, customURL, customKey, useModel, prompt, map[string]interface{}{
					"temperature": 0.0,
					"num_predict": 8192,
				})
				reqCancel()
			} else {
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
				fullText, readErr = doOllamaRequest(reqCtx, reqJSON)
				reqCancel()
				if readErr != nil {
					if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
						return nil, fmt.Errorf("scan interrupted")
					}
				}
			}

			if readErr != nil {
				return nil, fmt.Errorf("AI response read error: %w", readErr)
			}

			outputStr = fullText
			jsonContent = utils.ExtractJSON(outputStr)
			if jsonContent == "" {
				aiError = fmt.Errorf("no JSON found in AI response")
				break
			}

			// Check if the AI wants more context
			type AgenticResponse struct {
				NeedsContext []string `json:"needs_context"`
			}
			var agenticResp AgenticResponse
			err := json.Unmarshal([]byte(jsonContent), &agenticResp)

			// If no context needed OR we're on the last loop, break and parse findings
			if err != nil || len(agenticResp.NeedsContext) == 0 || loopIdx == maxAgenticLoops-1 {
				break
			}

			// Agentic Search: Fetch requested files
			var contextAdditions strings.Builder
			contextAdditions.WriteString("\n\n--- AGENTIC SEARCH RESULTS ---\nYou requested additional context. Here are the contents:\n")
			for _, reqFile := range agenticResp.NeedsContext {
				// Prevent path traversal: reject absolute paths and any ".." components.
				cleanPath := filepath.Clean(reqFile)
				if !filepath.IsAbs(cleanPath) && !strings.Contains(cleanPath, "..") {
					// Use the project scan root (derived from filePath's tree) as
					// the containment boundary, not just the file's own directory.
					// This lets the AI request context from anywhere in the project.
					dir := filepath.Dir(filePath)
					targetPath := filepath.Join(dir, cleanPath)
					// Final check: ensure resolved path stays within the scan directory.
					// Use the directory of the file as minimum; if a broader scanRoot
					// is available it would be used here.
					absScanDir, e1 := filepath.Abs(dir)
					absTarget, e2 := filepath.Abs(targetPath)
					if e1 != nil || e2 != nil {
						continue
					}
					// Allow files in the same directory (absTarget == absScanDir prefix)
					if !strings.HasPrefix(absTarget, absScanDir) {
						continue
					}
					content, err := os.ReadFile(targetPath)
					if err == nil {
						snippet := string(content)
						if len(snippet) > 32000 {
							snippet = snippet[:32000] + "\n... (context cap reached)"
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

		var response DiscoveryResponse

		if os.Getenv("AI_DEBUG") == "true" {
			if len(outputStr) > 0 {
				fmt.Printf("\n[DEBUG] Raw AI output for %s:\n%s\n", filePath, outputStr)
			} else {
				fmt.Printf("\n[DEBUG] AI returned empty response for %s\n", filePath)
			}
		}

		// clampLine ensures a line number returned by the AI stays within file bounds.
		// We do NOT add startLine here: the prompt already labels every line with its
		// absolute number (startLine+i+1), so the AI returns absolute line numbers.
		clampLine := func(ln FlexInt) FlexInt {
			if ln < 1 {
				return 1
			}
			if ln > FlexInt(totalLines) {
				return FlexInt(totalLines)
			}
			return ln
		}

		if err2 := json.Unmarshal([]byte(jsonContent), &response); err2 == nil {
			for i := range response.Vulnerabilities {
				response.Vulnerabilities[i].LineNumber = clampLine(response.Vulnerabilities[i].LineNumber)
			}
			allFindings = append(allFindings, response.Vulnerabilities...)
		} else {
			// Fallback 1: Try escaping unescaped quotes (AI outputs code with " inside JSON strings)
			repaired := utils.EscapeUnescapedQuotes(jsonContent)
			if err3 := json.Unmarshal([]byte(repaired), &response); err3 == nil {
				utils.LogInfo(fmt.Sprintf("Recovered JSON for %s after escaping unescaped quotes", filePath))
				for i := range response.Vulnerabilities {
					response.Vulnerabilities[i].LineNumber = clampLine(response.Vulnerabilities[i].LineNumber)
				}
				allFindings = append(allFindings, response.Vulnerabilities...)
			} else {
				// Fallback 2: Try RepairJSON for truncation issues
				repaired2 := utils.RepairJSON(repaired)
				if err4 := json.Unmarshal([]byte(repaired2), &response); err4 == nil {
					utils.LogInfo(fmt.Sprintf("Recovered JSON for %s after full repair", filePath))
					for i := range response.Vulnerabilities {
						response.Vulnerabilities[i].LineNumber = clampLine(response.Vulnerabilities[i].LineNumber)
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

	if err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip known non-source directories using filepath.SkipDir to avoid
		// descending into them (e.g., node_modules can have 50,000+ files).
		if info.IsDir() {
			skipDirs := map[string]bool{
				"node_modules": true, "vendor": true, ".git": true,
				"__pycache__": true, "venv": true, ".venv": true,
				"dist": true, "build": true, ".idea": true, ".vscode": true,
			}
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
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
	}); err != nil {
		utils.LogWarn(fmt.Sprintf("AI discovery: directory walk failed for %s: %v", targetDir, err))
	}

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
						Source:             "ai-discovery",
						IssueName:          v.IssueName,
						Severity:           strings.ToLower(strings.TrimSpace(v.Severity)),
						FilePath:           job.filePath,
						LineNumber:         fmt.Sprintf("%d", int(v.LineNumber)),
						Description:        v.Description,
						Remediation:        v.Remediation,
						ExploitPoC:         v.ExploitPoC,
						CWE:                reporter.NormalizeCWE(v.CWE),
						OWASP:              reporter.NormalizeOWASP(v.OWASP),
						AiReasoning:        v.Description,
						AiValidated:        "Discovered by AI",
						FixedCode:          v.FixedCodeSnippet,
						Confidence:         v.Confidence,
						VulnerablePattern:  strings.TrimSpace(v.VulnerableCode),
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
	color.White("  Vulnerable Files: %d of %d", filesWithIssues, filesProcessed)
	color.HiRed("  Total Discovered: %d vulnerabilities", totalDiscovered)
	color.Cyan("═══════════════════════════════════════════════════════\n")

	return allFindings
}
