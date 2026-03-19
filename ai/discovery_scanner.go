package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"

	"github.com/fatih/color"
)

// Interrupt flag for graceful shutdown
var interruptFlag int32
var globalCtx context.Context
var globalCancel context.CancelFunc

var aiHTTPClient = &http.Client{
	Timeout: 35 * time.Minute, // Must exceed the per-request context timeout (30m)
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
}

func init() {
	globalCtx, globalCancel = context.WithCancel(context.Background())
}

// SetInterrupted sets the interrupt flag and cancels all running operations
func SetInterrupted(val bool) {
	if val {
		atomic.StoreInt32(&interruptFlag, 1)
		if globalCancel != nil {
			globalCancel()
		}
	} else {
		atomic.StoreInt32(&interruptFlag, 0)
	}
}

// IsInterrupted returns true if the scan has been interrupted
func IsInterrupted() bool {
	return atomic.LoadInt32(&interruptFlag) == 1
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

const maxChunkLines = 2000
const chunkOverlap = 50

// DiscoverVulnerabilities scans a single file using AI to find vulnerabilities via sliding window chunking
func DiscoverVulnerabilities(modelName string, filePath string, content string) ([]DiscoveryFinding, error) {
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

		prompt := fmt.Sprintf("You are an elite Red-Team Security Engineer and Exploit Developer.\n"+
			"Your mission: Perform a deep-dive security audit of the provided code. Do NOT be superficial.\n\n"+
			"File Context: %s\n"+
			"%s\n\n"+
			"MASTER AUDIT SCOPE (Elite Level):\n"+
			"1.  BROKEN ACCESS CONTROL: IDOR, missing RBAC/ABAC checks, horizontal/vertical privilege escalation, and bypasses in JWT/OAuth implementations.\n"+
			"2.  INJECTION GALAXY: SSTI, NoSQLi, OS Command Injection, Log Poisoning, and LDAP/XPath/Template injections.\n"+
			"3.  DATA INTEGRITY & LOGIC: Insecure Deserialization (Pickle/Marshal), Prototype Pollution, XXE, and complex Business Logic Bypasses (e.g. state machine manipulation).\n"+
			"4.  SERVER-SIDE REQUEST FORGERY (SSRF): Metadata service exploitation, DNS rebinding potential, and internal network pivot points.\n\n"+
			"IMPORTANT CONSTRAINT: Do NOT flag missing infrastructure controls (e.g. missing security headers, rate limiting, CSRF tokens) as code vulnerabilities. Focus ONLY on exploitable code-level bugs with a clear Source-to-Sink taint flow.\n\n"+
			"ULTRA-DEEP SCAN INSTRUCTIONS:\n"+
			"- TAINT-FLOW SIMULATION: For every variable that comes from a request (Source), trace its path through the code until it hits a sensitive function (Sink). If there is no sanitization in between, it is a CRITICAL finding.\n"+
			"- ATTACKER'S PERSPECTIVE: How would I bypass the existing regex or filters? Look for encoding tricks, null bytes, or multi-step logical flaws.\n"+
			"- LANGUAGE-SPECIFIC ARCHETYPES: %s\n\n"+
			"CRITICAL TAXONOMY RULES:\n"+
			"- DO NOT misclassify vulnerabilities. You must use accurate CWE IDs based on the root cause and execution context.\n"+
			"- Client-side issues (like DOM XSS, postMessage vulnerabilities, javascript: URIs) MUST be classified as CWE-79 (Cross-Site Scripting), NOT OS Command Injection (CWE-78) or Eval Injection.\n"+
			"- Code injection via eval() or Function() on the server backend is CWE-94/CWE-95, NOT OS Command Injection.\n"+
			"- Apply strict contextual awareness (backend vs frontend).\n\n"+
			"FORMATTING RULES:\n"+
			"- In the 'remediation' field, explain the fix in pure english text. DO NOT generate git diffs (e.g., + and - lines) or unformatted code blocks.\n"+
			"- The 'code_snippet' field should ONLY contain the lines of vulnerable code, no extra commentary.\n\n"+
			"OUTPUT PROTOCOL:\n"+
			"1. Start with a <thinking> tag. Perform a step-by-step Taint-Flow analysis. If you find a 'Missing' control, explain why the omission is dangerous.\n"+
			"2. End with the final results in the requested JSON format.\n\n"+
			"Respond ONLY with valid JSON inside the final results portion:\n"+
			"{\n"+
			"  \"vulnerabilities\": [\n"+
			"    {\n"+
			"      \"issue_name\": \"[CWE-XXX] Clear descriptive name\",\n"+
			"      \"severity\": \"critical|high|medium|low|info\",\n"+
			"      \"line_number\": 42,\n"+
			"      \"description\": \"Detailed chain-of-thought analysis of the vulnerability. DO NOT include code diffs.\",\n"+
			"      \"remediation\": \"Specific, text-based explanation of the fix. DO NOT output code diffs/patches.\",\n"+
			"      \"exploit_poc\": \"Step-by-step exploitation guide or payload (curl/python/js).\",\n"+
			"      \"fixed_code_snippet\": \"Complete secure implementation of the affected logic.\",\n"+
			"      \"cwe\": \"CWE-XXX\",\n"+
			"      \"owasp\": \"A0X:2021\",\n"+
			"      \"confidence\": 0.95\n"+
			"    }\n"+
			"  ]\n"+
			"}", filePath, codeBlock, langSpecific)

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

		// Create a fresh context for each API call — large models (32b+) need up to 30 min for massive files
		reqCtx, reqCancel := context.WithTimeout(globalCtx, 30*time.Minute)
		defer reqCancel()

		req, err := http.NewRequestWithContext(reqCtx, "POST", ollamaAPIURL, bytes.NewBuffer(reqJSON))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := aiHTTPClient.Do(req)
		if err != nil {
			if strings.Contains(err.Error(), "context canceled") {
				return nil, fmt.Errorf("scan interrupted")
			}
			if strings.Contains(err.Error(), "context deadline exceeded") {
				return nil, fmt.Errorf("AI model timeout - try a faster model or increase timeout settings")
			}
			// Retry on EOF (remote server dropped connection) — up to 2 retries
			if strings.Contains(err.Error(), "EOF") {
				for retryNum := 1; retryNum <= 2; retryNum++ {
					func() {
						waitSec := retryNum * 5
						utils.LogWarn(fmt.Sprintf("Connection dropped (EOF) for %s, retry %d/2 in %ds...", filePath, retryNum, waitSec))
						time.Sleep(time.Duration(waitSec) * time.Second)
						
						reqCtx2, reqCancel2 := context.WithTimeout(globalCtx, 30*time.Minute)
						defer reqCancel2()
						
						req2, _ := http.NewRequestWithContext(reqCtx2, "POST", ollamaAPIURL, bytes.NewBuffer(reqJSON))
						req2.Header.Set("Content-Type", "application/json")
						resp, err = aiHTTPClient.Do(req2)
					}()
					if err == nil {
						break // success
					}
					if !strings.Contains(err.Error(), "EOF") {
						break // different error, stop retrying
					}
				}
				if err != nil {
					return nil, fmt.Errorf("API request failed after retries: %w", err)
				}
			} else {
				return nil, fmt.Errorf("API request failed: %w", err)
			}
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("Ollama API error (Status %d): %s", resp.StatusCode, string(body))
		}

		var ollamaResp OllamaAPIResponse
		if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("JSON decode error: %w", err)
		}
		resp.Body.Close()

		// DEBUG: Log full raw response as requested by user
		if len(ollamaResp.Response) > 0 {
			utils.LogInfo(fmt.Sprintf("Full AI Response for %s:\n\n%s\n\n", filePath, ollamaResp.Response))
		} else {
			utils.LogWarn(fmt.Sprintf("AI returned empty response for %s", filePath))
		}

		var response DiscoveryResponse
		outputStr := ollamaResp.Response
		
		// Robust JSON Extraction using common utility
		jsonContent := utils.ExtractJSON(outputStr)

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
func RunAIDiscovery(modelName string, targetDir string) []reporter.Finding {
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

	SetInterrupted(false)
	if globalCancel != nil {
		globalCancel()
	}
	globalCtx, globalCancel = context.WithCancel(context.Background())

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

	jobs := make(chan scanJob, totalFiles)
	results := make(chan []reporter.Finding, totalFiles)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for job := range jobs {
			if IsInterrupted() {
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

			// Perform Discovery
			vulns, scanErr := DiscoverVulnerabilities(modelName, job.filePath, string(content))

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

	if IsInterrupted() {
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
