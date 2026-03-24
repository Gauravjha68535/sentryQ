package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"SentryQ/reporter"
	"SentryQ/utils"

	treeSitter "github.com/smacker/go-tree-sitter"
	java "github.com/smacker/go-tree-sitter/java"
	javascript "github.com/smacker/go-tree-sitter/javascript"
	kotlin "github.com/smacker/go-tree-sitter/kotlin"
	python "github.com/smacker/go-tree-sitter/python"
)

// ASTAnalyzer performs AST-based vulnerability detection
type ASTAnalyzer struct {
	languages         map[string]*treeSitter.Language
	parsers           map[string]*treeSitter.Parser
	reachabilityCache map[string]bool
}

// NewASTAnalyzer creates a new AST analyzer with supported languages
func NewASTAnalyzer() *ASTAnalyzer {
	analyzer := &ASTAnalyzer{
		languages:         make(map[string]*treeSitter.Language),
		parsers:           make(map[string]*treeSitter.Parser),
		reachabilityCache: nil,
	}

	// Register supported languages
	analyzer.languages["python"] = python.GetLanguage()
	analyzer.languages["javascript"] = javascript.GetLanguage()
	analyzer.languages["typescript"] = javascript.GetLanguage() // TypeScript uses JS parser
	analyzer.languages["java"] = java.GetLanguage()
	analyzer.languages["kotlin"] = kotlin.GetLanguage()

	// Initialize parsers
	for lang, language := range analyzer.languages {
		parser := treeSitter.NewParser()
		parser.SetLanguage(language)
		analyzer.parsers[lang] = parser
	}

	return analyzer
}

// AnalyzeFile scans a file using AST-based analysis
func (aa *ASTAnalyzer) AnalyzeFile(filePath string) ([]reporter.Finding, error) {
	lang := getLanguageFromPath(filePath)
	if lang == "" || aa.parsers[lang] == nil {
		return nil, nil // Skip unsupported languages
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	parser := aa.parsers[lang]
	tree := parser.Parse(nil, content)
	if tree == nil {
		return nil, fmt.Errorf("failed to parse AST: parser returned nil")
	}
	defer tree.Close()

	rootNode := tree.RootNode()
	lines := strings.Split(utils.NormalizeNewlines(string(content)), "\n")

	var findings []reporter.Finding
	srNo := 1

	// Walk the AST and detect vulnerabilities based on language
	switch lang {
	case "python":
		findings = aa.analyzePythonAST(rootNode, content, lines, filePath, &srNo)
	case "javascript", "typescript":
		findings = aa.analyzeJavaScriptAST(rootNode, content, lines, filePath, &srNo)
	case "java":
		findings = aa.analyzeJavaAST(rootNode, content, lines, filePath, &srNo)
	case "kotlin":
		findings = aa.analyzeKotlinAST(rootNode, content, lines, filePath, &srNo)
	}

	return findings, nil
}

// analyzePythonAST detects Python-specific vulnerabilities via AST
func (aa *ASTAnalyzer) analyzePythonAST(node *treeSitter.Node, content []byte, lines []string, filePath string, srNo *int) []reporter.Finding {
	var findings []reporter.Finding

	nodeType := node.Type()
	startPoint := node.StartPoint()
	endPoint := node.EndPoint()
	lineRef := formatLineRef(int(startPoint.Row+1), int(endPoint.Row+1))

	switch nodeType {
	case "call":
		findings = append(findings, aa.checkPythonFunctionCall(node, content, lines, filePath, srNo, lineRef)...)
	case "assignment":
		findings = append(findings, aa.checkPythonAssignment(node, content, lines, filePath, srNo, lineRef)...)
	case "expression_statement":
		findings = append(findings, aa.checkPythonExpression(node, content, lines, filePath, srNo, lineRef)...)
	}

	// Recurse to children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			childFindings := aa.analyzePythonAST(child, content, lines, filePath, srNo)
			findings = append(findings, childFindings...)
		}
	}

	return findings
}

// checkPythonFunctionCall detects dangerous function calls in Python
func (aa *ASTAnalyzer) checkPythonFunctionCall(node *treeSitter.Node, content []byte, lines []string, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	functionNode := node.ChildByFieldName("function")
	if functionNode == nil {
		return findings
	}

	functionName := functionNode.Content(content)

	// Detect eval/exec usage
	if functionName == "eval" || functionName == "exec" || functionName == "compile" {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Dangerous Function Usage (AST)",
			FilePath:    filePath,
			Description: fmt.Sprintf("Use of %s() can execute arbitrary code - detected via AST analysis", functionName),
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: fmt.Sprintf("Avoid %s(). Use ast.literal_eval() for safe parsing or find safer alternatives", functionName),
			RuleID:      "ast-python-dangerous-eval",
			Source:      "ast-analyzer",
			CWE:         "CWE-94",
			OWASP:       "A03:2021",
			Confidence:  0.90,
		})
		*srNo++
	}

	// Detect SQL injection via string formatting
	if functionName == "execute" || functionName == "executemany" {
		argsNode := node.ChildByFieldName("arguments")
		if argsNode != nil && containsStringFormatting(argsNode, content) {
			findings = append(findings, reporter.Finding{
				SrNo:        *srNo,
				IssueName:   "Potential SQL Injection (AST)",
				FilePath:    filePath,
				Description: "SQL query constructed with string formatting may be vulnerable to injection - detected via AST",
				Severity:    "critical",
				LineNumber:  lineRef,
				AiValidated: "No",
				Remediation: "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
				RuleID:      "ast-python-sql-injection",
				Source:      "ast-analyzer",
			})
			*srNo++
		}
	}

	// Detect command injection via os.system/subprocess
	if functionName == "system" || functionName == "popen" || functionName == "call" {
		argsNode := node.ChildByFieldName("arguments")
		if argsNode != nil && containsUserInput(argsNode, content) {
			findings = append(findings, reporter.Finding{
				SrNo:        *srNo,
				IssueName:   "Potential Command Injection (AST)",
				FilePath:    filePath,
				Description: fmt.Sprintf("Shell command with potential user input via %s() - detected via AST", functionName),
				Severity:    "critical",
				LineNumber:  lineRef,
				AiValidated: "No",
				Remediation: "Use subprocess.run() with shell=False and pass arguments as list",
				RuleID:      "ast-python-command-injection",
				Source:      "ast-analyzer",
			})
			*srNo++
		}
	}

	// Detect PII Logging via Privacy Guard
	findings = append(findings, aa.checkPIILogging(node, content, filePath, srNo, lineRef, functionName)...)

	return findings
}

// checkPythonAssignment detects hardcoded secrets in assignments
func (aa *ASTAnalyzer) checkPythonAssignment(node *treeSitter.Node, content []byte, lines []string, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		return findings
	}

	varName := leftNode.Content(content)

	// Check for secret-like variable names
	if isSecretVariableName(varName) {
		value := rightNode.Content(content)
		if isHardcodedValue(value) && hasHighEntropy(stripQuotes(value)) {
			findings = append(findings, reporter.Finding{
				SrNo:        *srNo,
				IssueName:   "Hardcoded Secret (AST)",
				FilePath:    filePath,
				Description: fmt.Sprintf("Hardcoded value for sensitive variable: %s - detected via AST", varName),
				Severity:    "high",
				LineNumber:  lineRef,
				AiValidated: "No",
				Remediation: "Use environment variables or secrets manager for sensitive values",
				RuleID:      "ast-python-hardcoded-secret",
				Source:      "ast-analyzer",
			})
			*srNo++
		}
	}

	return findings
}

// checkPythonExpression detects XSS and other expression-based vulnerabilities
func (aa *ASTAnalyzer) checkPythonExpression(node *treeSitter.Node, content []byte, lines []string, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	// Detect direct output of user input (XSS risk)
	if containsPattern(node, content, "render_template_string") {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Potential SSTI Vulnerability (AST)",
			FilePath:    filePath,
			Description: "render_template_string with dynamic content may allow server-side template injection - detected via AST",
			Severity:    "critical",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Use render_template() with context variables instead of render_template_string()",
			RuleID:      "ast-python-ssti",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	return findings
}

// analyzeJavaScriptAST detects JavaScript-specific vulnerabilities via AST
func (aa *ASTAnalyzer) analyzeJavaScriptAST(node *treeSitter.Node, content []byte, lines []string, filePath string, srNo *int) []reporter.Finding {
	var findings []reporter.Finding

	nodeType := node.Type()
	startPoint := node.StartPoint()
	endPoint := node.EndPoint()
	lineRef := formatLineRef(int(startPoint.Row+1), int(endPoint.Row+1))

	switch nodeType {
	case "call_expression":
		findings = append(findings, aa.checkJSFunctionCall(node, content, lines, filePath, srNo, lineRef)...)
	case "assignment_expression":
		findings = append(findings, aa.checkJSAssignment(node, content, lines, filePath, srNo, lineRef)...)
	}

	// Recurse to children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			childFindings := aa.analyzeJavaScriptAST(child, content, lines, filePath, srNo)
			findings = append(findings, childFindings...)
		}
	}

	return findings
}

// checkJSFunctionCall detects dangerous function calls in JavaScript
func (aa *ASTAnalyzer) checkJSFunctionCall(node *treeSitter.Node, content []byte, lines []string, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	functionNode := node.ChildByFieldName("function")
	if functionNode == nil {
		return findings
	}

	functionName := functionNode.Content(content)

	// Detect eval usage
	if functionName == "eval" || functionName == "Function" {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Dangerous Function Usage (AST)",
			FilePath:    filePath,
			Description: fmt.Sprintf("Use of %s() can execute arbitrary code - detected via AST analysis", functionName),
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: fmt.Sprintf("Avoid %s(). Use JSON.parse() for data parsing or safer alternatives", functionName),
			RuleID:      "ast-js-dangerous-eval",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	// Detect innerHTML assignment (XSS risk)
	if functionName == "innerHTML" || containsPattern(node, content, ".innerHTML") {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Potential XSS via innerHTML (AST)",
			FilePath:    filePath,
			Description: "Direct innerHTML assignment may lead to XSS vulnerabilities - detected via AST",
			Severity:    "medium",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Use textContent for plain text or sanitize HTML with DOMPurify before assigning to innerHTML",
			RuleID:      "ast-js-xss-innerhtml",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	// Detect PII Logging via Privacy Guard
	findings = append(findings, aa.checkPIILogging(node, content, filePath, srNo, lineRef, functionName)...)

	return findings
}

// checkJSAssignment detects hardcoded secrets in JavaScript assignments
func (aa *ASTAnalyzer) checkJSAssignment(node *treeSitter.Node, content []byte, lines []string, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		return findings
	}

	varName := leftNode.Content(content)

	// Check for secret-like variable names
	if isSecretVariableName(varName) {
		value := rightNode.Content(content)
		if isHardcodedValue(value) && hasHighEntropy(stripQuotes(value)) {
			findings = append(findings, reporter.Finding{
				SrNo:        *srNo,
				IssueName:   "Hardcoded Secret (AST)",
				FilePath:    filePath,
				Description: fmt.Sprintf("Hardcoded value for sensitive variable: %s - detected via AST", varName),
				Severity:    "high",
				LineNumber:  lineRef,
				AiValidated: "No",
				Remediation: "Use environment variables or secrets manager for sensitive values",
				RuleID:      "ast-js-hardcoded-secret",
				Source:      "ast-analyzer",
			})
			*srNo++
		}
	}

	return findings
}

// Helper functions (non-redundant ones)
func getLanguageFromPath(filePath string) string {
	ext := filepath.Ext(filePath)
	switch ext {
	case ".py":
		return "python"
	case ".js", ".jsx", ".mjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".java", ".jsp":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".php":
		return "php"
	case ".go":
		return "go"
	case ".rb":
		return "ruby"
	case ".cs":
		return "csharp"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp":
		return "cpp"
	case ".sh", ".bash":
		return "bash"
	default:
		return ""
	}
}

// ============================================================================
// JAVA AST ANALYSIS
// ============================================================================

// analyzeJavaAST detects Java-specific vulnerabilities via AST
func (aa *ASTAnalyzer) analyzeJavaAST(node *treeSitter.Node, content []byte, lines []string, filePath string, srNo *int) []reporter.Finding {
	var findings []reporter.Finding

	nodeType := node.Type()
	startPoint := node.StartPoint()
	endPoint := node.EndPoint()
	lineRef := formatLineRef(int(startPoint.Row+1), int(endPoint.Row+1))

	switch nodeType {
	case "method_invocation":
		findings = append(findings, aa.checkJavaMethodCall(node, content, filePath, srNo, lineRef)...)
	case "variable_declarator":
		findings = append(findings, aa.checkJavaVariableDeclaration(node, content, filePath, srNo, lineRef)...)
	case "object_creation_expression":
		findings = append(findings, aa.checkJavaObjectCreation(node, content, filePath, srNo, lineRef)...)
	}

	// Recurse to children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			childFindings := aa.analyzeJavaAST(child, content, lines, filePath, srNo)
			findings = append(findings, childFindings...)
		}
	}

	return findings
}

func (aa *ASTAnalyzer) checkJavaMethodCall(node *treeSitter.Node, content []byte, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	nodeText := node.Content(content)

	// SQL injection via Statement.execute with concatenation
	if (strings.Contains(nodeText, "executeQuery") || strings.Contains(nodeText, "executeUpdate") ||
		strings.Contains(nodeText, "execute")) && strings.Contains(nodeText, "+") {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "SQL Injection (AST)",
			FilePath:    filePath,
			Description: "SQL query constructed with string concatenation detected via AST",
			Severity:    "critical",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Use PreparedStatement with parameterized queries",
			RuleID:      "ast-java-sql-injection",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	// Command injection via Runtime.exec
	if strings.Contains(nodeText, "Runtime") && strings.Contains(nodeText, "exec") {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Command Injection Risk (AST)",
			FilePath:    filePath,
			Description: "Runtime.exec() usage detected — potential command injection if input is user-controlled",
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Avoid Runtime.exec(). Use ProcessBuilder with explicit args list",
			RuleID:      "ast-java-command-injection",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	// Insecure deserialization via readObject
	if strings.Contains(nodeText, "readObject") {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Insecure Deserialization (AST)",
			FilePath:    filePath,
			Description: "ObjectInputStream.readObject() can lead to RCE if deserializing untrusted data",
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Avoid deserializing untrusted data. Use JSON or implement ObjectInputFilter",
			RuleID:      "ast-java-insecure-deserialization",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	// XSS via response writer
	if (strings.Contains(nodeText, "getWriter") || strings.Contains(nodeText, "getOutputStream")) &&
		strings.Contains(nodeText, "getParameter") {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "XSS via Response (AST)",
			FilePath:    filePath,
			Description: "User input written directly to HTTP response without encoding",
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "HTML-encode output using OWASP ESAPI or Apache Commons Text",
			RuleID:      "ast-java-xss-response",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	return findings
}

func (aa *ASTAnalyzer) checkJavaVariableDeclaration(node *treeSitter.Node, content []byte, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	nodeText := node.Content(content)

	// Hardcoded secrets in variable declarations
	if (strings.Contains(strings.ToLower(nodeText), "password") || strings.Contains(strings.ToLower(nodeText), "secret") ||
		strings.Contains(strings.ToLower(nodeText), "apikey") || strings.Contains(strings.ToLower(nodeText), "api_key")) &&
		(strings.Contains(nodeText, "\"") || strings.Contains(nodeText, "'")) {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Hardcoded Secret (AST)",
			FilePath:    filePath,
			Description: "Hardcoded secret detected in variable declaration via AST",
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Use environment variables, Java system properties, or a secrets manager",
			RuleID:      "ast-java-hardcoded-secret",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	return findings
}

func (aa *ASTAnalyzer) checkJavaObjectCreation(node *treeSitter.Node, content []byte, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	nodeText := node.Content(content)

	// Insecure cipher usage
	if strings.Contains(nodeText, "Cipher") && (strings.Contains(nodeText, "ECB") || strings.Contains(nodeText, "DES")) {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Weak Cipher Usage (AST)",
			FilePath:    filePath,
			Description: "ECB mode or DES cipher detected — both are cryptographically weak",
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Use AES/GCM/NoPadding for authenticated encryption",
			RuleID:      "ast-java-weak-cipher",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	return findings
}

// ============================================================================
// KOTLIN AST ANALYSIS
// ============================================================================

// analyzeKotlinAST detects Kotlin/Android-specific vulnerabilities via AST
func (aa *ASTAnalyzer) analyzeKotlinAST(node *treeSitter.Node, content []byte, lines []string, filePath string, srNo *int) []reporter.Finding {
	var findings []reporter.Finding

	nodeType := node.Type()
	startPoint := node.StartPoint()
	endPoint := node.EndPoint()
	lineRef := formatLineRef(int(startPoint.Row+1), int(endPoint.Row+1))

	switch nodeType {
	case "call_expression":
		findings = append(findings, aa.checkKotlinCallExpression(node, content, filePath, srNo, lineRef)...)
	case "property_declaration":
		findings = append(findings, aa.checkKotlinPropertyDeclaration(node, content, filePath, srNo, lineRef)...)
	}

	// Recurse to children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			childFindings := aa.analyzeKotlinAST(child, content, lines, filePath, srNo)
			findings = append(findings, childFindings...)
		}
	}

	return findings
}

func (aa *ASTAnalyzer) checkKotlinCallExpression(node *treeSitter.Node, content []byte, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	nodeText := node.Content(content)

	// Insecure WebView configuration
	if strings.Contains(nodeText, "javaScriptEnabled") && strings.Contains(nodeText, "true") {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Insecure WebView (AST)",
			FilePath:    filePath,
			Description: "WebView has JavaScript enabled — risk of XSS and code injection",
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Disable JavaScript if not needed. Use @JavascriptInterface annotation",
			RuleID:      "ast-kotlin-insecure-webview",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	// SQL injection via rawQuery
	if (strings.Contains(nodeText, "rawQuery") || strings.Contains(nodeText, "execSQL")) &&
		(strings.Contains(nodeText, "$") || strings.Contains(nodeText, "+")) {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "SQL Injection (AST)",
			FilePath:    filePath,
			Description: "SQL query with string interpolation or concatenation in Android SQLite",
			Severity:    "critical",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Use parameterized queries: rawQuery(\"SELECT * FROM users WHERE id = ?\", arrayOf(userId))",
			RuleID:      "ast-kotlin-sql-injection",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	// Sensitive data in logs
	if strings.Contains(nodeText, "Log.") &&
		(strings.Contains(strings.ToLower(nodeText), "password") || strings.Contains(strings.ToLower(nodeText), "token") ||
			strings.Contains(strings.ToLower(nodeText), "secret")) {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Sensitive Data Logging (AST)",
			FilePath:    filePath,
			Description: "Sensitive data (password/token/secret) found in Android Log statement",
			Severity:    "medium",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Remove sensitive data from log statements in production builds",
			RuleID:      "ast-kotlin-sensitive-logging",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	// Implicit intent (may be intercepted)
	if strings.Contains(nodeText, "startActivity") && strings.Contains(nodeText, "Intent(") &&
		!strings.Contains(nodeText, "::class") {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Implicit Intent (AST)",
			FilePath:    filePath,
			Description: "Implicit intent detected — may be intercepted by malicious apps",
			Severity:    "medium",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Use explicit intents with the target component class",
			RuleID:      "ast-kotlin-implicit-intent",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	// SharedPreferences with world-readable mode
	if strings.Contains(nodeText, "getSharedPreferences") && strings.Contains(nodeText, "MODE_WORLD") {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Insecure SharedPreferences (AST)",
			FilePath:    filePath,
			Description: "SharedPreferences with world-readable/writeable mode detected",
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Use Context.MODE_PRIVATE for SharedPreferences",
			RuleID:      "ast-kotlin-insecure-sharedprefs",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	return findings
}

func (aa *ASTAnalyzer) checkKotlinPropertyDeclaration(node *treeSitter.Node, content []byte, filePath string, srNo *int, lineRef string) []reporter.Finding {
	var findings []reporter.Finding

	nodeText := node.Content(content)

	// Hardcoded secrets
	if (strings.Contains(strings.ToLower(nodeText), "password") || strings.Contains(strings.ToLower(nodeText), "secret") ||
		strings.Contains(strings.ToLower(nodeText), "apikey") || strings.Contains(strings.ToLower(nodeText), "api_key") ||
		strings.Contains(strings.ToLower(nodeText), "token")) &&
		(strings.Contains(nodeText, "\"") || strings.Contains(nodeText, "'")) {
		findings = append(findings, reporter.Finding{
			SrNo:        *srNo,
			IssueName:   "Hardcoded Secret (AST)",
			FilePath:    filePath,
			Description: "Hardcoded secret detected in Kotlin property declaration",
			Severity:    "high",
			LineNumber:  lineRef,
			AiValidated: "No",
			Remediation: "Use Android Keystore, EncryptedSharedPreferences, or BuildConfig fields",
			RuleID:      "ast-kotlin-hardcoded-secret",
			Source:      "ast-analyzer",
		})
		*srNo++
	}

	return findings
}

// ScanWithAST runs AST-based analysis on a directory
func ScanWithAST(targetDir string) ([]reporter.Finding, error) {
	var findings []reporter.Finding
	analyzer := NewASTAnalyzer()

	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		fileFindings, err := analyzer.AnalyzeFile(path)
		if err != nil {
			utils.LogWarn(fmt.Sprintf("AST analysis failed for %s: %v", path, err))
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

// populateCacheFromNode recursively extracts identifiers and strings into the reachability cache
func (aa *ASTAnalyzer) populateCacheFromNode(node *treeSitter.Node, content []byte) {
	nodeType := node.Type()
	if nodeType == "identifier" || nodeType == "string" || nodeType == "property_identifier" {
		nodeText := strings.ToLower(node.Content(content))
		if nodeText != "" {
			aa.reachabilityCache[nodeText] = true
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		aa.populateCacheFromNode(node.Child(i), content)
	}
}

// BuildReachabilityCache scans the AST of an entire directory to build a cache of identifiers.
func (aa *ASTAnalyzer) BuildReachabilityCache(targetDir string) {
	if aa.reachabilityCache != nil {
		return // Cache already built
	}
	aa.reachabilityCache = make(map[string]bool)

	filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Skip common directories
		base := filepath.Base(path)
		if base == "node_modules" || base == "vendor" || base == ".git" {
			return filepath.SkipDir
		}

		lang := getLanguageFromPath(path)
		if lang == "" || aa.parsers[lang] == nil {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		parser := aa.parsers[lang]
		tree := parser.Parse(nil, content)
		if tree == nil {
			return nil
		}
		defer tree.Close()

		aa.populateCacheFromNode(tree.RootNode(), content)
		return nil
	})
}

// IsFunctionReachable quickly checks the AST cache to see if a specific library or function is ever called.
// This is used for SCA Reachability Analysis to reduce false positives for unused dependencies.
func (aa *ASTAnalyzer) IsFunctionReachable(targetDir string, functionOrLibName string) bool {
	aa.BuildReachabilityCache(targetDir)

	functionOrLibName = strings.ToLower(functionOrLibName)

	// Since we cached exact exact instances of identifiers, we iterate over the map keys
	// O(K) where K is unique identifiers typically finishes in microseconds.
	for cachedID := range aa.reachabilityCache {
		if strings.Contains(cachedID, functionOrLibName) {
			return true
		}
	}

	return false
}

// checkPIILogging detects if sensitive information is being logged/printed
func (aa *ASTAnalyzer) checkPIILogging(node *treeSitter.Node, content []byte, filePath string, srNo *int, lineRef string, functionName string) []reporter.Finding {
	var findings []reporter.Finding

	// Logging/Printing patterns
	logPattern := strings.ToLower(functionName)
	isLogging := strings.Contains(logPattern, "print") ||
		strings.Contains(logPattern, "log") ||
		strings.Contains(logPattern, "fmt.pr") ||
		strings.Contains(logPattern, "console.") ||
		strings.Contains(logPattern, "write")

	if !isLogging {
		return findings
	}

	// Arguments to the function
	var argsNode *treeSitter.Node
	if node.Type() == "call" || node.Type() == "call_expression" {
		argsNode = node.ChildByFieldName("arguments")
	}

	if argsNode == nil {
		// Fallback: look for children that might be arguments
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "argument_list" || child.Type() == "arguments" {
				argsNode = child
				break
			}
		}
	}

	if argsNode != nil {
		piiKeywords := []string{"ssn", "social_security", "credit_card", "password", "secret", "api_key", "token", "dob", "birth_date", "email"}
		argsText := strings.ToLower(argsNode.Content(content))

		for _, keyword := range piiKeywords {
			if strings.Contains(argsText, keyword) {
				findings = append(findings, reporter.Finding{
					SrNo:        *srNo,
					IssueName:   "Privacy Guard: PII Logging Detected",
					FilePath:    filePath,
					Description: fmt.Sprintf("Sensitive information (keyword: '%s') detected in logging statement via %s() - risk of PII leakage", keyword, functionName),
					Severity:    "medium",
					LineNumber:  lineRef,
					AiValidated: "No",
					Remediation: "Ensure PII is masked or encrypted before logging. Avoid logging passwords, tokens, or SSNs in plain text.",
					RuleID:      "ast-privacy-pii-logging",
					Source:      "ast-analyzer",
					CWE:         "CWE-532",
					OWASP:       "A04:2021-Insecure-Design",
					Confidence:  0.85,
				})
				*srNo++
				break // One finding per logging statement
			}
		}
	}

	return findings
}
