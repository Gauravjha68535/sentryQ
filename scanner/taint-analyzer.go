package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"QWEN_SCR_24_FEB_2026/reporter"
	"QWEN_SCR_24_FEB_2026/utils"
)

// TaintAnalyzer tracks user input through code to detect injection vulnerabilities
type TaintAnalyzer struct {
	taintSources      []*regexp.Regexp
	taintSinks        map[string][]string
	sanitizers        []*regexp.Regexp
	scopeStartPattern *regexp.Regexp
	// Pre-compiled patterns for taint flow analysis (compiled once at initialization)
	methodChainRe   *regexp.Regexp
	concatRe        *regexp.Regexp
	interpolationRe *regexp.Regexp
	funcCallRe      *regexp.Regexp
}

// NewTaintAnalyzer creates a new taint analyzer
func NewTaintAnalyzer() *TaintAnalyzer {
	return &TaintAnalyzer{
		// Sources: Where user input enters the application
		taintSources: []*regexp.Regexp{
			// Python
			regexp.MustCompile(`(?i)(request\.(args|form|json|values|GET|POST)|req\.(query|body|params)|input\s*\(|sys\.argv|os\.environ)`),
			// PHP
			regexp.MustCompile(`(?i)(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|\$HTTP_(GET|POST)_VARS)`),
			// JS / TS / Node
			regexp.MustCompile(`(?i)(req\.params|req\.query|req\.body|req\.cookies|req\.headers|window\.location|document\.(cookie|URL|documentURI|referrer|name)|process\.argv|process\.env)`),
			// Java / Kotlin
			regexp.MustCompile(`(?i)(request\.getParameter|request\.getHeader|request\.getCookies|System\.getenv|System\.getProperty|Scanner\(System\.in\))`),
			// C# / ASP.NET
			regexp.MustCompile(`(?i)(Request\.(QueryString|Form|Cookies|Headers)|Console\.ReadLine|Environment\.GetCommandLineArgs|Environment\.GetEnvironmentVariable)`),
			// Go
			regexp.MustCompile(`(?i)(r\.URL\.Query|r\.FormValue|r\.PostFormValue|r\.Header\.Get|r\.Cookie|os\.Args|os\.Getenv|chi\.URLParam|mux\.Vars)`),
			// Ruby
			regexp.MustCompile(`(?i)(params\[|request\.(env|cookies|headers)|ENV\[)`),
			// Swift
			regexp.MustCompile(`(?i)(URLComponents|URLQueryItem|request\.url|UserDefaults\.standard)`),
			// Dart/Flutter
			regexp.MustCompile(`(?i)(request\.uri|request\.headers|Platform\.environment|stdin\.readLineSync)`),
		},
		// Sinks: Dangerous functions that should not receive tainted input
		taintSinks: map[string][]string{
			"python": {
				`execute\s*\(`, `executemany\s*\(`, `exec\s*\(`, `eval\s*\(`, `os\.system\s*\(`, `subprocess\.(call|run|Popen|check_output)\s*\(`,
				`cursor\.execute\s*\(`, `\.raw\s*\(`, `render_template_string\s*\(`, `yaml\.load\s*\(`, `pickle\.loads\s*\(`, `requests\.(get|post|put|delete)\s*\(`,
			},
			"javascript": {
				`eval\s*\(`, `Function\s*\(`, `innerHTML\s*=`, `document\.write\s*\(`, `exec\s*\(`,
				`child_process\.(exec|spawn|execSync)\s*\(`, `\.query\s*\(`, `\.execute\s*\(`, `vm\.runInContext\s*\(`, `axios\s*\(`, `fetch\s*\(`,
			},
			"typescript": {
				`eval\s*\(`, `Function\s*\(`, `innerHTML\s*=`, `document\.write\s*\(`, `exec\s*\(`,
				`child_process\.(exec|spawn|execSync)\s*\(`, `\.query\s*\(`, `\.execute\s*\(`, `vm\.runInContext\s*\(`, `axios\s*\(`, `fetch\s*\(`,
			},
			"php": {
				`eval\s*\(`, `exec\s*\(`, `system\s*\(`, `passthru\s*\(`, `shell_exec\s*\(`,
				`mysql_query\s*\(`, `mysqli_query\s*\(`, `PDO::query\s*\(`, `include\s*\(`, `require\s*\(`, `unserialize\s*\(`, `curl_init\s*\(`,
			},
			"java": {
				`\.executeQuery\s*\(`, `\.executeUpdate\s*\(`, `Runtime\.getRuntime\(\)\.exec\s*\(`, `ProcessBuilder\s*\(`, `\.readObject\s*\(`,
				`\.(getOutputStream|getWriter)\(\)\.print`,
			},
			"kotlin": {
				`\.rawQuery\s*\(`, `\.execSQL\s*\(`, `Runtime\.getRuntime\(\)\.exec\s*\(`, `ProcessBuilder\s*\(`, `\.readObject\s*\(`,
			},
			"csharp": {
				`SqlCommand\s*\(`, `\.ExecuteReader\s*\(`, `\.ExecuteNonQuery\s*\(`, `Process\.Start\s*\(`, `BinaryFormatter\(\)\.Deserialize\s*\(`, `\.InnerHtml\s*=`, `Response\.Write\s*\(`,
			},
			"go": {
				`db\.Query\s*\(`, `db\.Exec\s*\(`, `exec\.Command\s*\(`, `http\.Get\s*\(`, `http\.NewRequest\s*\(`, `html/template`, `text/template`,
			},
			"ruby": {
				`eval\s*\(`, `system\s*\(`, `exec\s*\(`, `%\(`, `%\w\(`, `User\.find_by_sql\s*\(`, `ActiveRecord::Base\.connection\.execute\s*\(`, `URI\.open\s*\(`, `Net::HTTP\.get\s*\(`, `Marshal\.load\s*\(`,
			},
			"swift": {
				`NSTask\s*\(`, `Process\s*\(`, `evaluateJavaScript\s*\(`, `NSPredicate\s*\(`, `FileManager.*contentsOfDirectory`,
			},
			"dart": {
				`Process\.run\s*\(`, `Process\.start\s*\(`, `HttpClient.*get\s*\(`, `dart:io.*File\s*\(`,
			},
		},
		// Sanitizers: Functions that clean/sanitize input
		sanitizers: []*regexp.Regexp{
			// Generic sanitization functions
			regexp.MustCompile(`(?i)(escape|sanitize|htmlspecialchars|htmlentities|quote|escape_string|urlencode|encodeURIComponent|encodeURI)`),
			// Frontend sanitizers
			regexp.MustCompile(`(?i)(DOMPurify\.sanitize|sanitizeHtml|validator\.escape|xss\(|bleach\.clean)`),
			// Parameterized queries / ORM query builders
			regexp.MustCompile(`(?i)(Bind|Prepare|param|\?\.placeholder|setParameter|bindParam|bindValue|addBindValue)`),
			// Type casting / conversion (makes input safe for injection)
			regexp.MustCompile(`(?i)(parseInt|parseFloat|Number\(|int\(|float\(|Integer\.parseInt|Integer\.valueOf|strconv\.Atoi|strconv\.ParseInt)`),
			// ORM methods (inherently parameterized)
			regexp.MustCompile(`(?i)(\.where\(.*\?|\.filter\(|\.exclude\(|\.get\(pk=|\.objects\.|\.findOne\(|\.findById\(|\.findByPk\()`),
			// Template engines with auto-escaping
			regexp.MustCompile(`(?i)(html/template|template\.HTML|markupsafe\.escape|Markup\(|SafeString)`),
			// Safe output functions (not sinks — they PRODUCE safe output)
			regexp.MustCompile(`(?i)(JSON\.stringify|JSON\.parse|jsonify|json\.dumps|json\.loads|urlparse|url\.parse|path\.resolve|path\.join)`),
			// Guard validation functions
			regexp.MustCompile(`(?i)(startsWith|endsWith|includes|indexOf|match|test|validate|isValid|whitelist|allowlist|ALLOWED)`),
		},
		// Scope Boundaries: Basic boundary detection to clear taint state and avoid false positives across functions
		scopeStartPattern: regexp.MustCompile(`(?i)(^|\s)(func\s+\w+|def\s+\w+|class\s+\w+|public\s+\w+\s+\w+\(|private\s+\w+\s+\w+\(|protected\s+\w+\s+\w+\()`),
		// Pre-compiled patterns for taint flow analysis (compiled once at initialization)
		methodChainRe:   regexp.MustCompile(`(?:var|let|const)?\s*\$?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|:=)\s*(?:await\s+)?\$?([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_]+)\s*\(`),
		concatRe:        regexp.MustCompile(`(?:var|let|const)?\s*\$?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|:=|\+=)\s*.*(?:await\s+)?\$?([a-zA-Z_][a-zA-Z0-9_]*)`),
		interpolationRe: regexp.MustCompile(`(?:var|let|const)?\s*\$?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|:=)\s*(?:f"|f'|` + "`" + `|\$\{).*\$?([a-zA-Z_][a-zA-Z0-9_]*)`),
		funcCallRe:      regexp.MustCompile(`(?:await\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*?)\)`),
	}
}

// taintInfo stores metadata about how a variable became tainted
type taintInfo struct {
	SourceLine int      // Line where taint originated
	Hops       int      // Number of alias hops from original source
	SourceVar  string   // Original tainted source variable
	Path       []string // Steps in the execution path
}

// Risk 4 fix: Maximum alias hops to prevent circular/deep chains (a=b; b=a)
const maxTaintHops = 10

// AnalyzeTaintFlow scans a file for taint flow vulnerabilities
func (ta *TaintAnalyzer) AnalyzeTaintFlow(filePath string) ([]reporter.Finding, error) {
	lang := getLanguageFromPath(filePath)
	if lang == "" || ta.taintSinks[lang] == nil {
		return nil, nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(utils.NormalizeNewlines(string(content)), "\n")

	var findings []reporter.Finding
	srNo := 1

	// Track taint propagation through the file
	taintedVars := make(map[string]taintInfo)
	sanitizedVars := make(map[string]bool)

	// De-duplication: track reported source-sink pairs to avoid duplicates
	reportedPairs := make(map[string]bool)


	// Pre-compile sink regexes for performance
	compiledSinks := make([]*regexp.Regexp, 0)
	sinkPatterns := ta.taintSinks[lang]
	for _, sp := range sinkPatterns {
		re, err := regexp.Compile(sp)
		if err == nil {
			compiledSinks = append(compiledSinks, re)
		}
	}

	// Regexes for method-chain and concat/interpolation detection
	// Use pre-compiled patterns from struct for better performance
	methodChainRe := ta.methodChainRe
	concatRe := ta.concatRe
	interpolationRe := ta.interpolationRe
	scopeLevel := 0

	for lineNum, line := range lines {
		currentLine := lineNum + 1
		trimmedLine := strings.TrimSpace(line)

		// 0. Track block level scope `{` and `}`
		braceDiff := strings.Count(line, "{") - strings.Count(line, "}")
		scopeLevel += braceDiff
		if scopeLevel < 0 {
			scopeLevel = 0
		}

		// Clear scope if we hit a new function/class definition or we exit the root scope
		if ta.scopeStartPattern.MatchString(line) || (braceDiff < 0 && scopeLevel == 0) {
			taintedVars = make(map[string]taintInfo)
			sanitizedVars = make(map[string]bool)
		}

		// 1. Check for taint sources
		for _, sourcePattern := range ta.taintSources {
			if sourcePattern.MatchString(line) {
				varName := extractVariableName(line)
				if varName != "" {
					taintedVars[varName] = taintInfo{
						SourceLine: currentLine,
						Hops:       0,
						SourceVar:  varName,
						Path:       []string{fmt.Sprintf("Line %d: Source '%s' initialized", currentLine, varName)},
					}
					sanitizedVars[varName] = false
				}
			}
		}

		// 2a. Track direct aliases (a = b)
		aliasVar, sourceVar := extractAliasAssignment(line)
		if aliasVar != "" && sourceVar != "" {
			if info, isTainted := taintedVars[sourceVar]; isTainted && info.Hops < maxTaintHops {
				path := append([]string{}, info.Path...)
				path = append(path, fmt.Sprintf("Line %d: Propagated to '%s' (alias)", currentLine, aliasVar))
				taintedVars[aliasVar] = taintInfo{
					SourceLine: info.SourceLine,
					Hops:       info.Hops + 1,
					SourceVar:  info.SourceVar,
					Path:       path,
				}
				sanitizedVars[aliasVar] = sanitizedVars[sourceVar]
			}
		}

		// 2b. Track method-chain propagation (result = taintedVar.trim())
		if mcMatch := methodChainRe.FindStringSubmatch(trimmedLine); len(mcMatch) > 2 {
			destVar := mcMatch[1]
			srcVar := mcMatch[2]
			if info, isTainted := taintedVars[srcVar]; isTainted && !sanitizedVars[srcVar] && info.Hops < maxTaintHops {
				path := append([]string{}, info.Path...)
				path = append(path, fmt.Sprintf("Line %d: Propagated to '%s' (method chain)", currentLine, destVar))
				taintedVars[destVar] = taintInfo{
					SourceLine: info.SourceLine,
					Hops:       info.Hops + 1,
					SourceVar:  info.SourceVar,
					Path:       path,
				}
				sanitizedVars[destVar] = false
			}
		}

		// 2c. Track string concatenation taint (query = "SELECT " + userInput)
		if concatMatch := concatRe.FindStringSubmatch(trimmedLine); len(concatMatch) > 2 {
			destVar := concatMatch[1]
			for varName, info := range taintedVars {
				if !sanitizedVars[varName] && containsVariable(trimmedLine, varName) && destVar != varName && info.Hops < maxTaintHops {
					path := append([]string{}, info.Path...)
					path = append(path, fmt.Sprintf("Line %d: Propagated to '%s' (concatenation)", currentLine, destVar))
					taintedVars[destVar] = taintInfo{
						SourceLine: info.SourceLine,
						Hops:       info.Hops + 1,
						SourceVar:  info.SourceVar,
						Path:       path,
					}
					sanitizedVars[destVar] = false
					break
				}
			}
		}

		// 2d. Track string interpolation taint (query = f"SELECT {userInput}")
		if interpMatch := interpolationRe.FindStringSubmatch(trimmedLine); len(interpMatch) > 2 {
			destVar := interpMatch[1]
			for varName, info := range taintedVars {
				if !sanitizedVars[varName] && containsVariable(trimmedLine, varName) && destVar != varName && info.Hops < maxTaintHops {
					path := append([]string{}, info.Path...)
					path = append(path, fmt.Sprintf("Line %d: Propagated to '%s' (interpolation)", currentLine, destVar))
					taintedVars[destVar] = taintInfo{
						SourceLine: info.SourceLine,
						Hops:       info.Hops + 1,
						SourceVar:  info.SourceVar,
						Path:       path,
					}
					sanitizedVars[destVar] = false
					break
				}
			}
		}

		// 3. Check for sanitizers
		for _, sanitizer := range ta.sanitizers {
			if sanitizer.MatchString(line) {
				varName := extractSanitizedVariable(line, sanitizer)
				if varName != "" {
					sanitizedVars[varName] = true
				} else {
					genericVar := extractVariableName(line)
					if genericVar != "" {
						sanitizedVars[genericVar] = true
					}
				}
			}
		}


		// 4. Check for taint sinks with tainted input
		for i, re := range compiledSinks {
			if re.MatchString(line) {
				// Safe sink exclusion: skip sinks that use parameterized patterns
				if isSafeSinkUsage(line, sinkPatterns[i]) {
					continue
				}

				for varName, info := range taintedVars {
					if !sanitizedVars[varName] && containsVariable(line, varName) {

						// De-duplicate: skip if we already reported this source→sink pair
						pairKey := fmt.Sprintf("%s→%d→%s", info.SourceVar, info.SourceLine, sinkPatterns[i])
						if reportedPairs[pairKey] {
							continue
						}
						reportedPairs[pairKey] = true

						// Graduated confidence scoring
						confidence := calculateTaintConfidence(currentLine, info)

						// Guard clause detection: scan lines between source and sink for validation
						if hasGuardClause(lines, info.SourceLine, currentLine) {
							confidence = 0.25 // Effectively suppress — guard exists
						}

						// Skip very low confidence findings
						if confidence < 0.30 {
							continue
						}

						findings = append(findings, reporter.Finding{
							SrNo:        srNo,
							IssueName:   fmt.Sprintf("Taint Flow: %s Injection", getInjectionType(sinkPatterns[i])),
							FilePath:    filePath,
							Description: fmt.Sprintf("User input '%s' (tainted on line %d, %d hops) flows to %s on line %d without sanitization", info.SourceVar, info.SourceLine, info.Hops, getInjectionType(sinkPatterns[i]), currentLine),
							ExploitPath: append(info.Path, fmt.Sprintf("Line %d: Reaches sink '%s'", currentLine, sinkPatterns[i])),
							Severity:    "critical",
							LineNumber:  fmt.Sprintf("%d", currentLine),
							AiValidated: "No",
							Remediation: getTaintRemediation(sinkPatterns[i]),
							RuleID:      fmt.Sprintf("dataflow-%s-injection", strings.ToLower(getInjectionType(sinkPatterns[i]))),
							Source:      "taint-analyzer",
							CWE:         getInjectionCWE(sinkPatterns[i]),
							OWASP:       getInjectionOWASP(sinkPatterns[i]),
							Confidence:  confidence,
						})
						srNo++
						break // One finding per line per sink
					}
				}
			}
		}
	}

	return findings, nil
}

// calculateTaintConfidence computes a confidence score based on distance and hop count
func calculateTaintConfidence(sinkLine int, info taintInfo) float64 {
	confidence := 0.95

	// Degrade for large line distance (potential scope leak)
	lineDiff := sinkLine - info.SourceLine
	if lineDiff > 100 {
		confidence -= 0.15
	} else if lineDiff > 50 {
		confidence -= 0.10
	} else if lineDiff > 20 {
		confidence -= 0.05
	}

	// Degrade slightly for each alias hop (propagation uncertainty)
	if info.Hops > 3 {
		confidence -= 0.10
	} else if info.Hops > 1 {
		confidence -= 0.05
	}

	// Floor at 0.60
	if confidence < 0.60 {
		confidence = 0.60
	}
	return confidence
}

// isSafeSinkUsage checks if a sink line contains patterns that make it safe.
// For example, parameterized queries with ? placeholders, execFile with array args, etc.
func isSafeSinkUsage(line, sinkPattern string) bool {
	lowerLine := strings.ToLower(line)
	injType := getInjectionType(sinkPattern)

	switch injType {
	case "SQL":
		// Parameterized queries: uses ?, $1, %s placeholders with separate args
		if strings.Contains(line, "?") && (strings.Contains(line, "[") || strings.Contains(line, ",")) {
			return true // e.g., db.query("SELECT * FROM users WHERE id = ?", [id])
		}
		if strings.Contains(line, "$1") || strings.Contains(line, "$2") {
			return true // PostgreSQL parameterized
		}
	case "Command":
		// execFile / spawn with array args = no shell invocation
		if strings.Contains(lowerLine, "execfile") || strings.Contains(lowerLine, "spawn") {
			return true
		}
		// subprocess.run with list args
		if strings.Contains(lowerLine, "subprocess") && strings.Contains(line, "[") {
			return true
		}
	case "XSS":
		// textContent is safe (not innerHTML)
		if strings.Contains(lowerLine, "textcontent") {
			return true
		}
	case "SSRF":
		// If the line also contains validation keywords, it's likely guarded
		if strings.Contains(lowerLine, "allowlist") || strings.Contains(lowerLine, "whitelist") || strings.Contains(lowerLine, "allowed_hosts") {
			return true
		}
	}

	// Safe output functions that should never be sinks
	safeOutputFuncs := []string{"jsonify", "json.dumps", "json_encode", "json.stringify",
		"urlparse", "url.parse", "path.resolve", "path.join",
		"textcontent", "createtextnode"}
	for _, safe := range safeOutputFuncs {
		if strings.Contains(lowerLine, safe) {
			return true
		}
	}

	return false
}

// hasGuardClause scans lines between source and sink for validation/guard patterns.
// If found, the taint flow is likely guarded and should be suppressed.
func hasGuardClause(lines []string, sourceLine, sinkLine int) bool {
	// Convert to 0-indexed
	start := sourceLine // already 1-indexed, so this is line after source
	end := sinkLine - 1
	if start < 0 {
		start = 0
	}
	if end >= len(lines) {
		end = len(lines) - 1
	}

	guardPatterns := []string{
		"not in ", "not_in", "!= ", "!== ",
		"startswith", "endswith", "includes(",
		"indexof(", "match(", ".test(",
		"validate", "isvalid", "whitelist", "allowlist",
		"allowed_hosts", "return 403", "return 401", "return 400",
		"raise ", "throw ", "abort(",
		"path.sep", "filepath.clean",
	}

	for i := start; i <= end; i++ {
		lowerLine := strings.ToLower(strings.TrimSpace(lines[i]))
		// Skip empty lines
		if lowerLine == "" {
			continue
		}
		for _, pattern := range guardPatterns {
			if strings.Contains(lowerLine, pattern) {
				return true
			}
		}
	}
	return false
}

// extractVariableName extracts a variable name from an assignment line
func extractVariableName(line string) string {
	// Match common assignment patterns: var =, let var =, const var =, $var =, var :=
	re := regexp.MustCompile(`(?:var|let|const|String|int|String\[\])\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|:=)|\$?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|:=)`)
	match := re.FindStringSubmatch(line)
	if len(match) > 1 && match[1] != "" {
		return match[1]
	}
	if len(match) > 2 && match[2] != "" {
		return match[2]
	}
	return ""
}

// extractAliasAssignment detects `a = b` forms
func extractAliasAssignment(line string) (string, string) {
	// Looks for 'varName = sourceVar'
	re := regexp.MustCompile(`(?:var|let|const)?\s*\$?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|:=)\s*\$?([a-zA-Z_][a-zA-Z0-9_]*)`)
	match := re.FindStringSubmatch(line)
	if len(match) > 2 {
		// Exclude common keywords that might match
		if isKeyword(match[2]) {
			return "", ""
		}
		return match[1], match[2]
	}
	return "", ""
}

// extractSanitizedVariable looks for `sanitize(var)`
func extractSanitizedVariable(line string, sanitizer *regexp.Regexp) string {
	// We try to find the variable passed to the sanitizer
	re := regexp.MustCompile(sanitizer.String() + `\s*\(\s*\$?([a-zA-Z_][a-zA-Z0-9_]*)`)
	match := re.FindStringSubmatch(line)
	if len(match) > 1 {
		return match[1] // The captured group after the sanitizer call
	}

	// Also catch reassignment sanitization: myVar = escape(something)
	assignRe := regexp.MustCompile(`\$?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|:=)\s*.*` + sanitizer.String())
	matchAssign := assignRe.FindStringSubmatch(line)
	if len(matchAssign) > 1 {
		return matchAssign[1]
	}

	return ""
}

// containsVariable checks if a variable name appears as an independent token
func containsVariable(line, varName string) bool {
	varSafePatternStr := `\b` + regexp.QuoteMeta(varName) + `\b`
	if strings.HasPrefix(varName, "$") {
		varSafePatternStr = `\` + regexp.QuoteMeta(varName) + `\b`
	}
	re, err := regexp.Compile(varSafePatternStr)
	if err != nil {
		return strings.Contains(line, varName)
	}
	return re.MatchString(line)
}

func isKeyword(word string) bool {
	keywords := map[string]bool{
		"true": true, "false": true, "null": true, "nil": true, "None": true, "new": true, "await": true, "yield": true, "return": true, "if": true, "for": true, "while": true,
	}
	return keywords[word]
}

func getInjectionType(sinkPattern string) string {
	if strings.Contains(sinkPattern, "execute") || strings.Contains(sinkPattern, "query") || strings.Contains(sinkPattern, "mysql") || strings.Contains(sinkPattern, "ExecuteReader") || strings.Contains(sinkPattern, "find_by_sql") || strings.Contains(sinkPattern, "db.Query") || strings.Contains(sinkPattern, "db.Exec") || strings.Contains(sinkPattern, "ExecuteNonQuery") {
		return "SQL"
	}
	if strings.Contains(sinkPattern, "eval") || strings.Contains(sinkPattern, "Function") || strings.Contains(sinkPattern, "vm.runInContext") {
		return "Code"
	}
	if strings.Contains(sinkPattern, "system") || strings.Contains(sinkPattern, "exec") || strings.Contains(sinkPattern, "subprocess") || strings.Contains(sinkPattern, "Process") || strings.Contains(sinkPattern, "Runtime") || strings.Contains(sinkPattern, "popen") || strings.Contains(sinkPattern, "passthru") || strings.Contains(sinkPattern, "shell_exec") {
		return "Command"
	}
	if strings.Contains(sinkPattern, "innerHTML") || strings.Contains(sinkPattern, "document.write") || strings.Contains(sinkPattern, "InnerHtml") || strings.Contains(sinkPattern, "Response.Write") || strings.Contains(sinkPattern, "Writer") || strings.Contains(sinkPattern, "print") {
		return "XSS"
	}
	if strings.Contains(sinkPattern, "include") || strings.Contains(sinkPattern, "require") {
		return "File"
	}
	if strings.Contains(sinkPattern, "unserialize") || strings.Contains(sinkPattern, "readObject") || strings.Contains(sinkPattern, "Deserialize") || strings.Contains(sinkPattern, "yaml.load") || strings.Contains(sinkPattern, "pickle.loads") || strings.Contains(sinkPattern, "Marshal.load") {
		return "Deserialization"
	}
	if strings.Contains(sinkPattern, "curl_init") || strings.Contains(sinkPattern, "requests.") || strings.Contains(sinkPattern, "axios") || strings.Contains(sinkPattern, "fetch") || strings.Contains(sinkPattern, "http.Get") || strings.Contains(sinkPattern, "http.NewRequest") || strings.Contains(sinkPattern, "URI.open") || strings.Contains(sinkPattern, "Net::HTTP") {
		return "SSRF"
	}
	return "Injection"
}

// getTaintRemediation provides remediation advice based on sink pattern
func getTaintRemediation(sinkPattern string) string {
	injType := getInjectionType(sinkPattern)
	switch injType {
	case "SQL":
		return "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
	case "Code":
		return "Avoid eval() and similar functionality. Use safer options like JSON.parse() for data parsing."
	case "Command":
		return "Avoid executing system commands with user input. Pass arguments as a structured list and disable shell execution if possible."
	case "XSS":
		return "Contextually encode user input before reflecting it. Use strongly typed DOM manipulation methods like textContent."
	case "File":
		return "Never use user input directly in include/require or file system paths. Use strict allowlists."
	case "Deserialization":
		return "Avoid deserializing untrusted data. Use safer formats like JSON."
	case "SSRF":
		return "Validate URLs against a strict allowlist. Do not permit requests to internal network surfaces."
	default:
		return "Validate and sanitize all user input before using it in sensitive operations."
	}
}

func getInjectionCWE(sinkPattern string) string {
	injType := getInjectionType(sinkPattern)
	switch injType {
	case "SQL":
		return "CWE-89"
	case "Code":
		return "CWE-94"
	case "Command":
		return "CWE-78"
	case "XSS":
		return "CWE-79"
	case "File":
		return "CWE-22"
	case "Deserialization":
		return "CWE-502"
	case "SSRF":
		return "CWE-918"
	default:
		return "CWE-20"
	}
}

func getInjectionOWASP(sinkPattern string) string {
	injType := getInjectionType(sinkPattern)
	switch injType {
	case "SQL", "Code", "Command", "SSRF", "File":
		return "A03:2021"
	case "XSS":
		return "A03:2021" // Included in Injection now
	case "Deserialization":
		return "A08:2021"
	default:
		return "A03:2021" // Default generic Injection
	}
}

// isTestFilePath returns true if the file path looks like a test/mock/fixture file
func isTestFilePath(path string) bool {
	// Normalize to forward slashes so checks work on Windows too
	lowerPath := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	testIndicators := []string{
		"_test.go", "_test.py", "_test.js", "_test.ts", ".test.js", ".test.ts",
		".spec.js", ".spec.ts", "test_", "/test/", "/tests/", "/__tests__/",
		"/mock/", "/mocks/", "/fixture/", "/fixtures/", "/__mocks__/",
		"/testdata/", "/spec/", "/specs/",
	}
	for _, indicator := range testIndicators {
		if strings.Contains(lowerPath, indicator) {
			return true
		}
	}
	return false
}

// ScanTaintFlows runs taint analysis on a directory
func ScanTaintFlows(targetDir string) ([]reporter.Finding, error) {
	var findings []reporter.Finding
	analyzer := NewTaintAnalyzer()

	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip common non-source directories
			baseName := filepath.Base(path)
			if baseName == "node_modules" || baseName == "vendor" || baseName == ".git" || baseName == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip test and mock files to reduce false positives
		if isTestFilePath(path) {
			return nil
		}

		fileFindings, err := analyzer.AnalyzeTaintFlow(path)
		if err != nil {
			utils.LogWarn(fmt.Sprintf("Taint analysis failed for %s: %v", path, err))
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}
