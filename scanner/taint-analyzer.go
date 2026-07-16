package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// funcProfile stores per-function taint properties derived from a pre-scan pass.
// Used to enable inter-procedural taint tracking without a full call graph.
type funcProfile struct {
	// ReturnsTainted is true when the function has at least one code path that
	// returns user-controlled data (i.e. it is a "wrapper source").
	// e.g.  def get_name(): return request.args.get('name')
	ReturnsTainted bool
	// SinkInBody is true when the function body directly calls a dangerous sink
	// using one of its parameters. Call sites passing tainted args are flagged.
	// e.g.  def run_query(sql): cursor.execute(sql)
	SinkInBody bool
}

// TaintAnalyzer tracks user input through code to detect injection vulnerabilities
type TaintAnalyzer struct {
	taintSources      []*regexp.Regexp
	taintSinks        map[string][]string         // raw sink patterns (kept for reference)
	compiledSinks     map[string][]*regexp.Regexp // pre-compiled at init; used in AnalyzeTaintFlow
	sanitizers        []*regexp.Regexp
	scopeStartPattern *regexp.Regexp
	// Pre-compiled patterns for taint flow analysis (compiled once at initialization)
	methodChainRe   *regexp.Regexp
	concatRe        *regexp.Regexp
	interpolationRe *regexp.Regexp
	funcCallRe      *regexp.Regexp
	// Pre-compiled patterns for inter-procedural pre-scan
	funcDefRe    *regexp.Regexp
	returnStmtRe *regexp.Regexp
	callReturnRe *regexp.Regexp
}

// NewTaintAnalyzer creates a new taint analyzer
func NewTaintAnalyzer() *TaintAnalyzer {
	ta := &TaintAnalyzer{
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
		// Inter-procedural pre-scan patterns
		// Matches: def foo(, func foo(, function foo(, public void foo(, private String foo(, etc.
		funcDefRe: regexp.MustCompile(`(?i)(?:^|[\s{])(?:async\s+)?(?:def|func|function|sub|procedure)\s+(\w+)\s*\(|(?:public|private|protected|internal|static)\s+(?:async\s+)?(?:void|string|int|bool|object|var|\w+\??)\s+(\w+)\s*\(`),
		// Matches: return expr, yield expr
		returnStmtRe: regexp.MustCompile(`^\s*(?:return|yield)\s+(\w+)`),
		// Matches: result = someFunc(  OR  result := someFunc(  to detect call return value
		callReturnRe: regexp.MustCompile(`(?:var|let|const|async)?\s*\$?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=|:=)\s*(?:await\s+)?([a-zA-Z_][a-zA-Z0-9_]+)\s*\(`),
	}

	// Pre-compile all sink patterns at construction time so AnalyzeTaintFlow
	// does not pay the regexp.Compile cost on every file it processes.
	//
	// IMPORTANT: taintSinks[lang] is rebuilt here to contain ONLY the patterns
	// that compiled successfully, keeping it exactly in sync with compiledSinks[lang].
	// Without this, any invalid regex would shorten compiledSinks without shortening
	// taintSinks, causing sinkPatterns[i] to reference the wrong raw pattern at
	// runtime (wrong injection type, CWE, OWASP, remediation).
	ta.compiledSinks = make(map[string][]*regexp.Regexp, len(ta.taintSinks))
	for lang, patterns := range ta.taintSinks {
		compiled := make([]*regexp.Regexp, 0, len(patterns))
		valid := make([]string, 0, len(patterns))
		for _, p := range patterns {
			if re, err := regexp.Compile(p); err == nil {
				compiled = append(compiled, re)
				valid = append(valid, p)
			} else {
				utils.LogWarn(fmt.Sprintf("taint-analyzer: invalid sink regex for %s: %v", lang, err))
			}
		}
		ta.compiledSinks[lang] = compiled
		ta.taintSinks[lang] = valid // keep raw patterns in sync with compiled slice
	}

	return ta
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

// preScanFunctions performs a first pass over the file to build a map of
// user-defined function names to their taint properties. This enables the main
// analysis to follow taint across function call boundaries within the same file.
//
// Two profiles are built:
//   - ReturnsTainted: the function has a return/yield that hands back a tainted variable.
//     e.g. "def get_name(): return request.args.get('name')"
//     → calling get_name() produces tainted data at the call site.
//   - SinkInBody: the function body calls a dangerous sink using a local variable
//     that is likely to be a parameter (any non-source local used in a sink).
//     e.g. "def run_query(sql): cursor.execute(sql)"
//     → calling run_query(user_input) should be flagged at the call site.
func (ta *TaintAnalyzer) preScanFunctions(lines []string, lang string) map[string]funcProfile {
	profiles := make(map[string]funcProfile)
	compiledSinks := ta.compiledSinks[lang]

	var currentFunc string
	// Per-function bookkeeping (reset on each new function definition).
	localTaint := make(map[string]bool)  // varName → tainted within this func
	localVars  := make(map[string]bool)  // all assigned vars (potential params / locals)

	for _, line := range lines {
		// ── Detect function definition ────────────────────────────────────
		if m := ta.funcDefRe.FindStringSubmatch(line); m != nil {
			// Extract function name (first non-empty capture group)
			fname := ""
			for _, g := range m[1:] {
				if g != "" {
					fname = g
					break
				}
			}
			if fname != "" {
				currentFunc = fname
				localTaint = make(map[string]bool)
				localVars  = make(map[string]bool)
				continue
			}
		}
		if currentFunc == "" {
			continue
		}

		trimmed := strings.TrimSpace(line)

		// ── Track taint sources inside this function ──────────────────────
		for _, srcRe := range ta.taintSources {
			if srcRe.MatchString(line) {
				if v := extractVariableName(line); v != "" {
					localTaint[v] = true
					localVars[v]  = true
				}
			}
		}

		// ── Track simple aliases (a = b) ──────────────────────────────────
		aliasVar, srcVar := extractAliasAssignment(line)
		if aliasVar != "" {
			localVars[aliasVar] = true
			if localTaint[srcVar] {
				localTaint[aliasVar] = true
			}
		}

		// ── Track all local assignments (to catch parameter-like vars) ────
		if v := extractVariableName(line); v != "" {
			localVars[v] = true
		}

		// ── Check return/yield for tainted value ──────────────────────────
		if strings.Contains(trimmed, "return ") || strings.Contains(trimmed, "yield ") {
			marked := false
			// Case A: return taintedVar  (variable was assigned from source earlier)
			if m := ta.returnStmtRe.FindStringSubmatch(trimmed); m != nil {
				if localTaint[m[1]] {
					p := profiles[currentFunc]
					p.ReturnsTainted = true
					profiles[currentFunc] = p
					marked = true
				}
			}
			// Case B: return request.args.get('x')  (source expression returned directly,
			// no intermediate variable assignment — the most common wrapper pattern)
			if !marked {
				for _, srcRe := range ta.taintSources {
					if srcRe.MatchString(line) {
						p := profiles[currentFunc]
						p.ReturnsTainted = true
						profiles[currentFunc] = p
						break
					}
				}
			}
		}

		// ── Check if a sink is called with a local (likely-param) var ─────
		if compiledSinks != nil {
			for _, sinkRe := range compiledSinks {
				if sinkRe.MatchString(line) && !isSafeSinkUsage(line, "") {
					for v := range localVars {
						if !localTaint[v] && containsVariable(line, v) {
							// v is used in a sink but NOT from a known taint source
							// — it is probably a parameter received from the caller.
							p := profiles[currentFunc]
							p.SinkInBody = true
							profiles[currentFunc] = p
						}
					}
				}
			}
		}
	}

	return profiles
}

// CrossFileIndex holds cross-file taint information derived from scanning
// all files in the project before analysing individual files.
// Key = module/function name → ReturnsTainted bool.
type CrossFileIndex struct {
	// TaintedFunctions maps fully-qualified or short function names that are
	// known to return user-controlled data from another file in the project.
	// Example: "utils.get_user_input" → true
	TaintedFunctions map[string]bool
	// TaintedModules maps import aliases whose module is a known user-input source.
	// Example: "flask_request" → true (imported as `from flask import request as flask_request`)
	TaintedModules map[string]bool
}

// importPatterns matches import statements in Python, JS/TS, Go, Ruby
var importPatterns = []*regexp.Regexp{
	// Python: from module import func  OR  import module.func
	regexp.MustCompile(`(?m)^from\s+(\S+)\s+import\s+(.+)$`),
	regexp.MustCompile(`(?m)^import\s+(\S+)(?:\s+as\s+(\w+))?`),
	// JS/TS: import { func } from 'module'  OR  const func = require('module')
	regexp.MustCompile(`(?m)import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]`),
	regexp.MustCompile(`(?m)(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)`),
	// Go: import "package" or import alias "package"
	regexp.MustCompile(`(?m)(?:(\w+)\s+)?"([^"]+)"`),
	// Ruby: require 'module' or require_relative 'path'
	regexp.MustCompile(`(?m)require(?:_relative)?\s+['"]([^'"]+)['"]`),
}

// BuildCrossFileIndex scans all source files in targetDir to build a project-wide
// map of functions that return tainted data. This enables cross-file taint tracking:
// if utils.py defines get_user_id() that returns request.args, app.py scanning
// will recognise get_user_id() as a taint source without needing to open utils.py.
func (ta *TaintAnalyzer) BuildCrossFileIndex(targetDir string) *CrossFileIndex {
	idx := &CrossFileIndex{
		TaintedFunctions: make(map[string]bool),
		TaintedModules:   make(map[string]bool),
	}

	err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				name := d.Name()
				if name == "node_modules" || name == "vendor" || name == ".git" || name == ".claude" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		lang := getLanguageFromPath(path)
		if lang == "" || ta.compiledSinks[lang] == nil {
			return nil
		}

		// Skip files larger than 512 KB to avoid OOM on generated files
		if info, err := d.Info(); err == nil && info.Size() > 512*1024 {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(utils.NormalizeNewlines(string(content)), "\n")
		profiles := ta.preScanFunctions(lines, lang)

		// Derive the module name from the file path for cross-file lookups
		// e.g.  utils/helpers.py  →  "utils.helpers" or just "helpers"
		base := filepath.Base(path)
		modName := strings.TrimSuffix(base, filepath.Ext(base))

		for funcName, profile := range profiles {
			if profile.ReturnsTainted {
				// Register as "module.function" and bare "function"
				idx.TaintedFunctions[modName+"."+funcName] = true
				idx.TaintedFunctions[funcName] = true
			}
		}
		return nil
	})

	if err != nil {
		utils.LogWarn(fmt.Sprintf("cross-file index: walk error: %v", err))
	}

	return idx
}

// AnalyzeTaintFlow scans a file for taint flow vulnerabilities
func (ta *TaintAnalyzer) AnalyzeTaintFlow(filePath string) ([]reporter.Finding, error) {
	return ta.analyzeTaintFlowInternal(filePath, nil)
}

// AnalyzeTaintFlowWithIndex scans a file using a pre-built cross-file index so that
// functions defined in other files that return user-controlled data are recognised
// as taint sources in this file.
func (ta *TaintAnalyzer) AnalyzeTaintFlowWithIndex(filePath string, idx *CrossFileIndex) ([]reporter.Finding, error) {
	return ta.analyzeTaintFlowInternal(filePath, idx)
}

func (ta *TaintAnalyzer) analyzeTaintFlowInternal(filePath string, crossFileIdx *CrossFileIndex) ([]reporter.Finding, error) {
	lang := getLanguageFromPath(filePath)
	if lang == "" || ta.compiledSinks[lang] == nil {
		return nil, nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(utils.NormalizeNewlines(string(content)), "\n")

	// ── Phase 3: Inter-procedural pre-scan ───────────────────────────────────
	// Build per-function taint profiles before the main linear pass.
	// This lets the main pass recognise wrapper sources (functions that return
	// user input) and sink-body functions (functions whose body calls a sink).
	funcProfiles := ta.preScanFunctions(lines, lang)

	// ── Cross-file: merge external taint profiles into local funcProfiles ────
	// When a cross-file index is provided, any function imported from another
	// file that was marked ReturnsTainted is promoted to a local taint source.
	if crossFileIdx != nil {
		for extFunc := range crossFileIdx.TaintedFunctions {
			if _, alreadyLocal := funcProfiles[extFunc]; !alreadyLocal {
				funcProfiles[extFunc] = funcProfile{ReturnsTainted: true}
			}
		}
	}

	var findings []reporter.Finding
	srNo := 1

	// Track taint propagation through the file
	taintedVars := make(map[string]taintInfo)
	sanitizedVars := make(map[string]bool)

	// De-duplication: track reported source-sink pairs to avoid duplicates
	reportedPairs := make(map[string]bool)

	// Use the sink regexes pre-compiled in NewTaintAnalyzer (zero allocation per file).
	compiledSinks := ta.compiledSinks[lang]
	// Raw sink patterns are still needed for display strings (getInjectionType, etc.).
	sinkPatterns := ta.taintSinks[lang]

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

		// 2e. Inter-procedural: wrapper-source call return value taint
		// If result = someFunc(...) and someFunc was found to return tainted data
		// in the pre-scan, mark result as tainted at this call site.
		// This catches:  name = get_user_name()  →  cursor.execute(f"... {name}")
		if len(funcProfiles) > 0 {
			if m := ta.callReturnRe.FindStringSubmatch(trimmedLine); len(m) > 2 {
				destVar := m[1]
				calledFunc := m[2]
				if profile, ok := funcProfiles[calledFunc]; ok && profile.ReturnsTainted {
					if _, alreadyTainted := taintedVars[destVar]; !alreadyTainted {
						taintedVars[destVar] = taintInfo{
							SourceLine: currentLine,
							Hops:       1,
							SourceVar:  calledFunc + "()",
							Path: []string{
								fmt.Sprintf("Line %d: Return value of wrapper-source function '%s()' is tainted", currentLine, calledFunc),
							},
						}
						sanitizedVars[destVar] = false
					}
				}
			}
		}

		// 2f. Inter-procedural: sink-body function called with tainted argument
		// If run_query(user_input) and run_query has a sink in its body (pre-scan),
		// report at the call site rather than waiting for the sink line.
		// This catches:  run_query(tainted_var)  when run_query does cursor.execute(sql)
		if len(funcProfiles) > 0 {
			if callMatch := ta.funcCallRe.FindStringSubmatch(trimmedLine); len(callMatch) > 1 {
				calledFunc := callMatch[1]
				if profile, ok := funcProfiles[calledFunc]; ok && profile.SinkInBody {
					// Check if any tainted variable appears in the argument list
					for varName, info := range taintedVars {
						if !sanitizedVars[varName] && containsVariable(trimmedLine, varName) {
							pairKey := fmt.Sprintf("sink-body:%s→%d→%s", info.SourceVar, info.SourceLine, calledFunc)
							if !reportedPairs[pairKey] {
								reportedPairs[pairKey] = true
								confidence := calculateTaintConfidence(currentLine, info) - 0.05 // slight discount for indirect
								if confidence >= 0.30 {
									findings = append(findings, reporter.Finding{
										SrNo:        srNo,
										IssueName:   fmt.Sprintf("Taint Flow: Injection via %s()", calledFunc),
										FilePath:    filePath,
										Description: fmt.Sprintf("Tainted variable '%s' (from line %d) passed to '%s()' which calls a dangerous sink internally", info.SourceVar, info.SourceLine, calledFunc),
										ExploitPath: append(info.Path, fmt.Sprintf("Line %d: Passed as argument to '%s()' (sink in body)", currentLine, calledFunc)),
										Severity:    "high",
										LineNumber:  fmt.Sprintf("%d", currentLine),
										AiValidated: "No",
										Remediation: "Sanitize or validate the argument before passing it to this function, or refactor the function to use parameterized operations.",
										RuleID:      fmt.Sprintf("dataflow-interprocedural-%s", strings.ToLower(calledFunc)),
										Source:      "taint-analyzer",
										CWE:         "CWE-20",
										OWASP:       "A03:2021",
										Confidence:  confidence,
									})
									srNo++
								}
							}
						}
					}
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


