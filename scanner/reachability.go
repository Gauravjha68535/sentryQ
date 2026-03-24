package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"SentryQ/reporter"
	"SentryQ/utils"
)

// ReachabilityAnalyzer builds a basic call graph to determine if vulnerable code is reachable
type ReachabilityAnalyzer struct {
	// callGraph maps function name to the functions it calls
	callGraph map[string][]string
	// funcDefinitions maps function names to file:line
	funcDefinitions map[string]string
	// entryPoints are the app's entry functions (main, init, handlers)
	entryPoints []string
	// fileContentCache avoids redundant os.ReadFile calls per line
	fileContentCache map[string][]string
}

// NewReachabilityAnalyzer creates a new reachability analyzer
func NewReachabilityAnalyzer() *ReachabilityAnalyzer {
	return &ReachabilityAnalyzer{
		callGraph:        make(map[string][]string),
		funcDefinitions:  make(map[string]string),
		entryPoints:      make([]string, 0),
		fileContentCache: make(map[string][]string),
	}
}

// BuildCallGraph scans the target directory and builds a simplified call graph
func (ra *ReachabilityAnalyzer) BuildCallGraph(targetDir string) error {
	// Patterns to detect function definitions across languages
	funcDefPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^(?:func|def|function)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`),             // Go, Python, JS
		regexp.MustCompile(`(?m)(?:public|private|protected)\s+\w+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`), // Java, C#
		regexp.MustCompile(`(?m)(?:fun)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`),                            // Kotlin
	}

	// Patterns to detect function calls
	funcCallPattern := regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)

	// Entry point indicators
	entryPointPatterns := []string{
		"main", "init", "Main", "Init",
		"HandleFunc", "HandleRequest", "ServeHTTP",
		"handle", "handler", "Controller", "Action",
		"onCreate", "onStart", "viewdidload", "componentdidmount",
		"app.get", "app.post", "app.put", "app.delete", "app.use",
		"router.", "mux.", "http.Handle", "route.",
		"@app.route", "@admin_bp.route", "@bp.route", ".route(",
		"endpoint", "service", "api", "rpc",
		"public func", "export func", "export default",
	}

	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "node_modules" || base == "vendor" || base == ".git" || base == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process source code files
		lang := getLanguageFromPath(path)
		if lang == "" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		source := string(content)
		lines := strings.Split(utils.NormalizeNewlines(source), "\n")

		var currentFunc string
		var lastLine string

		for lineNum, line := range lines {
			// Check for function definitions
			for _, defPattern := range funcDefPatterns {
				if m := defPattern.FindStringSubmatch(line); len(m) > 1 {
					currentFunc = m[1]
					ra.funcDefinitions[currentFunc] = fmt.Sprintf("%s:%d", path, lineNum+1)

					// Check if this is an entry point
					for _, ep := range entryPointPatterns {
						if strings.Contains(line, ep) || strings.Contains(lastLine, ep) {
							ra.entryPoints = append(ra.entryPoints, currentFunc)
							break
						}
					}
				}
			}

			// If we're inside a function, track what it calls
			if currentFunc != "" {
				calls := funcCallPattern.FindAllStringSubmatch(line, -1)
				for _, call := range calls {
					if len(call) > 1 && call[1] != currentFunc { // Don't track self-calls
						calledFunc := call[1]
						// Skip common keywords and built-ins
						if !isCommonKeyword(calledFunc) {
							ra.callGraph[currentFunc] = append(ra.callGraph[currentFunc], calledFunc)
						}
					}
				}
			}
			lastLine = line
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error building call graph: %w", err)
	}

	utils.LogInfo(fmt.Sprintf("Call graph built: %d functions, %d entry points", len(ra.funcDefinitions), len(ra.entryPoints)))
	return nil
}

// IsReachable checks if a function is reachable from any entry point
func (ra *ReachabilityAnalyzer) IsReachable(funcName string) bool {
	if len(ra.entryPoints) == 0 {
		// If we can't determine entry points, assume reachable (conservative)
		return true
	}

	for _, ep := range ra.entryPoints {
		if ra.canReach(ep, funcName, make(map[string]bool)) {
			return true
		}
	}
	return false
}

// canReach does a DFS to check if `from` can reach `target`
func (ra *ReachabilityAnalyzer) canReach(from, target string, visited map[string]bool) bool {
	if from == target {
		return true
	}
	if visited[from] {
		return false
	}
	visited[from] = true

	for _, callee := range ra.callGraph[from] {
		if ra.canReach(callee, target, visited) {
			return true
		}
	}
	return false
}

// GetFunctionAtLine returns the function name containing the given line in a file
func (ra *ReachabilityAnalyzer) GetFunctionAtLine(filePath string, lineNum int) string {
	lines, ok := ra.fileContentCache[filePath]
	if !ok {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return ""
		}
		lines = strings.Split(utils.NormalizeNewlines(string(content)), "\n")
		ra.fileContentCache[filePath] = lines
	}
	funcDefPattern := regexp.MustCompile(`(?:func|def|function|fun)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)

	lastFunc := ""
	for i := 0; i < lineNum && i < len(lines); i++ {
		if m := funcDefPattern.FindStringSubmatch(lines[i]); len(m) > 1 {
			lastFunc = m[1]
		}
	}
	return lastFunc
}

// AnnotateFindings adds reachability info to findings
func (ra *ReachabilityAnalyzer) AnnotateFindings(findings []reporter.Finding) []reporter.Finding {
	annotated := make([]reporter.Finding, 0, len(findings))

	for _, f := range findings {
		// Parse line number
		var lineNum int
		fmt.Sscanf(f.LineNumber, "%d", &lineNum)

		funcName := ra.GetFunctionAtLine(f.FilePath, lineNum)
		if funcName != "" && !ra.IsReachable(funcName) {
			// Downgrade unreachable findings
			f.Severity = "info"
			f.Description = fmt.Sprintf("[UNREACHABLE] %s (function '%s' is not called from any entry point)", f.Description, funcName)
			f.Confidence = f.Confidence * 0.3 // Significantly reduce confidence
		}

		annotated = append(annotated, f)
	}

	return annotated
}

// isCommonKeyword returns true for common language keywords that look like function calls
func isCommonKeyword(name string) bool {
	keywords := map[string]bool{
		"if": true, "for": true, "while": true, "switch": true, "case": true,
		"return": true, "break": true, "continue": true, "else": true,
		"try": true, "catch": true, "finally": true, "throw": true,
		"new": true, "delete": true, "typeof": true, "instanceof": true,
		"import": true, "from": true, "as": true, "class": true,
		"true": true, "false": true, "null": true, "nil": true, "None": true,
		"print": true, "println": true, "fmt": true, "log": true,
		"len": true, "cap": true, "make": true, "append": true,
		"range": true, "defer": true, "go": true, "select": true,
		"var": true, "let": true, "const": true, "type": true,
	}
	return keywords[name]
}
