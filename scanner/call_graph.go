package scanner

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CallGraph represents the project-wide interprocedural call graph.
// Each key is a function name; the value is the set of functions it calls.
type CallGraph struct {
	// Callers maps callee → set of callers (reverse graph for taint propagation)
	Callers map[string][]string
	// Callees maps caller → set of callees (forward graph)
	Callees map[string][]string
	// FuncFiles maps function name → file it was defined in
	FuncFiles map[string]string
}

// NewCallGraph allocates an empty call graph.
func NewCallGraph() *CallGraph {
	return &CallGraph{
		Callers:   make(map[string][]string),
		Callees:   make(map[string][]string),
		FuncFiles: make(map[string]string),
	}
}

// interprocedural patterns
var (
	cgFuncDefRe = regexp.MustCompile(
		`(?i)(?:^|[\s{])(?:async\s+)?(?:def|func|function|sub)\s+(\w+)\s*\(` +
		`|(?:public|private|protected|internal|static)\s+(?:async\s+)?(?:void|string|int|bool|object|var|\w+\??)\s+(\w+)\s*\(`,
	)
	cgCallRe = regexp.MustCompile(`\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
)

// BuildCallGraph walks the directory and constructs a project-wide call graph
// by parsing function definitions and call sites.
func BuildCallGraph(rootDir string) *CallGraph {
	cg := NewCallGraph()

	_ = filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				if n := d.Name(); n == "node_modules" || n == "vendor" || n == ".git" || n == ".claude" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !isSourceExt(ext) {
			return nil
		}
		parseFileIntoCallGraph(path, cg)
		return nil
	})

	return cg
}

func parseFileIntoCallGraph(filePath string, cg *CallGraph) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	var currentFunc string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Detect function definition
		if m := cgFuncDefRe.FindStringSubmatch(line); m != nil {
			name := m[1]
			if name == "" {
				name = m[2]
			}
			if name != "" {
				currentFunc = name
				cg.FuncFiles[name] = filePath
			}
		}

		if currentFunc == "" {
			continue
		}

		// Detect function calls within the current function body
		matches := cgCallRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			callee := m[1]
			if callee == "" || callee == currentFunc || isCGKeyword(callee) {
				continue
			}
			cg.Callees[currentFunc] = appendUnique(cg.Callees[currentFunc], callee)
			cg.Callers[callee] = appendUnique(cg.Callers[callee], currentFunc)
		}
	}
}

// PropagateCallGraphTaint extends the CrossFileIndex by following call chains.
// If function A calls B, and B is already tainted, A is also marked tainted.
// Runs BFS from all initially tainted functions.
func PropagateCallGraphTaint(cg *CallGraph, idx *CrossFileIndex) {
	// Seed: all already-known tainted functions
	queue := make([]string, 0, len(idx.TaintedFunctions))
	for fn := range idx.TaintedFunctions {
		queue = append(queue, fn)
	}

	visited := make(map[string]bool)

	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]

		if visited[fn] {
			continue
		}
		visited[fn] = true

		// Mark it tainted
		idx.TaintedFunctions[fn] = true

		// All callers of fn also become tainted (they receive/use tainted return values)
		for _, caller := range cg.Callers[fn] {
			if !visited[caller] {
				queue = append(queue, caller)
			}
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

var commonKeywordsForCG = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "case": true,
	"return": true, "print": true, "len": true, "make": true, "new": true,
	"append": true, "delete": true, "panic": true, "recover": true,
	"fmt": true, "log": true, "err": true, "error": true, "string": true,
	"int": true, "bool": true, "float": true, "var": true, "type": true,
	"import": true, "package": true, "class": true, "struct": true,
}

func isCGKeyword(s string) bool {
	return commonKeywordsForCG[strings.ToLower(s)]
}

func isSourceExt(ext string) bool {
	switch ext {
	case ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
		".cs", ".cpp", ".c", ".rs", ".swift", ".kt", ".scala", ".groovy",
		".ex", ".exs", ".lua", ".pl", ".r", ".dart", ".nim", ".zig":
		return true
	}
	return false
}

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
