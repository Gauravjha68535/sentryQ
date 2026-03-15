package utils

// LanguageMap maps file extensions to language identifiers
// Supports 50+ file extensions across 30+ programming languages
var LanguageMap = map[string]string{
	// ==================== Web Languages ====================
	".js":     "javascript",
	".jsx":    "javascript",
	".mjs":    "javascript",
	".ts":     "typescript",
	".tsx":    "typescript",
	".html":   "html",
	".htm":    "html",
	".css":    "css",
	".scss":   "sass",
	".sass":   "sass",
	".less":   "less",
	".vue":    "vue",
	".svelte": "svelte",

	// ==================== Backend Languages ====================
	".py":      "python",
	".pyw":     "python",
	".ipynb":   "python",
	".java":    "java",
	".class":   "java",
	".jsp":     "java",
	".php":     "php",
	".php3":    "php",
	".php4":    "php",
	".php5":    "php",
	".phtml":   "php",
	".go":      "go",
	".golang":  "go",
	".rs":      "rust",
	".rb":      "ruby",
	".erb":     "ruby",
	".rake":    "ruby",
	".gemspec": "ruby",

	// ==================== Microsoft Languages ====================
	".cs":        "csharp",
	".cshtml":    "csharp",
	".razor":     "csharp",
	".vb":        "vb",
	".vbnet":     "vb",
	".vbs":       "vbscript",
	".asp":       "asp",
	".aspx":      "csharp",
	".ascx":      "csharp",
	".ashx":      "csharp",
	".asmx":      "csharp",
	".config":    "xml",
	".webconfig": "xml",

	// ==================== C/C++ Languages ====================
	".c":   "c",
	".h":   "c",
	".cpp": "cpp",
	".cc":  "cpp",
	".cxx": "cpp",
	".c++": "cpp",
	".hpp": "cpp",
	".hh":  "cpp",
	".hxx": "cpp",
	".h++": "cpp",

	// ==================== Mobile Languages ====================
	".swift":   "swift",
	".m":       "objective-c",
	".mm":      "objective-cpp",
	".kt":      "kotlin",
	".kts":     "kotlin",
	".dart":    "dart",
	".flutter": "dart",

	// ==================== Scripting Languages ====================
	".sh":   "bash",
	".bash": "bash",
	".zsh":  "bash",
	".fish": "bash",
	".pl":   "perl",
	".pm":   "perl",
	".t":    "perl",
	".pod":  "perl",
	".lua":  "lua",
	".r":    "r",
	".R":    "r",

	// ==================== Configuration Files ====================
	".yaml":         "yaml",
	".yml":          "yaml",
	".json":         "json",
	".xml":          "xml",
	".toml":         "toml",
	".ini":          "ini",
	".cfg":          "ini",
	".conf":         "ini",
	".env":          "env",
	".dockerfile":   "dockerfile",
	".dockerignore": "dockerfile",

	// ==================== Database & Query Languages ====================
	".sql":   "sql",
	".plsql": "plsql",
	".tsql":  "tsql",
	// ==================== Mobile/Platform Specific ====================
	".axml":       "xml",
	".storyboard": "xml",
	".xib":        "xml",
	".gradle":     "groovy",
	".groovy":     "groovy",
	".build":      "swift",

	// ==================== Infrastructure as Code ====================
	".tf":     "terraform",
	".tfvars": "terraform",
	".hcl":    "terraform",
	".pulumi": "typescript",
	".bicep":  "bicep",
	".arm":    "json",

	// ==================== Documentation ====================
	".md":  "markdown",
	".mdx": "markdown",
	".rst": "markdown",
	".txt": "text",

	// ==================== Other Languages ====================
	".scala":  "scala",
	".sc":     "scala",
	".clj":    "clojure",
	".cljs":   "clojure",
	".edn":    "clojure",
	".ex":     "elixir",
	".exs":    "elixir",
	".erl":    "erlang",
	".hs":     "haskell",
	".lhs":    "haskell",
	".ml":     "ocaml",
	".mli":    "ocaml",
	".fs":     "fsharp",
	".fsi":    "fsharp",
	".fsx":    "fsharp",
	".rkt":    "racket",
	".scm":    "scheme",
	".lisp":   "lisp",
	".lsp":    "lisp",
	".jl":     "julia",
	".nb":     "mathematica",
	".d":      "d",
	".nim":    "nim",
	".nimble": "nim",
	".zig":    "zig",
	".v":      "v",
	".hx":     "haxe",
	".cr":     "crystal",
	".sol":    "solidity",
	".move":   "move",
	".apex":   "apex",
	".abap":   "abap",
	".cob":    "cobol",
	".cbl":    "cobol",
	".f":      "fortran",
	".f90":    "fortran",
	".f95":    "fortran",
	".pas":    "delphi",
	".dpr":    "delphi",
	".pro":    "prolog",
	".asm":    "assembly",
	".s":      "assembly",
	".S":      "assembly",
	".vhd":    "vhdl",
	".sv":     "systemverilog",
	".wasm":   "webassembly",
	".wat":    "webassembly",
	".ps1":    "powershell",
	".psm1":   "powershell",

	// ==================== Template Languages ====================
	".ejs":    "javascript",
	".hbs":    "html",
	".pug":    "html",
	".twig":   "php",
	".jinja2": "python",
	".j2":     "python",

	// ==================== GraphQL ====================
	".graphql": "graphql",
	".gql":     "graphql",
}

// GetLanguage returns the language ID for a file extension
func GetLanguage(ext string) string {
	if lang, ok := LanguageMap[ext]; ok {
		return lang
	}
	return "unknown"
}
