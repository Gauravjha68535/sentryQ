# Stop Drowning in False Positives: How We Built a Local-AI Orchestrated Security Scanner

**TL;DR:** SentryQ is an open-source security platform written in Go that fuses 12,400+ static rules across 67+ languages, Tree-Sitter AST analysis, inter-procedural taint-flow tracking, Shannon-entropy secret detection, SCA/OSV dependency auditing, Dockerfile & Kubernetes linting, and MITRE ATT&CK enrichment — then validates every finding through a local Chain-of-Thought AI Judge running on Ollama. Zero cloud dependencies. Your code never leaves `localhost`.

---

## 1. The Problem — Why Traditional SAST Fails

If you've ever run a SAST tool on a production codebase, you know the drill:

1. You trigger a scan.
2. You grab a coffee.
3. You come back to 500 "CRITICAL" alerts.
4. You spend three days triaging them.
5. You discover 490 were false positives.

This is Alert Fatigue — and it's destroying DevSecOps adoption.

### Why does this happen?

Traditional scanners rely on regex pattern matching. If a rule says *"Flag any string that looks like a JWT token,"* it will happily flag:

- Unit test mock tokens
- Documentation examples
- Comment blocks explaining JWT flow
- Environment variable *references* (not values)
- Base64-encoded config that looks high-entropy

The scanner has zero understanding of context. It can't tell the difference between `SECRET_KEY = "hunter2"` in production code and `SECRET_KEY = process.env.SECRET_KEY` which is perfectly safe.

### The numbers tell the story

Traditional SAST tools average a **60–80% false positive rate**, requiring 3–5 days of manual triage per scan. SentryQ targets **8–15% false positives** with 30–60 minutes of triage, using AST + Taint + AI context awareness across 67+ languages — all with zero cloud dependency.

### The cloud privacy problem

Some teams try to fix Alert Fatigue by sending code to cloud-hosted LLMs. But most enterprise compliance frameworks — SOC 2, HIPAA, PCI DSS, ISO 27001 — strictly forbid sending source code to third-party AI providers.

We needed the speed of Go, the strictness of static rules, and the reasoning of an AI — all running entirely on localhost.

---

## 2. The Solution — SentryQ's Multi-Tier Architecture

SentryQ is not a single scanner. It's a pipeline of seven independent analysis engines whose results converge through an AI-powered validation and deduplication layer.

```
Source Code
    │
    ├──► Pattern Engine (12,400+ regex rules, 67 languages)
    ├──► AST Analyzer (Tree-Sitter: Python, JS, Java, Kotlin)
    ├──► Taint-Flow Tracker (source → sink dataflow, 11 languages)
    ├──► Secret Detector (regex + Shannon entropy + base64/hex decode)
    ├──► Dependency Scanner (OSV API + osv-scanner CLI, 9 ecosystems)
    ├──► Container Scanner (Dockerfile lint + K8s manifest audit + Trivy)
    │
    ▼
Aggregated Raw Findings
    │
    ├──► False Positive Suppressor (code-context pattern matching)
    ├──► Reachability Analyzer (call-graph DFS from entry points)
    ├──► MITRE ATT&CK Enrichment (local technique mapping)
    │
    ▼
AI Validation Layer
    │
    ├──► Chain-of-Thought Validator (per-finding taint analysis)
    ├──► AI Discovery Engine (sliding-window vulnerability hunting)
    ├──► Judge Engine (multi-report deduplication & consensus)
    ├──► Confidence Calibrator (historical accuracy weighting)
    ├──► ML FP Reducer (similarity-based historical filtering)
    │
    ▼
Final Report
    ├──► React Dashboard (Dark/Light mode, WebSocket real-time)
    ├──► HTML Report (standalone, embeddable)
    ├──► SARIF (GitHub Security Tab, GitLab, Azure DevOps)
    ├──► CSV / PDF
    └──► SQLite Database (scan history, triage status)
```

Every engine runs independently. The AI layer is entirely optional — SentryQ produces useful results with pure static analysis alone. When AI is enabled, it acts as a filter, not a crutch.

---

## 3. Engine #1 — Pattern Matching (12,400+ Rules)

The pattern engine is the workhorse. It ships with 67 YAML rule files covering languages from Assembly to Zig, plus framework-specific rulesets.

**Supported languages (67+):** Python, JavaScript, TypeScript, Go, Java, Kotlin, C, C++, C#, Rust, Ruby, PHP, Swift, Dart, Elixir, Erlang, Haskell, Scala, Clojure, Lua, Perl, R, Julia, MATLAB, Nim, OCaml, F#, Crystal, Groovy, COBOL, VHDL, Zig, Move, Cairo, Vyper, Solidity, Objective-C, Bash, PowerShell, SQL, HTML, GraphQL, gRPC, Protobuf, and more.

**Infrastructure coverage:** Terraform, Kubernetes, Helm, Docker, Ansible, Chef, Puppet, CloudFormation, Bicep, Serverless, Nginx, Apache, OpenAPI, Azure, GCP — plus specialized rulesets for insecure randomness, race conditions, and supply chain attacks.

### How rules work

Each rule is a YAML definition with regex patterns, severity, CWE/OWASP mappings, and remediation guidance:

```yaml
# rules/javascript.yaml
- id: js-eval-injection
  languages: [javascript, typescript]
  patterns:
    - regex: '\beval\s*\('
  severity: high
  description: "Use of eval() can execute arbitrary code"
  remediation: "Use JSON.parse() for data parsing or safer alternatives"
  cwe: "CWE-94"
  owasp: "A03:2021"
```

### Writing custom rules

Drop any `.yaml` file into the `rules/` directory and SentryQ automatically loads it:

```yaml
# rules/my-company-rules.yaml
- id: acme-hardcoded-jwt
  languages: [javascript, typescript, python, go]
  patterns:
    - regex: '(?i)(jwt_secret|jwt_key|secret_key)\s*=\s*["\'][a-zA-Z0-9_\-\.]{10,}["\']'
  severity: critical
  description: "Detected a hardcoded JWT secret"
  remediation: "Use environment variables (e.g., process.env.JWT_SECRET)"
  cwe: "CWE-798"
  owasp: "A07:2021"
```

### Language-aware rule loading

SentryQ doesn't load all 12,400+ rules for every scan. It first walks the target directory to detect which languages are present, then loads only the relevant rule files — dramatically reducing memory usage and startup time:

```go
// config/rule_loader.go
rules, err := config.LoadRulesForLanguages(rulesDir, detectedLangs)
```

---

## 4. Engine #2 — Tree-Sitter AST Analysis

Pattern matching catches syntactic patterns. AST analysis catches semantic vulnerabilities — dangerous function calls, insecure assignments, and structural code flaws that regex can't express.

SentryQ uses the Tree-Sitter parsing library to build full Abstract Syntax Trees for Python, JavaScript/TypeScript, Java, and Kotlin.

**What the AST engine catches:**

*Python:* `eval()` / `exec()` / `compile()` arbitrary code execution (CWE-94), SQL injection via string formatting in `cursor.execute()` (CWE-89), command injection via `os.system()` with user input (CWE-78), SSTI via `render_template_string()`, hardcoded secrets with entropy analysis, and PII logging.

*JavaScript/TypeScript:* `eval()` / `Function()` constructor (CWE-94), XSS via `innerHTML` assignment (CWE-79), hardcoded secrets with high-entropy detection.

*Java:* SQL injection via `Statement.executeQuery()` with string concatenation, command injection via `Runtime.getRuntime().exec()` (CWE-78), insecure deserialization via `ObjectInputStream.readObject()` (CWE-502), XSS via `getWriter().print(getParameter())`, weak cipher usage (ECB mode, DES) (CWE-327).

*Kotlin/Android:* Insecure WebView with `javaScriptEnabled = true`, SQL injection via `rawQuery()` with string interpolation, sensitive data in `Log.*` statements, implicit Intents interceptable by malicious apps, world-readable `SharedPreferences`.

### Reachability cache

The AST engine also builds a global index of every identifier and string literal in the codebase. This cache powers the SCA reachability analysis that determines whether a vulnerable dependency is actually *used* in your code:

```go
// scanner/ast-analyzer.go
func (aa *ASTAnalyzer) IsFunctionReachable(targetDir, functionOrLibName string) bool {
    aa.BuildReachabilityCache(targetDir)
    return aa.reachabilityCache[strings.ToLower(functionOrLibName)]
}
```

---

## 5. Engine #3 — Taint-Flow Dataflow Tracking

This is where SentryQ differentiates itself from naive scanners. The taint analyzer performs inter-procedural dataflow analysis — tracking user-controlled input from sources (where data enters) through propagation (aliases, concatenation, method chains, string interpolation) to sinks (dangerous functions).

### How taint tracking works

**Step 1 — Identify Sources (user input entry points):**

The engine recognizes taint sources across 11 languages:

- Python: `request.args`, `request.form`, `input()`, `sys.argv`
- JavaScript: `req.params`, `req.query`, `document.cookie`, `window.location`
- PHP: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`
- Java: `request.getParameter()`, `request.getHeader()`, `Scanner(System.in)`
- Go: `r.URL.Query()`, `r.FormValue()`, `os.Args`, `chi.URLParam()`
- Ruby: `params[]`, `request.env`, `ENV[]`
- And more for C#, Swift, Dart...

**Step 2 — Track Propagation across four vectors:**

```
Direct alias:         userInput = req.query.name
Method chain:         cleaned = userInput.trim()
String concatenation: query = "SELECT * FROM " + userInput
String interpolation: query = f"SELECT * FROM {userInput}"
```

Each propagation hop is tracked with full path metadata, up to a configurable maximum of 10 hops (preventing infinite loops from circular aliases like `a=b; b=a`).

**Step 3 — Check Sinks (dangerous operations):**

The engine maintains sink definitions for each language — SQL execution, shell commands, eval, innerHTML, deserialize, SSRF-triggering HTTP calls, etc.

**Step 4 — Apply Sanitizer Awareness:**

Before flagging a taint flow, the engine checks for sanitizers: escaping functions (`escape()`, `htmlspecialchars()`, `encodeURIComponent()`), parameterized queries (`?` placeholders, `$1`, `bindParam()`), type casting (`parseInt()`, `Number()`, `strconv.Atoi()`), ORM methods (`.where(?)`, `.filter()`), template auto-escaping (`html/template`, `markupsafe.escape()`), and validation guards.

**Step 5 — Graduated Confidence Scoring:**

- Source-to-sink distance > 100 lines: −15% confidence
- More than 3 alias hops: −10% confidence
- Guard clause detected between source and sink: confidence drops to 25% (effectively suppressed)

### Example: A real taint flow finding

```
Taint Flow: SQL Injection
File: app/routes/users.py
Line: 47
Severity: critical
Confidence: 0.90

User input 'username' (tainted on line 12, 2 hops) flows to SQL
on line 47 without sanitization.

Exploit Path:
  Line 12: Source 'username' initialized (request.form['username'])
  Line 23: Propagated to 'clean_name' (method chain — .strip())
  Line 47: Reaches sink 'cursor.execute()'

Remediation: Use parameterized queries or prepared statements.
             Never concatenate user input into SQL queries.
```

---

## 6. Engine #4 — Entropy-Based Secret Detection

Pattern matching alone catches known secret formats (AWS keys start with `AKIA`, GitHub tokens with `ghp_`). But what about custom secrets — internal API keys, database passwords, or JWT signing secrets that don't follow any known format?

SentryQ's secret detector combines 14+ regex patterns with Shannon entropy analysis to catch both known and unknown secrets.

**Known patterns detected:**

- **AWS Access Key** (`AKIA[0-9A-Z]{16}`) — e.g., `AKIAIOSFODNN7EXAMPLE`
- **GitHub PAT** (`ghp_[a-zA-Z0-9]{36}`)
- **Stripe Key** (`sk_live_[a-zA-Z0-9]{24,}`)
- **Private Keys** (`-----BEGIN.*PRIVATE KEY-----`) — RSA/EC/OPENSSH
- **JWT Token** — three-segment Base64 (`eyJ...eyJ...`)
- **Google API Key** (`AIza[0-9A-Za-z_-]{35}`)
- **Slack Token** (`xox[baprs]-...`)
- **Generic hardcoded password** (`password\s*=\s*"..."`)

### Entropy analysis

For strings that don't match known patterns, SentryQ calculates Shannon entropy — a measure of randomness. Real secrets tend to have entropy > 4.5 bits/character, while English text averages ~3.5:

```go
// scanner/secret_detector.go
func calculateEntropy(s string) float64 {
    freq := make(map[rune]int)
    for _, c := range s {
        freq[c]++
    }
    entropy := 0.0
    length := float64(len(s))
    for _, count := range freq {
        p := float64(count) / length
        entropy -= p * math.Log2(p)
    }
    return entropy
}
```

### Base64/Hex decoding

SentryQ also attempts to decode Base64 and hex-encoded strings before analysis. This catches secrets that have been obfuscated through encoding:

```go
// Try base64 decode, then check entropy of decoded content
if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
    if hasHighEntropy(string(decoded)) {
        // Flag as encoded secret
    }
}
```

### Smart exclusions

The detector automatically skips files larger than 2 MB (avoids RAM spikes on minified bundles), test files (`_test.go`, `.spec.js`, `__tests__/`), binary files, and common non-source directories (`node_modules`, `vendor`, `.git`, `__pycache__`).

---

## 7. Engine #5 — Supply-Chain & Dependency Auditing

SentryQ scans your dependency manifests against the OSV (Open Source Vulnerabilities) database — Google's comprehensive vulnerability database covering npm, PyPI, Go, Maven, RubyGems, Packagist, and more.

### Two-tier approach

**Tier 1 — osv-scanner CLI (preferred):** If Google's official `osv-scanner` binary is in your PATH, SentryQ delegates to it for the most accurate results with full lockfile support.

**Tier 2 — Built-in parser + OSV API (fallback):** If `osv-scanner` isn't installed, SentryQ's built-in parsers extract dependencies from all major manifest formats:

- `package.json` (npm) — JSON dependencies + devDependencies
- `yarn.lock` (npm) — line-by-line v1 parser
- `pnpm-lock.yaml` (npm) — regex-based extraction
- `requirements.txt` (PyPI) — `==`, `>=`, `<=` version specifiers
- `go.mod` (Go) — `require` block parser
- `pom.xml` (Maven) — XML regex extraction
- `build.gradle` (Maven) — `implementation`/`api` declaration parser
- `composer.json` (Packagist) — JSON parser
- `Gemfile.lock` (RubyGems) — Specs section parser

Each dependency is then queried against the OSV API with exponential backoff (1s → 2s → 4s + jitter) for rate-limit resilience.

### Reachability-aware SCA

Here's what makes SentryQ's SCA different: after identifying a vulnerable dependency, it checks whether your code actually uses that dependency by querying the AST reachability cache:

```go
isReachable := analyzer.IsFunctionReachable(targetDir, dep.Name)
if !isReachable {
    issueName = "[UNREACHABLE] " + issueName
    severity = "low"
    description += "\nREACHABILITY: The AST Analyzer could not find any active
    invocations of this library. It may be an unused transitive dependency."
}
```

An unreachable CVE in an unused transitive dependency is not the same risk as an actively-exploited library in your hot path. SentryQ makes this distinction automatically.

---

## 8. Engine #6 — Container & Kubernetes Security

### Dockerfile linting

SentryQ parses `Dockerfile` and `*.dockerfile` files and checks for:

- **`:latest` tag** (Medium) — unpredictable builds
- **`USER root` / `USER 0`** (High) — running as root violates least privilege
- **Missing `USER` directive** (High) — container defaults to root
- **Missing `HEALTHCHECK`** (Low) — orchestrator can't monitor health
- **Secrets in `ENV`/`ARG`** (Critical) — secrets baked into image layers
- **Sensitive port exposure (22, 3389, 23)** (High) — SSH/RDP/Telnet in containers

### Kubernetes manifest auditing

For YAML files containing `apiVersion:` and `kind:`, SentryQ checks for `privileged: true` (container with full host capabilities — Critical) and `allowPrivilegeEscalation: true` (container can gain more privileges — High).

### Trivy integration

When Trivy is installed, SentryQ automatically runs `trivy image` against base images extracted from Dockerfiles, with a 2-minute timeout per image to prevent hanging on unreachable registries.

---

## 9. The AI Layer — Chain-of-Thought Validation

This is the core innovation. Every finding from the static engines passes through an AI validator that acts as a Senior Security Code Reviewer.

### How validation works

For each finding, SentryQ sends the AI:

1. The vulnerability details (issue name, severity, CWE, description)
2. The full file content (for files ≤ 500 lines) or ±150 lines of context
3. A test-file indicator (if the file matches test patterns)
4. Cross-file context (related imports, callers)

The AI is prompted to perform structured analysis:

```
VALIDATION STEPS:
1. TAINT ANALYSIS: Map from Source to Sink. Is there an unvalidated path?
2. CONFIGURATION & SECRETS: Hardcoded secrets DON'T require user input.
3. CONFIGURATION FILE RULE: .env, .yaml, .properties files with secrets
   are ALWAYS true positives.
4. FILTER ANALYSIS: Is sanitization present? Could it be insufficient?
5. ENVIRONMENT CHECK: Dev-only tool or real production vulnerability?
6. IMPACT ESTIMATION: What is the worst-case scenario?
```

The AI returns a structured JSON verdict:

```json
{
  "is_true_positive": true,
  "confidence": 0.92,
  "explanation": "User input from request.form flows directly to
                  cursor.execute() without parameterization.",
  "suggested_fix": "Use parameterized queries with ? placeholders.",
  "fixed_code_snippet": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
  "exploit_poc": "curl -X POST /login -d 'username=admin%27%20OR%201=1--'",
  "severity_adjustment": "critical"
}
```

### AI Discovery — Finding what rules miss

Beyond validation, SentryQ has a separate AI Discovery Engine that reads source files through a sliding window (2000 lines per chunk, 50-line overlap) and asks the AI to find vulnerabilities that no static rule would catch:

- Business logic flaws
- IDOR (Insecure Direct Object Reference)
- Race conditions
- Prototype pollution
- SSRF via internal network access
- Missing authorization checks

The discovery engine includes language-specific prompting — Go-specific checks for unsafe pointer usage and concurrent map access, Python-specific checks for pickle deserialization, Java-specific checks for XXE and Log4Shell patterns.

### Agentic search loop

When the AI identifies a vulnerability but needs more context, it can request related files. SentryQ implements a 2-iteration agentic loop:

1. AI analyzes file A, returns `"needs_context": ["utils/auth.go"]`
2. SentryQ fetches `utils/auth.go` and re-prompts with the additional context
3. AI provides final analysis with cross-file understanding

Path traversal protection ensures the AI can only request files within the scan directory.

---

## 10. The Judge Engine — Multi-Report Consensus

When running in Ensemble Mode, SentryQ produces two independent reports:

- **Report A:** Static analysis findings (pattern + AST + taint + secrets)
- **Report B:** AI discovery findings

The Judge Engine acts as a Supreme Security Auditor that merges these reports using five rules:

1. Findings on the same file ± 5 lines with the same vulnerability type → Deduplicate (keep the richer description)
2. Test files, comments, dead code → Drop as false positives
3. Safe patterns (parameterized queries, `textContent`, secure RNGs) → Drop
4. Unique to one scanner and valid → Keep
5. Combined evidence suggests severity change → Adjust

The Judge processes findings in batches of 5 to prevent LLM timeouts, with a 15-minute timeout per batch.

---

## 11. False Positive Suppression — The 5-Layer Defense

SentryQ has five independent layers to eliminate false positives:

**Layer 1: Static FP Suppressor** — Code-context pattern matching that recognizes safe patterns. Examples: weak random suppressed when `crypto.randomBytes` or `secrets.token_hex` is used; SQL injection suppressed when parameterized queries (`?`, `$1`, `.prepare()`) are present; hardcoded secret suppressed when the value comes from `process.env.*` or `os.getenv()`.

**Layer 2: Taint Sanitizer Awareness** — The taint engine tracks 9 categories of sanitizers (escaping, parameterized queries, type casting, ORM methods, template auto-escaping, safe output functions, validation guards) and clears taint state when sanitization is detected.

**Layer 3: AI Chain-of-Thought Validation** — Each finding is individually reviewed by the local LLM with full code context.

**Layer 4: Confidence Calibrator** — A learning system that tracks historical AI accuracy per severity level. After 5+ validations it calibrates future confidence scores:

```
calibrated = (rawConfidence × 0.70) + (historicalAccuracy × 0.30)
```

Stats persist across scans in `~/.sentryq/.scanner-ai-stats.json`.

**Layer 5: ML FP Reducer** — A similarity-based historical filter that learns from past scan feedback. If a specific rule ID + file extension + severity combination was historically flagged as false positive ≥ 80% of the time, future identical matches are automatically dropped.

---

## 12. Reachability Analysis & Call Graph

SentryQ builds a simplified call graph of your entire codebase by:

1. Scanning for function definitions across Go, Python, JS, Java, Kotlin, C#
2. Tracking function calls within each function body
3. Identifying entry points (main, init, HTTP handlers, route decorators, export default)
4. Performing DFS reachability from entry points to vulnerable functions

Findings in unreachable code (dead functions never called from any entry point) are downgraded to `info` severity, marked as `[UNREACHABLE]` in the description, and have their confidence reduced by 70%.

---

## 13. MITRE ATT&CK Threat Intelligence

Every finding is automatically enriched with MITRE ATT&CK technique mappings — entirely offline, no API calls:

- **SQL Injection** → T1190 (Exploit Public-Facing Application) — Initial Access
- **Command Injection** → T1059 (Command and Scripting Interpreter) — Execution
- **XSS** → T1189 (Drive-by Compromise) — Initial Access
- **Hardcoded Credentials** → T1078 (Valid Accounts) — Persistence, Privilege Escalation
- **Path Traversal** → T1083 (File and Directory Discovery) — Discovery
- **SSRF** → T1190 (Exploit Public-Facing Application) — Initial Access
- **Deserialization** → T1190 (Exploit Public-Facing Application) — Initial Access

---

## 14. Risk Scoring & Priority Matrix

### Aggregate Risk Score (0–100)

SentryQ calculates a weighted risk score:

- Critical finding: +10 points
- High finding: +5 points
- Medium finding: +2 points
- Low finding: +0.5 points

Score ≥ 75 = Critical Risk | ≥ 50 = High Risk | ≥ 25 = Medium Risk | < 25 = Low Risk

### Multi-Engine Trust Score

Each finding gets a trust score combining the base confidence from the detecting engine (0–100), plus +15 points per additional confirming engine, and +10 points for AI validation confirmation (capped at 100).

### Priority Matrix

- **P0** — Critical + AI confirmed → Fix immediately
- **P1** — Critical (unvalidated) or High + AI confirmed → Fix this sprint
- **P2** — High (unvalidated) or Medium + AI confirmed → Fix next sprint
- **P3** — Everything else → Fix when possible

---

## 15. Reporting — SARIF, HTML, CSV, PDF

Every scan generates four report formats simultaneously:

**HTML Report** — Standalone, self-contained report with embedded CSS. Includes severity breakdown charts, finding cards with code snippets, and remediation guidance.

**SARIF** — Static Analysis Results Interchange Format. Native integration with GitHub Security Tab, GitLab SAST, and Azure DevOps. Includes CWE IDs, OWASP categories, and rule metadata.

**CSV** — For spreadsheet-based triage workflows or importing into ticketing systems.

**PDF** — Professional report with risk score summary, priority matrix, and detailed findings. Suitable for executive reviews and compliance documentation.

---

## 16. Installation & Quick Start

### Prerequisites

**Linux:** Go 1.24+, Node.js 18+, Ollama (optional, for AI)

**macOS:** `brew install go nodejs ollama`

**Windows:** Go 1.24+, Node.js 18+, Ollama

### 5-Minute Setup

```bash
# 1. Clone
git clone https://github.com/Gauravjha68535/sentryQ.git
cd sentryQ

# 2. Build (Linux/macOS)
chmod +x build.sh && ./build.sh

# 3. Pull the default AI model (optional)
ollama pull qwen2.5-coder:7b

# 4. Run
./sentryq
# Open http://localhost:5336
```

**Windows:**

```batch
REM build.bat handles everything automatically
.\build.bat
.\sentryq.exe
```

### Zero-CGO binary

SentryQ is built with `CGO_ENABLED=0` — the binary has zero C dependencies. No GCC, no MinGW, no compilation headaches. It runs natively on any platform without external libraries.

---

## 17. Usage Examples — Real-World Workflows

### Interactive Web Dashboard

```bash
# Start with defaults
./sentryq

# Custom port
./sentryq --port 8080

# Remote Ollama server
./sentryq --ollama-host 192.168.1.10:11434
```

Navigate to `http://localhost:5336`, click **New Scan**, choose Upload / Git Clone / Local Path, and watch findings stream in via WebSocket.

### Headless CLI Scan

```bash
# Quick scan — static only, no AI
./sentryq /path/to/my-project

# Full scan with AI validation
./sentryq /path/to/my-project -model qwen2.5-coder:7b
```

### Scanning a Git Repository

From the web dashboard, paste any Git URL (HTTPS or SSH) and SentryQ will:

1. Clone with `--depth 1` (5-minute timeout)
2. Run the full analysis pipeline
3. Auto-cleanup the cloned directory after scan

### REST API

```bash
# Upload files for scanning
curl -X POST http://localhost:5336/api/scan/upload \
  -F "files=@app.py" \
  -F "config={\"enableAI\": true, \"aiModel\": \"qwen2.5-coder:7b\"}"

# Clone and scan a repo
curl -X POST http://localhost:5336/api/scan/git \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/example/app"}'

# Get findings
curl http://localhost:5336/api/scan/{scanID}/findings

# Download SARIF report
curl -O http://localhost:5336/api/scan/{scanID}/report/sarif
```

---

## 18. CI/CD Integration — GitHub Actions

SentryQ generates SARIF natively, so CI/CD integration is straightforward:

```yaml
# .github/workflows/sentryq-scan.yml
name: "SentryQ Security Scan"
on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

jobs:
  sentryq:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Set up Go
      uses: actions/setup-go@v5
      with:
        go-version: '1.24'

    - name: Build SentryQ
      run: |
        git clone https://github.com/Gauravjha68535/sentryQ.git /tmp/sentryQ
        cd /tmp/sentryQ && sh build.sh

    - name: Run SentryQ Headless Scan
      run: /tmp/sentryQ/sentryq ./

    - name: Upload SARIF to GitHub Security
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: report.sarif
      if: always()
```

---

## 19. Configuration Deep Dive

Settings are stored at `~/.sentryq/settings.json` (owner-only, mode 0600). You can configure via the Settings page in the UI or environment variables.

**Key settings:**

- `ollama_host` — Ollama server host:port (default: `localhost:11434`)
- `default_model` — LLM for Chain-of-Thought validation (auto-detected from installed models)
- `ai_provider` — `ollama` for local, `openai` for any OpenAI-compatible endpoint, `custom` for vLLM/LM Studio
- `custom_api_url` — Custom endpoint URL
- `custom_api_key` — API key for custom provider

**Environment variables:**

- `PORT` — Override default port 5336
- `OLLAMA_HOST` — Remote Ollama host:port (e.g., `OLLAMA_HOST=10.0.0.5:11434`)
- `SENTRYQ_CUSTOM_API_KEY` — Inject API key without writing to disk
- `AI_DEBUG` — Print raw AI output for debugging

### Recommended Models

- `qwen2.5-coder:7b` (~4 GB VRAM, fast) — General purpose, recommended default
- `qwen2.5-coder:14b` (~8 GB VRAM, medium) — Complex codebases
- `deepseek-coder:6.7b` (~4 GB VRAM, fast) — Alternative to Qwen
- `llama3.1:8b` (~5 GB VRAM, medium) — General reasoning

---

## 20. Architecture Decisions & Engineering Trade-offs

### Why Go?

Go gives us a compiled binary with no runtime dependencies, goroutines for concurrent file walking and analysis, seamless cross-platform builds for Linux/macOS/Windows from a single source tree, and `CGO_ENABLED=0` for a pure-Go binary with zero native library dependencies.

### Why sequential AI validation?

We initially ran AI validation concurrently. On consumer GPUs (≤ 8 GB VRAM), this caused immediate VRAM thrashing — LLM context windows competed for memory and the system froze. We settled on sequential validation with a circuit breaker (3 consecutive errors → skip remaining validations).

### Why not use Semgrep for everything?

Semgrep is excellent and SentryQ integrates with it as an optional deep-scan engine. But it requires Python, adds installation complexity, and its rule format differs from our YAML schema. SentryQ's built-in pattern engine + AST + taint analysis covers the vast majority of cases without external dependencies.

### Why SQLite for scan storage?

We use `modernc.org/sqlite` — a pure-Go SQLite implementation. No CGO needed. Scan history, findings, and triage status persist across restarts. Auto-cleanup removes reports older than 48 hours.

---

## 21. Performance Benchmarks

- Pattern scan speed (10K files): ~8 seconds
- AST analysis (1K source files): ~3 seconds
- Taint analysis (1K source files): ~5 seconds
- Secret detection (10K files): ~4 seconds
- AI validation per finding: 10–60 seconds (model-dependent)
- Full ensemble scan (medium project): 10–30 minutes
- Binary size: ~25 MB
- Memory usage (static only): ~100 MB

---

## 22. SentryQ vs. Traditional Tools

**Local AI validation:** SentryQ ✅ | SonarQube ❌ | Snyk ❌ | Semgrep ❌ | Bandit ❌

**Zero cloud dependency:** SentryQ ✅ | SonarQube ❌ | Snyk ❌ | Semgrep ✅ | Bandit ✅

**FP reduction:** SentryQ ~90% | SonarQube ~30% | Snyk ~40% | Semgrep ~35% | Bandit ~20%

**Languages supported:** SentryQ 67+ | SonarQube 30+ | Snyk 10+ | Semgrep 30+ | Bandit Python only

**Taint analysis:** SentryQ ✅ (11 languages) | SonarQube ✅ | Snyk ❌ | Semgrep ✅ | Bandit ❌

**SCA (dependency auditing):** SentryQ ✅ (OSV) | SonarQube ✅ | Snyk ✅ | Semgrep ❌ | Bandit ❌

**Container scanning:** SentryQ ✅ | SonarQube ❌ | Snyk ✅ | Semgrep ❌ | Bandit ❌

**MITRE ATT&CK mapping:** SentryQ ✅ | SonarQube ❌ | Snyk ❌ | Semgrep ❌ | Bandit ❌

**Single binary, no install:** SentryQ ✅ | SonarQube ❌ | Snyk ❌ | Semgrep ❌ | Bandit ❌

---

## 23. FAQ

**Does SentryQ work without Ollama / without AI?**
Yes. All static engines (pattern, AST, taint, secrets, SCA, container) run independently. AI is an optional enhancement layer for false positive reduction and deep discovery.

**Is my source code sent to the cloud?**
No. When using Ollama (default), everything runs on localhost. If you configure an external OpenAI-compatible endpoint, code context is sent to that endpoint — SentryQ makes this explicit in settings.

**What are the minimum system requirements?**
Static-only scanning: 4 GB RAM, any CPU. With AI: 8 GB+ RAM, GPU with 4 GB+ VRAM recommended. Storage: ~5 GB for models.

**Can I use SentryQ with cloud LLMs like GPT-4 or Claude?**
Yes. Set `ai_provider` to `openai` or `custom` and provide your API URL and key. SentryQ supports any OpenAI-compatible chat/completions endpoint.

**How do I add support for a new language?**
Create a YAML rule file in the `rules/` directory. SentryQ automatically discovers and loads it on the next scan — no code changes needed.

**Does SentryQ support monorepos?**
Yes. The file walker handles arbitrary directory depth and size. Language-aware rule loading ensures only relevant rules are loaded for the detected languages.

---

## 24. Conclusion

The era of manually triaging 500-page false-positive reports is over.

SentryQ combines the speed of Go-powered concurrent static analysis, the precision of AST and taint-flow tracking, the breadth of 12,400+ rules across 67+ languages, and the intelligence of local Chain-of-Thought AI — all in a single binary that never sends your code to the cloud.

```bash
git clone https://github.com/Gauravjha68535/sentryQ.git
cd sentryQ && ./build.sh && ./sentryq
```

**Star SentryQ on GitHub → https://github.com/Gauravjha68535/sentryQ**

*Built by Gaurav Jha, with foundational ideas from Deevan and critical architectural contributions from Akshay.*

---
