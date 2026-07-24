# SentryQ

<div align="center">
  <p><strong>Next-Gen AI-Orchestrated Security Analysis Platform</strong></p>
  <p><i>A high-performance, local-first security tool designed for elite engineering teams. Powered by Go and AI.</i></p>

  [![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go)](https://golang.org)
  [![React Version](https://img.shields.io/badge/React-18+-61DAFB?style=flat-square&logo=react)](https://react.dev)
  [![AI Support](https://img.shields.io/badge/AI-Ollama%20%7C%20OpenAI%20%7C%20Claude%20%7C%20Gemini-FF9900?style=flat-square&logo=openai)](https://ollama.com)
  [![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)](LICENSE)
</div>

<hr/>

SentryQ transforms security scanning from simple pattern matching into **Intelligent Orchestration**. It runs your codebase through seven independent static analysis engines, performs **AI-driven vulnerability validation** via Chain-of-Thought reasoning, and uses a **"Security Judge" LLM** to deduplicate and merge findings — all running 100% locally. Your code never leaves `localhost`.

> **Local-first guarantee:** No telemetry, no cloud uploads. Scans run entirely on your machine — including AI inference via Ollama.

---

## Core Capabilities

| Feature | Details |
| :--- | :--- |
| **Multi-Engine SAST** | 13,168+ rules across 120 rule files (71 languages, 15 framework targets) + Tree-Sitter AST (18 languages) + taint tracking (11 languages) |
| **Cross-File Taint Tracking** | Project-wide function-signature index built before scanning so taint sources exported from one file are recognised when imported by another. _Scope: signature-level propagation, not a full data-flow graph._ |
| **Negative Pattern Suppression** | Per-rule `negative_patterns` teach the engine about sanitizers and safe API variants; any match within a ±10-line context window auto-suppresses the finding |
| **Low-Confidence Severity Capping** | Rules with `confidence < 0.3` are automatically capped to `info` severity so speculative rules never pollute critical/high queues |
| **Shannon Entropy Secret Detection** | Catches known secrets (AWS, GitHub, Google, Stripe, Slack, JWT, private keys) and custom credentials via entropy analysis + base64/hex decode |
| **SCA / Dependency Auditing** | OSV API + `osv-scanner` CLI, reachability-aware (unused deps are downgraded) + supply chain / typosquatting checks |
| **Container & K8s Security** | Dockerfile lint + Kubernetes manifest audit + Trivy integration |
| **MITRE ATT&CK Enrichment** | Local technique mapping from CWE/issue keywords — no network calls |
| **AI-Orchestrated Triage** | Supports **Ollama, OpenAI, Anthropic Claude, Google Gemini, and LM Studio**. Chain-of-Thought validation slashes false positives. Generates Exploit PoC + Fixed Code per finding. |
| **Judge LLM with ID Validation** | Ensemble Judge deduplicates two reports in batches of 30 (up from 5) so static and AI findings that describe the same vulnerability land in the same batch and get merged; output coverage verified — missing IDs retained via catch-all |
| **Ensemble Audit Mode** | 3-phase pipeline: Static Expert → AI Expert → Judge LLM merge (separate configurable models per phase) |
| **CI Policy Engine** | `--fail-on critical`, `--max-critical N`, `--max-high N`, `--max-medium N`, `--max-low N`, `--max-total N` — exit code 1 on violation; also configurable from the New Scan UI |
| **PR / MR Decoration** | Posts findings as GitHub PR review comments (inline) and GitLab MR notes; token + repo configured per-scan from UI or CLI |
| **Webhook Notifications** | POST JSON payload to any URL on scan completion or policy violation; configure globally in Settings or per-scan in New Scan |
| **Incremental Scan** | `--changed-only` (CLI) or toggle in UI — only scans files changed since the base branch |
| **Scan Diff** | Compare any two scans: new / fixed / persisting findings + critical/high delta. `sentryq --diff <id1> <id2>` or Compare Scans page |
| **Compliance Reports** | OWASP Top 10 2021, PCI DSS 3.2.1, NIST SP 800-53 mapping — JSON + HTML reports auto-generated per scan, downloadable from Report Viewer |
| **CycloneDX SBOM** | Software Bill of Materials (CycloneDX 1.4) auto-generated per scan; downloadable from Report Viewer |
| **SentryQL Query Language** | Semantic rule queries: `FIND function_call(execute) WHERE tainted_by(request) AND not_sanitized_by(escape) REPORT AS critical` |
| **Real-Time Dashboard** | React + WebSocket. Dark/Light mode. Per-finding triage (open/resolved/ignored/FP) with bulk triage. Pause/Resume scan controls. Policy gate badge per scan. |
| **Rule Builder UI** | In-browser YAML rule editor with live regex test pane. Edit and create custom rules without leaving the dashboard |
| **Trust Score & Priority Matrix** | Per-finding composite Trust Score (0–100) + P0–P3 remediation priority tiers in all reports |
| **FP History Cache** | User triage decisions feed a local history file (`~/.sentryq/ml-cache/`). Findings whose per-rule FP rate exceeds a threshold are suppressed on future scans. Frequency-based — not a trained model. |
| **Multi-User RBAC** | Set `SENTRYQ_MULTI_USER=1` to enable login, user management (admin/analyst/viewer roles), session tokens. Admin panel in Settings. |
| **Auto-Update** | `./sentryq update` checks GitHub for a newer release and replaces the binary in-place (old binary saved as `sentryq.bak`) |
| **Multi-Format Reports** | SARIF, HTML, PDF (go-pdf/fpdf), CSV, CycloneDX SBOM, OWASP/PCI compliance HTML — auto-generated per scan, served for 48 hours then auto-cleaned |

---

## Architecture

```
Source Code
    │
    ├──► Pattern Engine       (13,168+ regex rules, 71 languages, 15 framework targets)
    │     └── Negative Patterns (±10-line context window suppresses sanitized code paths)
    │     └── SentryQL Engine  (semantic queries: tainted_by, not_sanitized_by, matches)
    ├──► AST Analyzer         (Tree-Sitter: 18 languages — Python, JS/TS, Java, Kotlin, Go,
    │                          Ruby, Rust, C, C++, C#, PHP, Scala, Swift, Bash, Elixir, Groovy, Lua)
    ├──► Taint-Flow Tracker   (cross-file call-graph index + intra-file source→sink, 11 languages)
    ├──► Secret Detector      (regex + Shannon entropy + base64/hex decode)
    ├──► Dependency Scanner   (OSV API + osv-scanner CLI, reachability-aware)
    ├──► Container Scanner    (Dockerfile + K8s + Trivy)
    │
    ▼
Aggregated Raw Findings
    │
    ├──► FP Suppressor        (code-context pattern matching + blocked rule list)
    ├──► Reachability Analyzer(call-graph DFS from entry points)
    ├──► MITRE ATT&CK Enrich  (local technique mapping)
    │
    ▼
AI Validation Layer (optional)
    │
    ├──► Chain-of-Thought Validator  (per-finding analysis + Exploit PoC + Fixed Code)
    ├──► AI Discovery Engine         (sliding-window vulnerability hunt)
    ├──► Judge Engine                (multi-report consensus & dedup; configurable separate model)
    ├──► Confidence Calibrator       (historical accuracy weighting)
    └──► FP History Cache            (frequency-based historical filter via local feedback cache)
    │
    ▼
Final Report
    ├──► React Dashboard  (WebSocket real-time, Dark/Light mode, Pause/Resume, bulk triage)
    ├──► SARIF            (GitHub Security Tab, GitLab, Azure DevOps)
    ├──► HTML / PDF / CSV (Trust Score, Priority Matrix P0–P3, Exploit PoC, Fixed Code)
    ├──► CycloneDX SBOM   (Software Bill of Materials, auto-generated)
    ├──► Compliance HTML  (OWASP Top 10, PCI DSS, NIST 800-53 control mapping)
    └──► SQLite           (scan history, per-finding triage status, ensemble phase storage)
```

---

## Installation

### Prerequisites

| Platform | Requirements |
| :--- | :--- |
| **Linux** | Go 1.25+, Node.js 18+, GCC (required for go-tree-sitter CGO sources), [Ollama](https://ollama.com) (optional, for AI) |
| **macOS** | `brew install go node ollama` |
| **Windows** | Go 1.25+, Node.js 18+, GCC via [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or MSYS2, Ollama |

> **Note:** SentryQ uses `modernc.org/sqlite` (pure Go SQLite driver) for its database. However, **CGO is required** because the Tree-Sitter AST analyzer embeds C grammar sources via `go-tree-sitter`. Ensure GCC (or a compatible C compiler) is available on your `PATH` before building.

**Optional AI model (recommended):**
```bash
ollama pull qwen2.5-coder:7b
```

### Build

**Linux / macOS:**
```bash
git clone https://github.com/Gauravjha68535/sentryQ.git
cd sentryQ
chmod +x build.sh
./build.sh
```

**Windows:**
```batch
git clone https://github.com/Gauravjha68535/sentryQ.git
cd sentryQ
.\build.bat
```

This bundles the React frontend and compiles the Go backend into a single `sentryq` binary. The `rules/` directory is packaged alongside the binary in `dist/` — both must remain co-located at runtime.

---

## Usage

### Web Dashboard (recommended)

```bash
./sentryq
```

Navigate to **`http://localhost:5336`** → click **New Scan** → configure scan options → start.

### CLI / Headless Mode

```bash
# Static scan of a local directory (pattern + AST + taint + secrets, no AI)
./sentryq /path/to/my-repo

# AI-powered scan — adds Chain-of-Thought validation, discovery, and consolidation
./sentryq --enable-ai /path/to/repo

# Full Ensemble Audit — 3-phase pipeline: static → AI → Judge LLM merge
./sentryq --enable-ensemble /path/to/repo

# Ensemble with explicit models
./sentryq --enable-ensemble \
  --ai-model qwen2.5-coder:7b \
  --judge-model llama3.1:8b \
  /path/to/repo

# Print version
./sentryq --version

# Custom port
./sentryq --port 8080

# Remote Ollama instance
./sentryq --ollama-host 192.168.1.10:11434

# CI: fail if any critical finding
./sentryq --fail-on critical /path/to/repo

# CI: fail if more than 5 high findings (also supports --max-medium, --max-low, --max-total)
./sentryq --max-high 5 /path/to/repo

# Scan only files changed since main branch
./sentryq --changed-only --base-branch main /path/to/repo

# Compare two scans
./sentryq --diff <scan-id-1> <scan-id-2>

# Check for and install the latest release
./sentryq update
```

### Environment Variables

| Variable | Description | Example |
| :--- | :--- | :--- |
| `PORT` | Override default port 5336 | `PORT=8080 ./sentryq` |
| `OLLAMA_HOST` | Remote Ollama host:port | `OLLAMA_HOST=10.0.0.5:11434 ./sentryq` |
| `SENTRYQ_CUSTOM_API_KEY` | Inject API key without writing to disk | `SENTRYQ_CUSTOM_API_KEY=sk-... ./sentryq` |
| `SENTRYQ_CLAUDE_API_KEY` | Inject Anthropic Claude API key | `SENTRYQ_CLAUDE_API_KEY=sk-ant-... ./sentryq` |
| `SENTRYQ_GEMINI_API_KEY` | Inject Google Gemini API key | `SENTRYQ_GEMINI_API_KEY=AIza... ./sentryq` |
| `SENTRYQ_BIND` | Set listening interface (defaults to 127.0.0.1 for security) | `SENTRYQ_BIND=0.0.0.0 ./sentryq` |
| `SENTRYQ_AUTH_TOKEN` | Enable single-token API authentication & CSRF protection | `SENTRYQ_AUTH_TOKEN=mysecret ./sentryq` |
| `SENTRYQ_MULTI_USER` | Enable multi-user RBAC mode (admin/analyst/viewer) | `SENTRYQ_MULTI_USER=1 ./sentryq` |
| `SENTRYQ_WEBHOOK_URLS` | Comma-separated webhook URLs for scan completion notifications | `SENTRYQ_WEBHOOK_URLS=https://...` |
| `SENTRYQ_PR_TOKEN` | Inject GitHub/GitLab token for PR decoration without writing to disk | `SENTRYQ_PR_TOKEN=ghp_...` |

---

## Configuration

Settings are stored at `~/.sentryq/settings.json` (owner-only, mode 0600). Configure via the Settings page in the UI or environment variables.

| Field | Description | Default |
| :--- | :--- | :--- |
| `ollama_host` | Ollama server host:port | `localhost:11434` |
| `default_model` | LLM for Chain-of-Thought validation | auto-detected from installed models |
| `ai_provider` | `ollama`, `openai`, `claude`, `gemini`, or `lmstudio` | `ollama` |
| `custom_api_url` | Custom endpoint URL (vLLM, TGI, LM Studio, etc.) | — |
| `custom_api_key` | API key for custom provider | — |
| `custom_model` | Model name for custom provider | — |
| `webhook_urls` | Comma-separated webhook endpoints notified on scan completion | — |

**Per-scan overrides** (configurable from the New Scan UI):

| Field | Description |
| :--- | :--- |
| `aiModel` / `ollamaHost` | Model and host used for Chain-of-Thought validation |
| `consolidationModel` / `consolidationOllamaHost` | Model used for AI discovery consolidation |
| `judgeModel` / `judgeOllamaHost` | Separate model and host for the Judge LLM in Ensemble mode |
| `enableMLFPReduction` | Enable FP history-based suppression using local feedback |
| `customRulesDir` | Path to an additional directory of custom YAML rule files |
| `policyFailOn` | Severity threshold that triggers policy failure (`critical`, `high`, `medium`, `low`) |
| `maxCritical` / `maxHigh` / `maxMedium` / `maxLow` / `maxTotal` | Maximum findings per severity before policy fails (-1 = no limit) |
| `prProvider` / `prToken` / `prRepo` / `prNumber` | GitHub PR decoration config |
| `webhookUrls` | Per-scan webhook override (comma-separated) |
| `incrementalScan` / `baseBranch` | Restrict scan to files changed vs base branch |

### Custom Rules

Drop any `.yaml` file into the `rules/` directory next to the binary:

```yaml
- id: acme-hardcoded-jwt
  languages: [javascript, typescript, python, go]
  patterns:
    - regex: '(?i)(jwt_secret|jwt_key)\s*=\s*["\'][a-zA-Z0-9_\-\.]{10,}["\']'
  negative_patterns:
    - regex: 'os\.environ|process\.env|getenv|config\.'
  severity: critical
  description: "Hardcoded JWT secret detected"
  remediation: "Load from environment variable: process.env.JWT_SECRET"
  cwe: "CWE-798"
  owasp: "A07:2021"
```

Rules also support the **SentryQL** query language for semantic pattern matching:

```yaml
- id: my-ssrf-rule
  languages: [python]
  patterns:
    - regex: 'requests\.(get|post)\s*\('
  sentryql: |
    FIND requests.get OR requests.post
    WHERE input IS NOT LITERAL
  negative_patterns:
    - regex: '(?i)(allowlist|validate_url|urlparse)'
  severity: high
  description: "SSRF risk — outbound HTTP with user-controlled URL"
  cwe: "CWE-918"
  owasp: "A10:2021"
```

SentryQ auto-loads all rules on startup and on every scan, filtered to the languages detected in the target.

---

## Additional Capabilities

| Capability | Details |
| :--- | :--- |
| **Scan Pause / Resume** | Pause a running scan between phases and resume later; state persisted to DB |
| **Bulk Triage** | Multi-select findings in the dashboard and set status in one action |
| **Compare Scans** | Side-by-side diff of any two scans — new / fixed / persisting findings with severity delta |
| **Rule Builder** | In-browser YAML rule editor with live regex test pane — no file system access needed |
| **Trust Score** | Per-finding composite score (0–100): base confidence + engine corroboration bonus + AI validation bonus |
| **Priority Matrix** | P0 (critical/high reachable) → P3 (low) remediation tiers surfaced in HTML and PDF reports |
| **Exploit PoC & Fixed Code** | AI validator generates a working proof-of-concept and a corrected code snippet per finding |
| **FP History Cache** | Triage decisions (false_positive / resolved) are stored locally at `~/.sentryq/ml-cache/` and used to suppress recurring false positives in future scans |
| **Confidence Calibration** | Historical TP/FP accuracy per severity is tracked in `~/.sentryq/.scanner-ai-stats.json` and used to adjust future AI confidence scores |
| **Multi-Phase Ensemble Storage** | All three ensemble phases (static / ai / final) are stored independently in SQLite and viewable separately in the ReportViewer |
| **Git URL scanning** | Paste a public or private Git URL in the UI; SentryQ clones, scans, and cleans up automatically |
| **Report auto-cleanup** | Generated report files (HTML, PDF, CSV, SARIF, SBOM, Compliance) are automatically deleted 48 hours after scan completion |
| **Browser Notifications** | Desktop push notification on scan completion — opt-in via "Notify me" button on the scan progress page (no automatic permission prompt) |

---

## Rule Coverage

120 rule files covering 71 languages and security domains:

**Languages & Runtimes:** C, C++, C#, Go, Java, JavaScript, TypeScript, Python, Ruby, PHP, Rust, Swift, Kotlin, Scala, Dart, Groovy, Elixir, Erlang, Haskell, Lua, Perl, R, Julia, Nim, OCaml, F#, Crystal, Clojure, Zig, Move, Cairo, Vyper, Solidity, WebAssembly, Objective-C, Bash/Shell, PowerShell, ASP, ASP.NET, and more.

**Security Domains:** SQL Injection, XSS, SSRF, Command Injection, Path Traversal, Secrets Detection, Cryptography, Authentication, Authorization, JWT, OAuth/OIDC, Session Management, CSRF, Deserialization, Race Conditions, ReDoS, Prototype Pollution, Template Injection, XXE, GraphQL, gRPC, WebSockets, CORS, CSP Bypass, HTTP Request Smuggling, LDAP Injection, NoSQL Injection, Email/SMTP Injection, Supply Chain, Side-Channel / Timing, LLM/AI Security, Cloud Metadata, Container Security, Kubernetes, Serverless, Service Mesh, eBPF Security, Mobile (Android/iOS/Flutter), and more.

**Frameworks:** Angular, Django, Express, FastAPI, Flask, Go Web (Gin/Echo/Fiber), Laravel, Next.js, Nuxt.js, Rails, React, Spring, Svelte, Vue, Mobile (React Native/Ionic).

---

## CI/CD Integration (GitHub Actions)

```yaml
name: SentryQ Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sentryq:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Build SentryQ
        run: |
          git clone https://github.com/Gauravjha68535/sentryQ.git /tmp/sentryQ
          cd /tmp/sentryQ && sh build.sh

      - name: Run SentryQ headless scan (fail on critical)
        run: /tmp/sentryQ/sentryq --fail-on critical ./

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: /tmp/sentryQ/report.sarif
```

### PR Decoration (GitHub)

```yaml
      - name: Decorate PR with findings
        if: github.event_name == 'pull_request'
        env:
          # Pass token via env var — SentryQ reads SENTRYQ_PR_TOKEN and never
          # writes it to the scan database, keeping the secret out of storage.
          SENTRYQ_PR_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          /tmp/sentryQ/sentryq \
            --pr-provider github \
            --pr-repo ${{ github.repository }} \
            --pr-number ${{ github.event.pull_request.number }} \
            --fail-on high \
            ./
```

---

## Scan Modes

### Standard Mode
Runs all always-on engines (pattern, AST, taint, secret detection, FP suppression, reachability). Enable **Deep Scan** to add dependency auditing, Semgrep, supply chain / typosquatting checks, container scanning, and MITRE ATT&CK enrichment. Enable **AI** to add Chain-of-Thought validation (with Exploit PoC + Fixed Code generation), AI discovery, Judge LLM consolidation, and confidence calibration.

> **Note:** AST analysis now covers **18 languages** — Python, JavaScript, TypeScript, Java, Kotlin, Go, Ruby, Rust, C, C++, C#, PHP, Scala, Swift, Bash, Elixir, Groovy, Lua. Taint tracking is cross-file + intra-file across 11 languages (Python, PHP, JavaScript/TypeScript, Java, Kotlin, C#/ASP.NET, Go, Ruby, Swift, Dart). Browser notifications fire on scan completion.

### Ensemble Audit Mode
Three-phase high-assurance pipeline for maximum accuracy:

| Phase | What happens |
| :--- | :--- |
| **Phase 1 — Static Expert** | All static engines run independently → Report A |
| **Phase 2 — AI Expert** | AI independently scans all files → Report B |
| **Phase 3 — Judge LLM** | A second LLM reviews both reports, resolves conflicts, and produces the final master report |

---

## Contributing

| Area | Location |
| :--- | :--- |
| Core scanner engines | `scanner/` |
| AI validation, judge, calibration, FP history cache | `ai/` |
| API server, scan orchestration, CI policy, PR decoration, auto-updater | `cmd/scanner/` |
| Frontend UI | `web/src/` |
| Report generators (SARIF, HTML, PDF, CSV, SBOM, Compliance) | `reporter/` |
| Detection rules (120 files: 71 languages + security domains; 15 framework files) | `rules/` |
| Rule loader (YAML parsing, negative patterns, SentryQL) | `config/` |
| Shared utilities | `utils/` |

**Frontend dev server:**
```bash
cd web && npm install && npm run dev
```

**Run tests:**
```bash
go test ./...
```

---

## License

© 2026 SentryQ. All rights reserved.
