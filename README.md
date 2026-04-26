# 🛡️ SentryQ

<div align="center">
  <p><strong>Next-Gen AI-Orchestrated Security Analysis Platform</strong></p>
  <p><i>A high-performance, local-first security tool designed for elite engineering teams. Powered by Go and AI.</i></p>

  [![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go)](https://golang.org)
  [![React Version](https://img.shields.io/badge/React-18+-61DAFB?style=flat-square&logo=react)](https://react.dev)
  [![Ollama Support](https://img.shields.io/badge/AI-Ollama%20%7C%20OpenAI-FF9900?style=flat-square&logo=openai)](https://ollama.com)
  [![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)](LICENSE)
</div>

<hr/>

SentryQ transforms security scanning from simple pattern matching into **Intelligent Orchestration**. It runs your codebase through seven independent static analysis engines, performs **AI-driven vulnerability validation** via Chain-of-Thought reasoning, and uses a **"Security Judge" LLM** to deduplicate and merge findings — all running 100% locally. Your code never leaves `localhost`.

> **Local-first guarantee:** No telemetry, no cloud uploads. Scans run entirely on your machine — including AI inference via Ollama.

---

## ✨ Core Capabilities

| Feature | Details |
| :--- | :--- |
| **Multi-Engine SAST** | 13,900+ rules across 67+ languages + Tree-Sitter AST (Python, JS, Java, Kotlin) + intra-file taint tracking (11 languages) |
| **Shannon Entropy Secret Detection** | Catches known secrets (AWS, GitHub, Stripe, JWT, Slack) and custom credentials via entropy analysis + base64/hex decode |
| **SCA / Dependency Auditing** | OSV API + `osv-scanner` CLI, reachability-aware (unused deps are downgraded) + supply chain / typosquatting checks |
| **Container & K8s Security** | Dockerfile lint + Kubernetes manifest audit + Trivy integration |
| **MITRE ATT&CK Enrichment** | Local technique mapping from CWE/issue keywords — no network calls |
| **AI-Orchestrated Triage** | Local LLMs via Ollama or any OpenAI-compatible endpoint. Chain-of-Thought validation slashes false positives. Generates Exploit PoC + Fixed Code per finding |
| **Ensemble Audit Mode** | 3-phase pipeline: Static Expert → AI Expert → Judge LLM merge (separate configurable models per phase) |
| **Real-Time Dashboard** | React + WebSocket. Dark/Light mode. Per-finding triage (open/resolved/ignored/FP) with bulk triage. Pause/Resume scan controls |
| **Rule Builder UI** | In-browser YAML rule editor with live regex test pane. Edit and create custom rules without leaving the dashboard |
| **Trust Score & Priority Matrix** | Per-finding composite Trust Score (0–100) + P0–P3 remediation priority tiers in all reports |
| **ML Feedback Loop** | User triage decisions feed a local FP-history cache (`~/.sentryq/ml-cache/`) to filter recurring false positives in future scans |
| **Multi-Format Reports** | SARIF, HTML, PDF, CSV — auto-generated per scan, served for 48 hours then auto-cleaned |

---

## 🏗️ Architecture

```
Source Code
    │
    ├──► Pattern Engine       (13,900+ regex rules, 67+ languages)
    ├──► AST Analyzer         (Tree-Sitter: Python, JavaScript, Java, Kotlin)
    ├──► Taint-Flow Tracker   (intra-file source→sink, 11 languages)
    ├──► Secret Detector      (regex + Shannon entropy + base64/hex decode)
    ├──► Dependency Scanner   (OSV API + osv-scanner CLI)
    ├──► Container Scanner    (Dockerfile + K8s + Trivy)
    │
    ▼
Aggregated Raw Findings
    │
    ├──► FP Suppressor        (code-context pattern matching)
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
    └──► FP Reducer                  (frequency-based historical filter via local feedback cache)
    │
    ▼
Final Report
    ├──► React Dashboard  (WebSocket real-time, Dark/Light mode, Pause/Resume, bulk triage)
    ├──► SARIF            (GitHub Security Tab, GitLab, Azure DevOps)
    ├──► HTML / PDF / CSV (Trust Score, Priority Matrix P0–P3, Exploit PoC, Fixed Code)
    └──► SQLite           (scan history, per-finding triage status, ensemble phase storage)
```

---

## 🚀 Installation

### Prerequisites

| Platform | Requirements |
| :--- | :--- |
| **Linux** | Go 1.24+, Node.js 18+, GCC (for SQLite), [Ollama](https://ollama.com) (optional, for AI) |
| **macOS** | `brew install go node ollama` |
| **Windows** | Go 1.24+, Node.js 18+, GCC via [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or MSYS2, Ollama |

> **Note:** SentryQ uses `modernc.org/sqlite` (pure Go SQLite driver) — no CGO required on most platforms. The `CGO_ENABLED=0` build flag is enforced in the build scripts.

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

This bundles the React frontend and compiles the Go backend into a single `sentryq` binary.

---

## 🏁 Usage

### Web Dashboard (recommended)

```bash
./sentryq
```

Navigate to **`http://localhost:5336`** → click **New Scan** → upload a folder or paste a Git URL.

### CLI / Headless Mode

```bash
# Static scan of a local directory (no AI, fast)
./sentryq /path/to/my-repo

# Custom port
./sentryq --port 8080

# Remote Ollama instance
./sentryq --ollama-host 192.168.1.10:11434
```

### Environment Variables

| Variable | Description | Example |
| :--- | :--- | :--- |
| `PORT` | Override default port 5336 | `PORT=8080 ./sentryq` |
| `OLLAMA_HOST` | Remote Ollama host:port | `OLLAMA_HOST=10.0.0.5:11434 ./sentryq` |
| `SENTRYQ_CUSTOM_API_KEY` | Inject API key without writing to disk | `SENTRYQ_CUSTOM_API_KEY=sk-... ./sentryq` |

---

## ⚙️ Configuration

Settings are stored at `~/.sentryq/settings.json` (owner-only, mode 0600). Configure via the Settings page in the UI or environment variables.

| Field | Description | Default |
| :--- | :--- | :--- |
| `ollama_host` | Ollama server host:port | `localhost:11434` |
| `default_model` | LLM for Chain-of-Thought validation | auto-detected from installed models |
| `ai_provider` | `ollama` or `openai` (any OpenAI-compatible endpoint) | `ollama` |
| `custom_api_url` | Custom endpoint URL (vLLM, TGI, LM Studio, etc.) | — |
| `custom_api_key` | API key for custom provider | — |
| `custom_model` | Model name for custom provider | — |

### Custom Rules

Drop any `.yaml` file into the `rules/` directory next to the binary:

```yaml
- id: acme-hardcoded-jwt
  languages: [javascript, typescript, python, go]
  patterns:
    - regex: '(?i)(jwt_secret|jwt_key)\s*=\s*["\'][a-zA-Z0-9_\-\.]{10,}["\']'
  severity: critical
  description: "Hardcoded JWT secret detected"
  remediation: "Load from environment variable: process.env.JWT_SECRET"
  cwe: "CWE-798"
  owasp: "A07:2021"
```

SentryQ auto-loads all rules on startup and on every scan, filtered to the languages detected in the target.

---

## 🔧 Additional Capabilities

| Capability | Details |
| :--- | :--- |
| **Scan Pause / Resume** | Pause a running scan between phases and resume later; state persisted to DB |
| **Bulk Triage** | Multi-select findings in the dashboard and set status in one action |
| **Rule Builder** | In-browser YAML rule editor with live regex test pane — no file system access needed |
| **Trust Score** | Per-finding composite score (0–100): base confidence + engine corroboration bonus + AI validation bonus |
| **Priority Matrix** | P0 (critical/high reachable) → P3 (low) remediation tiers surfaced in HTML and PDF reports |
| **Exploit PoC & Fixed Code** | AI validator generates a working proof-of-concept and a corrected code snippet per finding |
| **FP Feedback Loop** | Triage decisions (false_positive / resolved) are stored locally at `~/.sentryq/ml-cache/` and used to suppress recurring false positives in future scans |
| **Multi-Phase Ensemble Storage** | All three ensemble phases (static / ai / final) are stored independently in SQLite and viewable separately in the ReportViewer |
| **Git URL scanning** | Paste a public or private Git URL in the UI; SentryQ clones, scans, and cleans up automatically |
| **Report auto-cleanup** | Generated report files (HTML, PDF, CSV, SARIF) are automatically deleted 48 hours after scan completion |

---

## ⚙️ CI/CD Integration (GitHub Actions)

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
          go-version: '1.24'

      - name: Build SentryQ
        run: |
          git clone https://github.com/Gauravjha68535/sentryQ.git /tmp/sentryQ
          cd /tmp/sentryQ && sh build.sh

      - name: Run SentryQ headless scan
        run: /tmp/sentryQ/sentryq ./

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: /tmp/sentryQ/report.sarif
```

---

## 🔍 Scan Modes

### Standard Mode
Runs all always-on engines (pattern, AST, taint, secret detection, FP suppression, reachability). Enable **Deep Scan** to add dependency auditing, Semgrep, supply chain / typosquatting checks, container scanning, and MITRE ATT&CK enrichment. Enable **AI** to add Chain-of-Thought validation (with Exploit PoC + Fixed Code generation), AI discovery, Judge LLM consolidation, and confidence calibration.

> **Note:** AST analysis covers Python, JavaScript, Java, and Kotlin. Taint tracking is intra-file across 11 languages. Browser notifications fire on scan completion.

### Ensemble Audit Mode
Three-phase high-assurance pipeline for maximum accuracy:

| Phase | What happens |
| :--- | :--- |
| **Phase 1 — Static Expert** | All static engines run independently → Report A |
| **Phase 2 — AI Expert** | AI independently scans all files → Report B |
| **Phase 3 — Judge LLM** | A second LLM reviews both reports, resolves conflicts, and produces the final master report |

---

## 🤝 Contributing

| Area | Location |
| :--- | :--- |
| Core scanner engines | `scanner/` |
| AI validation, judge, calibration | `ai/` |
| API server & scan orchestration | `cmd/scanner/` |
| Frontend UI | `web/src/` |
| Report generators (SARIF, HTML, PDF, CSV) | `reporter/` |
| Detection rules (67 languages + 15 framework files) | `rules/` |
| Rule loader (YAML parsing) | `config/` |

**Frontend dev server:**
```bash
cd web && npm install && npm run dev
```

**Run tests:**
```bash
go test ./...
```

---

## 📜 License

© 2026 SentryQ. All rights reserved.
