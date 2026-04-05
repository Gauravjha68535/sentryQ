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

---

## ✨ Core Capabilities

| Feature | Details |
| :--- | :--- |
| **Multi-Engine SAST** | 12,400+ rules across 67+ languages + Tree-Sitter AST + inter-procedural taint tracking |
| **Shannon Entropy Secret Detection** | Catches known secrets (AWS, GitHub, Stripe) and custom credentials via entropy analysis + base64/hex decode |
| **SCA / Dependency Auditing** | OSV API + `osv-scanner` CLI, reachability-aware (unused deps are downgraded) |
| **Container & K8s Security** | Dockerfile lint + Kubernetes manifest audit + Trivy integration |
| **MITRE ATT&CK Enrichment** | Local technique mapping — no network calls |
| **AI-Orchestrated Triage** | Local LLMs via Ollama or any OpenAI-compatible endpoint. Chain-of-Thought validation slashes false positives |
| **Ensemble Audit Mode** | 3-phase pipeline: Static Expert → AI Expert → Judge LLM merge |
| **Real-Time Dashboard** | React + WebSocket. Dark/Light mode. Per-finding triage (open/resolved/ignored/FP) |
| **Multi-Format Reports** | SARIF, HTML, PDF, CSV — auto-generated per scan |

---

## 🏗️ Architecture

```
Source Code
    │
    ├──► Pattern Engine       (12,400+ regex rules, 67+ languages)
    ├──► AST Analyzer         (Tree-Sitter: Python, JS/TS, Java, Kotlin)
    ├──► Taint-Flow Tracker   (source→sink dataflow, 11 languages)
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
    ├──► Chain-of-Thought Validator  (per-finding taint analysis)
    ├──► AI Discovery Engine         (sliding-window vulnerability hunt)
    ├──► Judge Engine                (multi-report consensus & dedup)
    ├──► Confidence Calibrator       (historical accuracy weighting)
    └──► ML FP Reducer               (similarity-based historical filter)
    │
    ▼
Final Report
    ├──► React Dashboard  (WebSocket real-time, Dark/Light mode)
    ├──► SARIF            (GitHub Security Tab, GitLab, Azure DevOps)
    ├──► HTML / PDF / CSV
    └──► SQLite           (scan history, per-finding triage status)
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
Runs all always-on engines (pattern, AST, taint, secret detection). Enable **Deep Scan** to add dependency auditing, Semgrep, supply chain checks, container scanning, and MITRE enrichment. Enable **AI** to add Chain-of-Thought validation and AI discovery.

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
| AI validation & triage | `ai/` |
| API server & scan orchestration | `cmd/scanner/` |
| Frontend UI | `web/src/` |
| Report generators | `reporter/` |
| Detection rules | `rules/` |

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
