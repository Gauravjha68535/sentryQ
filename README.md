# 🛡️ SentryQ

> **Next-Gen AI-Orchestrated Security Analysis Platform**
> A high-performance, local-first security tool designed for elite engineering teams. Powered by Go and Local AI (Ollama).

SentryQ transforms security scanning from simple pattern matching into **Intelligent Orchestration**. It runs your codebase through **12,400+ static rules** across 60+ languages, performs **AI-driven vulnerability discovery**, and uses a **"Security Judge" LLM** to deduplicate and validate findings—all running 100% locally on your machine.

---

## 🏗️ System Architecture

SentryQ follows a multi-tier analysis pipeline that prioritizes precision and context.

```mermaid
graph TD
    A[Source Code] --> B{Discovery Phase}
    B --> C[Static Analysis Engine]
    B --> D[AI Discovery Engine]
    
    subgraph "Static Analysis Engine"
        C1[AST Analyzer]
        C2[Taint Flow Tracker]
        C3[Pattern Matching]
        C4[Secret Detector]
    end
    
    subgraph "Supply Chain"
        S1[OSV Scanner]
        S2[Semgrep Runner]
        S3[Container Scan]
    end

    C --> E[Aggregator]
    D --> E
    S1 --> E
    
    E --> F[AI Validation Triage]
    F --> G[Judge LLM Merger]
    G --> H[Consolidated Security Report]
    
    H --> I[Web UI / Dashboard]
    H --> J[PDF/JSON/CSV Export]
```

---

## 🌟 Core Features

| Feature | Technical Breakdown |
| :--- | :--- |
| **🔍 Multi-Engine SAST** | Combines AST-based logic, Taint-flow analysis, and 12,000+ regex-based patterns. |
| **🧠 AI-Orchestrated Triage** | Uses local LLMs (Qwen2.5-Coder) to validate findings (Chain-of-Thought) and suppress FPs. |
| **🌊 Deep Taint Tracking** | Analyzes data flow from user-controlled sources to dangerous sinks across variables and functions. |
| **🛡️ Mitigation Awareness** | AI recognizes secure coding patterns (e.g., `nonce` checks, `path.resolve` guards) to reduce noise. |
| **📦 Supply Chain & SCA** | Integrates Google **OSV-Scanner** and **Semgrep** for dependency and framework-specific audits. |
| **⚖️ Decision Judge** | A specialized "Judge LLM" compares static and AI results to produce a unified, trusted report. |
| **🏢 Triage Dashboard** | Real-time scan updates, finding drill-downs, and a built-in AI Security Chatbot. |

---

## 🔍 Security Engine Deep-Dive

### 1. Taint Analysis & Reachability
SentryQ doesn't just look for "dangerous functions." Our **[Taint Analyzer](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/taint-analyzer.go)** builds a variable flow graph to see if untrusted input (e.g., `req.body`) can actually reach a sink (e.g., `sql.Execute`) without being sanitized or escaped. This is augmented by **[Reachability Analysis](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/reachability.go)** which verifies that the vulnerable code path is actually traversable in the application's call graph.

### 2. AI Intelligence Layer
The **[AI Layer](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/ai/)** operates in three phases:
- **Discovery**: The LLM scans files for logic flaws that static tools miss (e.g., broken access control, IDOR).
- **Validation**: Every finding is passed to the **[Validator](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/ai/validator.go)** with full-file context to confirm exploitability.
- **Judge Merger**: The **[Judge Engine](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/ai/judge_engine.go)** uses a larger model to semantically deduplicate findings that overlap (e.g., a static rule and AI discovery hitting the same line).

### 3. Threat Intelligence Enrichment
Findings are enriched via the **[Threat Intel Scanner](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/threat_intel.go)** using:
- **MITRE ATT&CK** Mapping
- **CISA KEV** (Known Exploited Vulnerabilities)
- **EPSS** (Exploit Prediction Scoring System)

---

## 🏁 Quick Start

### 1. Prerequisites (One-Liner Install)

#### 🐧 Linux / 🍏 macOS
```bash
# Install Go, Ollama, and dependencies
curl -sSL https://raw.githubusercontent.com/SentryQ/setup/main/install.sh | bash

# Ensure you have the AI model running
ollama run qwen2.5-coder:7b
```

#### 🪟 Windows
1. Install **Go** from [golang.org](https://golang.org/dl/).
2. Install **Ollama** and run `ollama run qwen2.5-coder:7b`.
3. Install **Semgrep** (`pip install semgrep`).

### 2. Build & Deploy
```bash
# Build the embedded Frontend & Backend
./build.sh

# Start SentryQ
./sentryq
```
*Access the dashboard at `http://localhost:5336`*

---

## ⌨️ CLI & Configuration

| Flag | Description |
| :--- | :--- |
| `-port` | Web Dashboard port (default: `5336`) |
| `-ollama-host` | Remote Ollama instance (default: `localhost:11434`) |
| `[target]` | Optional: Path to a directory for an immediate CLI scan |

**Configuration**: Edit **[`.qwen-settings.json`](./.qwen-settings.json.example)** to configure AI providers (OpenAI/Ollama), custom API endpoints, and model preferences.

---

## 🤝 Contributing

We welcome contributions to the SentryQ core!
- **Core Engine**: See **[`cmd/scanner/`](./cmd/scanner/)** and **[`scanner/`](./scanner/)**.
- **Rules**: Add custom YAML rules to **[`rules/`](./rules/)**.
- **Frontend**: Built with React in **[`web/`](./web/)**.

Run tests via: `go test ./...`

---

## 📄 License

© 2026 SentryQ Security Team.