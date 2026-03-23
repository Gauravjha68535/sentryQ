# 🛡️ QWEN Security Scanner

> **Modern SAST, Supply Chain, & AI-Orchestrated Security Platform**
> A high-performance, local-first security tool designed for elite engineering teams. Powered by Go and Local AI (Ollama).

QWEN Security Scanner transforms security scanning from simple pattern matching into **Intelligent Orchestration**. It runs your codebase through **12,400+ static rules** across 60+ languages, performs AI-driven vulnerability discovery, and uses a "Security Guru" LLM to deduplicate and validate findings—all running 100% locally on your machine.

---

## 🏗️ Project Architecture & Technical Overview

QWEN is a hybrid security analysis tool that combines **Static Analysis (SAST)**, **Software Composition Analysis (SCA)**, and **AI-powered reasoning**.

### Tech Stack
- **Backend**: Go (Golang) for high-performance orchestration.
- **Frontend**: React.js with Tailwind CSS & Framer Motion.
- **Database**: BadgerDB (embedded Key-Value store).
- **AI Engine**: Ollama (local LLM) for validation and discovery.

### Documentation & Core Components

#### 📂 [Backend Orchestration](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/cmd/scanner/)
- **[Main Entrypoint](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/cmd/scanner/main.go)**: Initializes the system and starts the web dashboard.
- **[Scan Manager](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/cmd/scanner/scan_manager.go)**: The "Brain" coordinates between Semgrep, SCA, and AI engines.
- **[Web Dashboard API](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/cmd/scanner/web_dashboard.go)**: Handles HTTP requests, API security, and serves the UI via `go:embed`.
- **[WebSocket Hub](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/cmd/scanner/websocket_hub.go)**: Real-time progress and log broadcasting.

#### 🔍 [Security Engines](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/)
- **[SAST](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/semgrep_runner.go)**: Wraps Semgrep for deep pattern matching across frameworks.
- **[SCA](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/dependency_scanner.go)**: Identifies vulnerable packages using Google's **[OSV](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/osv_cli.go)** database.
- **[Secrets](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/secret_detector.go)**: Entropy-based detection for AWS keys, tokens, and private keys.
- **[AST & Taint](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/ast-analyzer.go)**: Tracks data flow from **[Source to Sink](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/scanner/taint-analyzer.go)**.

#### 🤖 [AI Layer](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/ai/)
- **[Validator](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/ai/validator.go)**: Adversarial simulation to eliminate false positives.
- **[Discovery](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/ai/discovery_scanner.go)**: AI-driven hunt for zero-days and logic flaws.
- **[Judge Engine](file:///home/justdial/Desktop/QWEN_SCR_24_FEB_2026/ai/judge_engine.go)**: Consolidates findings from all engines into a single master report.

---

## 🌟 Core Features

| Feature | Description |
| :--- | :--- |
| **🔍 Pattern Engine** | 12,400+ rules across 60+ languages. Auto-rescues broken YAML rules. |
| **🧠 Intelligence Overhaul** | **Deduplication v2**: CWE family grouping + proximity clustering (±5 lines). |
| **🛡️ Mitigation Awareness** | AI-driven FP suppression for safe APIs (`crypto.randomBytes`, `textContent`, etc.). |
| **🌊 Context Injection** | Full-file context + Cross-file dependency tracking for deep taint validation. |
| **⚖️ Security Judge** | Multi-engine consolidation with Chain-of-Thought (CoT) reasoning. |
| **📦 Supply Chain** | Google OSV-Scanner integration with local fallback. |
| **🌍 Cross-Platform** | Native execution on Windows, macOS, and Linux. |

---

## 🔬 Recent Intelligence Overhaul (Phase 3 & 4)

We recently performed a massive architectural upgrade to solve the "Noise & Duplication" problem common in AI scanners:

### 1. High-Precision Deduplication
- **CWE Family Grouping**: Instead of exact matches, the scanner now groups 22+ related CWEs into 16 canonical families (e.g., all Weak Randomness or SQLi variants merge into one).
- **Proximity Clustering**: Merges findings from different engines (Static, AI, Rules) that occur within ±5 lines of each other.

### 2. False Positive Suppression (Safe Pattern Recognition)
The scanner now performs a post-scan analysis pass that recognizes secure coding patterns and automatically suppresses them:
- **Crypto**: Recognizes `crypto.randomBytes` and `secrets.token_hex` as safe (not "Weak Random").
- **DOM**: Recognizes `textContent` usage as safe (not "XSS").
- **SQL**: Detects parameterized queries (`?`, `$1`) as safe.
- **Paths**: Identifies `path.resolve` + `startsWith` guards as valid path traversal mitigations.

### 3. Deep Context Validation
- **Full-File Context**: The AI Validator now analyzes the entire file (up to 500 lines) to find sanitizers and guards that might be far from the vulnerability sink.
- **Cross-File Dependency Tracking**: If a vulnerability is traced across files, the scanner automatically injects the related dependency code into the AI prompt for validation.
- **Chain-of-Thought JSON**: The Validator must now explicitly state logical steps (Taint Source found? Sanitizer found? Sink reachable?) before giving a final verdict.


---

## 🏁 Quick Start

### 1. Install Prerequisites

#### 🐧 Linux (Ubuntu/Debian)
```bash
sudo apt install golang-go
curl -fsSL https://ollama.com/install.sh | sh
ollama run qwen2.5-coder:7b
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2
sudo apt install python3-pip && pip3 install semgrep
```

#### 🍏 macOS
```bash
brew install go
brew install --cask ollama
ollama run qwen2.5-coder:7b
brew install semgrep
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2
```

#### 🪟 Windows
```powershell
winget install GoLang.Go
# Install Ollama from https://ollama.com/download/windows
ollama run qwen2.5-coder:7b
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2
pip install --upgrade semgrep
```

### 2. Build & Run
```bash
chmod +x build.sh
./build.sh
./qwen-scanner
```
*Access the dashboard at `http://localhost:5336`*

---

## ⚙️ Scanning Modes
1. **AI Validation only**: Confirm static findings. 
2. **AI Discovery only**: Find new issues.
3. **AI Discovery + Validate**: Find & verify new issues.
4. **Static + AI + Validate**: Thorough sequential scan.
5. **Consolidated (Recommended)**: Runs all engines and semantically merges results.
6. **Disable AI**: Standard static scanning only.

---

## ⌨️ CLI Flags

| Flag | Description |
| :--- | :--- |
| `-d` | Target directory to scan. |
| `-ai` | Enable AI validation. |
| `-semgrep` | Enable Semgrep community rules. |
| `-consolidated` | Enable consolidated intelligence mode. |
| `-model` | Specify Ollama model (default: `qwen2.5-coder:7b`). |
| `-port` | Web Dashboard port (default: `5336`). |

---

## 📊 Reports & Analysis
- **HTML**: Interactive charts and data filtering.
- **PDF/CSV**: Export findings for stakeholders or Jira.
- **ChatBot**: Ask questions about findings directly in the UI.
- **Taint-Flow Simulation**: Visualizes data paths from source to sink.

---

## 🤝 Contributing

Contributions are welcome! To get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and ensure tests pass: `go test ./... && go build ./...`
4. Submit a Pull Request

**Adding New Security Rules:**
Adding rules is simple! Place any `.yaml` file in the **[`rules/`](./rules)** directory (or a subdirectory). The engine auto-loads them on the next scan. Follow the existing format with `id`, `languages`, `patterns`, `severity`, `description`, `remediation`, `cwe`, and `owasp` fields.

**Tests:**
Our test suite protects cross-platform compatibility. Run `go test ./... -v` to verify core logic. Tests cover: newline normalization, test-file detection (Windows + Unix paths), CLI binary resolution, severity mapping, and language detection.

---

## 📄 License

This project is provided as-is for internal security research and development.
© 2026 QWEN Security Team.