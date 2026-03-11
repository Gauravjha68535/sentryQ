# 🛡️ AI-Powered Security Scanner

> **Modern SAST, Supply Chain, & AI-Orchestrated Security Platform**
> A high-performance, local-first security tool designed for elite engineering teams. Powered by Go and Local AI (Ollama).

This tool transforms security scanning from simple pattern matching into **Intelligent Orchestration**. It runs your codebase through 900+ static rules, performs AI-driven vulnerability discovery, and uses a "Security Guru" LLM to deduplicate and validate findings—all running 100% locally on your machine.

---

## 🌟 What Can It Do? (Core Features Explained)

| Feature | What it means & why it's useful |
| :--- | :--- |
| **🔍 Pattern Matching Engine** | Uses **security rules** across 20+ languages to find hardcoded secrets, weak crypto, and classic injections. |
| **🧠 Security Guru 3.0 (AI)** | **Chain of Thought (CoT)** reasoning. The AI "thinks" like an attacker, performing simulated **Taint-Flow** traces and construction exploitation payloads before reporting. |
| **🔄 Intelligent Orchestration** | **The Merger Mode:** Runs Static rules first, then AI Discovery, then uses a Master LLM to semantically deduplicate and merge the results into one "Master" report. |
| **🌊 Deep Flow Analysis** | Tracks data from Source to Sink. It understands what is MISSING—detecting the **Absence of CSRF tokens**, missing **HSTS/CSP headers**, or unvalidated entry points. |
| **📦 Supply Chain (SCA)** | Integrates **Google OSV-Scanner** for deep lockfile analysis. If the CLI is missing, it fails back to a custom built-in parser with OSV.dev API support. |
| **🛡️ Adversarial Validation** | The AI doesn't just "check" code; it attempts to **Simulated Bypass**. It tries to break your filters using encoding tricks (Base64, Unicode, Null bytes) to ensure they are truly secure. |
| **🌍 100% Cross-Platform** | Native execution on Windows, macOS, and Linux. Automatically handles OS-specific RAM detection, CLI `.exe` resolutions, and Carriage Return (`\r\n`) normalizations. |

---

## 🏁 How to Use (Quick Start)

### Step 1: Install Prerequisites (OS Specific)

We have built this tool to automatically adapt to **Windows, macOS, and Linux**. Install the core dependencies for your specific OS below:

#### 🐧 Linux (Ubuntu/Debian)
```bash
# 1. Install Go (cross‑platform compatible)
sudo apt install golang-go
# 2. Install Ollama & Models
curl -fsSL https://ollama.com/install.sh | sh
ollama run qwen2.5-coder:7b
# 3. Supplemental Tools
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2
sudo apt install python3-pip && pip3 install semgrep
```

#### 🍏 macOS
```bash
# 1. Install Go
brew install go
# 2. Install Ollama & Models
brew install --cask ollama
ollama run qwen2.5-coder:7b
# 3. Supplemental Tools
brew install semgrep
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2
```

#### 🪟 Windows (Native or PowerShell)
```powershell
# 1. Install Go
winget install GoLang.Go
# 2. Install Ollama & Models
# Download & Run installer from https://ollama.com/download/windows
ollama run qwen2.5-coder:7b
# 3. Supplemental Tools
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2
# 4. Install Semgrep (Requires Python)
#    a. Install Python: winget install Python.Python.3.11
#    b. Set Encoding: [System.Environment]::SetEnvironmentVariable('PYTHONUTF8', '1', 'Machine')
#    c. Install Semgrep: pip install --upgrade semgrep
```

### Step 2: Run the Scanner
```bash
go run ./cmd/scanner
```

---

## ⚙️ The Elite AI Menu (Option 2)

We have upgraded the scan pipeline with 6 distinct modes:

1. **AI Validation Only**: Takes static findings and asks AI if they are real.
2. **AI Discovery Only**: AI hunts for vulnerabilities the static rules might miss.
3. **AI Discovery + Validate**: Find new issues AND double-check all of them.
4. **Static + AI + Validate**: The "Everything" mode. Sequential and thorough.
5. **Consolidated AI + Static**: **(Recommended)** Runs both, stashes results in a local DB, and merges them semantically into one clean report.
6. **Disable AI**: Standard static scanning only.

---

## 📂 Project Structure

- **[`ai/`](./ai)**: 
  - `discovery_scanner.go` — The "Guru" prompt with CoT and Taint-Flow simulation.
  - `validator.go` — Adversarial bypass simulation engine.
  - `merging_engine.go` — Semantic deduplication and finding correlation.
- **[`scanner/`](./scanner)**: Pattern-matching engine, AST analyzer, and SCA logic.
- **[`reporter/`](./reporter)**: Generates HTML, PDF, and CSV reports with Risk Scoring.
- **[`rules/`](./rules)**: YAML security rules (You can add rules in this directory).

---

## 🚿 How False Positives Are Killed
1. **Context Filtering:** Automatically ignores comments and test/mock files.
2. **Adversarial Bypass Sim:** The AI tries to "hack" the fix to ensure it works.
3. **Taint-Flow Simulation:** AI traces the path of data from request to database.
4. **Local DB Stashing:** Intermediate results are saved to `.findings_stashed.json` to prevent data loss.

---

## 📊 Output Formats

The scanner generates multiple report formats so you can share results with any audience:

| Format | File | Description |
| :--- | :--- | :--- |
| **HTML** | `report.html` | Interactive, styled report with filtering and charts. |
| **PDF** | `report.pdf` | Printable executive summary for stakeholders. |
| **CSV** | `report.csv` | Importable into Excel, Jira, or any ticketing system. |
| **Web Dashboard** | `localhost:8080` | Live, auto-refreshing browser dashboard with Chart.js analytics. |
| **JSON (Stashed)** | `.findings_stashed.json` | Machine-readable local DB for consecutive scans. |

---

## ⌨️ CLI Flags & Configuration

You can bypass the interactive menu entirely using CLI flags:

```bash
go run ./cmd/scanner -d /path/to/your/code -ai -semgrep -consolidated
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-d` | *(required)* | Target directory to scan. |
| `-r` | `rules` | Path to custom rules directory. |
| `-ai` | `false` | Enable AI validation via local Ollama LLM. |
| `-ai-discovery` | `false` | Enable AI-powered vulnerability discovery. |
| `-semgrep` | `false` | Enable Semgrep community rules. |
| `-deps` | `true` | Enable dependency/SCA scanning. |
| `-secrets` | `true` | Enable secret detection. |
| `-supply-chain` | `false` | Enable SBOM generation. |
| `-compliance` | `false` | Enable compliance checking. |
| `-threat-intel` | `false` | Enable threat intelligence enrichment. |
| `-ml-fp` | `false` | Enable ML false-positive reduction. |
| `-consolidated` | `false` | Enable Consolidated AI + Static intelligence. |
| `-model` | `qwen2.5-coder:7b` | AI model name (any Ollama model). |
| `-ollama-host` | `localhost:11434` | Ollama host:port (for remote AI). |
| `-csv` | `report.csv` | Output CSV report file path. |
| `-html` | `report.html` | Output HTML report file path. |
| `-pdf` | `report.pdf` | Output PDF report file path. |
| `-frameworks` | *(none)* | Comma-separated: `PCI-DSS,HIPAA,SOC2,ISO27001,GDPR` |

**Changing the AI Model:** Pull any Ollama model, then pass it via the `-model` flag:
```bash
ollama pull llama3
go run ./cmd/scanner -d ./myapp -ai -model llama3
```

---

## 🔄 Architecture / Workflow

```
┌─────────────────┐
│  Source Code    │
└───────┬─────────┘
        ▼
┌─────────────────┐     ┌──────────────────┐
│ Static Engine   │────▶│  Pattern Matching│(928 YAML rules)
│ (Pattern + AST  │     │  AST Analysis    │(Tree-sitter)
│  + Taint Flow)  │     │  Taint Tracking  │(Source → Sink)
└───────┬─────────┘     └──────────────────┘
        ▼
┌─────────────────┐     ┌──────────────────┐
│ Supplemental    │────▶│  OSV-Scanner     │(SCA/Dependencies)
│ Engines         │     │  Semgrep         │(Community Rules)
│                 │     │  Secret Detector │(Entropy Analysis)
└───────┬─────────┘     └──────────────────┘
        ▼
┌─────────────────┐     ┌──────────────────┐
│ AI Layer        │────▶│  Discovery (CoT) |(Find new vulns)
│ (Ollama LLM)    │     │  Validation      |(Adversarial sim)
│                 │     │  Merger          |(Deduplication)
└───────┬─────────┘     └──────────────────┘
        ▼
┌─────────────────┐
│ Reports         │──▶  HTML / PDF / CSV / Web Dashboard
└─────────────────┘
```

---

## 🛠️ Troubleshooting / FAQ

| Problem | Solution |
| :--- | :--- |
| **Scanner freezes at AI step** | Ensure Ollama is running: `ollama serve` in a separate terminal. |
| **"Out of memory" or slow AI** | Use a smaller model: `-model qwen2.5-coder:1.5b`. Check RAM via Option 17 (System Diagnostic). |
| **"Semgrep not found"** | The tool will safely skip it. Install via `pip install semgrep` (all OS) or `brew install semgrep` (macOS). |
| **"osv-scanner not found"** | Install via `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2`. The tool falls back to the OSV HTTP API. |
| **Windows paths look wrong** | Ensure you're on the latest version. All path handling uses `filepath.Join` for OS-native separators. |
| **Want to add custom rules?** | Create a `.yaml` file in the `rules/` directory following the existing format. It will be auto-loaded on next scan. |
| **Want remote AI?** | Run Ollama on another machine, then use `-ollama-host 192.168.1.42:11434`. |

---

## 🧪 Running Tests

The project includes a unit test suite to protect cross-platform compatibility:

```bash
go test ./... -v
```

Tests cover: newline normalization, test-file detection (Windows + Unix paths), CLI binary resolution, severity mapping, and language detection.

---

## 🤝 Contributing

Contributions are welcome! To get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and ensure tests pass: `go test ./... && go build ./...`
4. Submit a Pull Request

**Adding New Security Rules:** Simply add a `.yaml` file to the `rules/` directory (or a subdirectory). Follow the existing format with `id`, `languages`, `patterns`, `severity`, `description`, `remediation`, `cwe`, and `owasp` fields.

---

## 📄 License

This project is provided as-is for internal security research and development.