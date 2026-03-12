package reporter

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// GenerateHTMLReport generates an interactive HTML report to a file
func GenerateHTMLReport(filename string, findings []Finding, summary ReportSummary) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return GenerateHTMLReportToWriter(file, findings, summary)
}

// stripCodeFences removes markdown code fences like ```python ... ``` and returns clean code
var codeFenceRegex = regexp.MustCompile("(?m)^\\s*```[a-zA-Z]*\\s*\n?")
var closingFenceRegex = regexp.MustCompile("(?m)\n?\\s*```\\s*$")

func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	s = codeFenceRegex.ReplaceAllString(s, "")
	s = closingFenceRegex.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

// GenerateHTMLReportToWriter generates an interactive HTML report to any io.Writer
func GenerateHTMLReportToWriter(w io.Writer, findings []Finding, summary ReportSummary) error {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},
		"confidencePct": func(c float64) string {
			if c <= 0 {
				return "100%"
			}
			return fmt.Sprintf("%.0f%%", c*100)
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"splitPrefix": func(s string) string {
			parts := strings.SplitN(s, ":", 2)
			return parts[0]
		},
		"splitDesc": func(s string) string {
			parts := strings.SplitN(s, ":", 2)
			if len(parts) > 1 {
				return parts[1]
			}
			return ""
		},
		"replaceNewline": func(s string) string {
			return strings.ReplaceAll(s, "\\n", "\n")
		},
		"stripFences": func(s string) string {
			return stripCodeFences(s)
		},
		"hasCodeFence": func(s string) bool {
			return strings.Contains(s, "```")
		},
	}).Parse(htmlTemplate))

	// Simple deduplication: Key = FilePath + LineNumber + IssueName
	uniqueFindings := make([]Finding, 0)
	seen := make(map[string]bool)
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%s", f.FilePath, f.LineNumber, f.IssueName)
		if !seen[key] {
			seen[key] = true
			uniqueFindings = append(uniqueFindings, f)
		}
	}
	findings = uniqueFindings

	confirmed, falsePositives := SplitFindings(findings)

	data := struct {
		Findings       []Finding
		FalsePositives []Finding
		Summary        ReportSummary
		RiskScore      RiskScore
		PriorityMatrix PriorityMatrix
		CWECounts      []KVCount
		OWASPCounts    []KVCount
	}{
		Findings:       confirmed,
		FalsePositives: falsePositives,
		Summary:        summary,
		RiskScore:      CalculateRiskScore(findings),
		PriorityMatrix: GetPriorityMatrix(findings),
		CWECounts:      aggregateCWE(findings),
		OWASPCounts:    aggregateOWASP(findings),
	}

	return tmpl.Execute(w, data)
}

// KVCount is a key-value pair for aggregated counts
type KVCount struct {
	Key   string
	Count int
}

func aggregateCWE(findings []Finding) []KVCount {
	counts := make(map[string]int)
	for _, f := range findings {
		if f.CWE != "" && f.CWE != "N/A" {
			counts[f.CWE]++
		}
	}
	var result []KVCount
	for k, v := range counts {
		result = append(result, KVCount{Key: k, Count: v})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	if len(result) > 15 {
		result = result[:15]
	}
	return result
}

func aggregateOWASP(findings []Finding) []KVCount {
	counts := make(map[string]int)
	for _, f := range findings {
		if f.OWASP != "" && f.OWASP != "N/A" {
			counts[f.OWASP]++
		}
	}
	var result []KVCount
	for k, v := range counts {
		result = append(result, KVCount{Key: k, Count: v})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	return result
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report — {{.Summary.TargetDirectory}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1"></script>
    <style>
        :root {
            --primary: #3b82f6; --primary-dark: #2563eb; --primary-glow: rgba(59,130,246,0.12);
            --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #0ea5e9; --info: #8b5cf6;
            --success: #22c55e;
            --bg: #0b1121; --bg-card: #111827; --bg-elevated: #1a2332; --bg-hover: #1e293b;
            --text: #e2e8f0; --text-muted: #94a3b8; --text-dim: #64748b;
            --border: #1e293b; --border-active: #334155;
            --shadow: 0 1px 3px rgba(0,0,0,0.4); --shadow-lg: 0 8px 24px rgba(0,0,0,0.3);
            --radius: 10px; --radius-sm: 6px;
            --font: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            --mono: 'JetBrains Mono', 'Fira Code', monospace;
        }
        [data-theme="light"] {
            --bg: #f1f5f9; --bg-card: #ffffff; --bg-elevated: #f8fafc; --bg-hover: #f1f5f9;
            --text: #0f172a; --text-muted: #475569; --text-dim: #94a3b8;
            --border: #e2e8f0; --border-active: #cbd5e1;
            --shadow: 0 1px 3px rgba(0,0,0,0.08); --shadow-lg: 0 8px 24px rgba(0,0,0,0.08);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.6; min-height: 100vh; }
        .container { max-width: 1720px; margin: 0 auto; padding: 20px 24px; }

        /* Header */
        .header { background: var(--bg-card); padding: 24px 32px; border-radius: var(--radius); margin-bottom: 20px; border: 1px solid var(--border); box-shadow: var(--shadow); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; }
        .header h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.5px; }
        .header-meta { font-size: 0.82rem; color: var(--text-muted); margin-top: 2px; }
        .header-meta strong { color: var(--text); }
        .header-actions { display: flex; gap: 8px; }
        .btn { padding: 7px 14px; border-radius: var(--radius-sm); font-weight: 500; cursor: pointer; display: inline-flex; align-items: center; gap: 6px; transition: all 0.15s; border: 1px solid var(--border); background: var(--bg-elevated); color: var(--text); font-family: inherit; font-size: 0.82rem; }
        .btn:hover { border-color: var(--primary); background: var(--primary-glow); }

        /* Risk + Stats */
        .top-grid { display: grid; grid-template-columns: 280px 1fr; gap: 20px; margin-bottom: 20px; }
        .risk-card { background: var(--bg-card); border: 1px solid var(--border); padding: 28px; border-radius: var(--radius); box-shadow: var(--shadow); text-align: center; }
        .risk-card h3 { color: var(--text-muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 8px; }
        .risk-ring { width: 160px; height: 160px; margin: 8px auto; position: relative; }
        .risk-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
        .risk-ring circle { fill: none; stroke-width: 10; stroke-linecap: round; }
        .risk-ring .bg { stroke: var(--border); }
        .risk-ring .fill { transition: stroke-dashoffset 1.5s ease; }
        .risk-value { position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); font-size: 2.6rem; font-weight: 800; font-family: var(--mono); }
        .risk-label { font-size: 0.9rem; color: var(--text-muted); margin-top: 4px; font-weight: 500; }

        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; }
        .stat-card { background: var(--bg-card); border: 1px solid var(--border); padding: 18px 14px; border-radius: var(--radius-sm); box-shadow: var(--shadow); text-align: center; transition: transform 0.2s; position: relative; overflow: hidden; }
        .stat-card:hover { transform: translateY(-2px); }
        .stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }
        .stat-card.critical::before { background: var(--critical); }
        .stat-card.high::before { background: var(--high); }
        .stat-card.medium::before { background: var(--medium); }
        .stat-card.low::before { background: var(--low); }
        .stat-card.total::before { background: var(--primary); }
        .stat-card.ai-stat::before { background: var(--success); }
        .stat-value { font-size: 2rem; font-weight: 800; font-family: var(--mono); }
        .stat-value.critical { color: var(--critical); }
        .stat-value.high { color: var(--high); }
        .stat-value.medium { color: var(--medium); }
        .stat-value.low { color: var(--low); }
        .stat-label { color: var(--text-dim); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; margin-top: 2px; }

        /* Priority Matrix */
        .priority-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 12px; }
        .priority-card { padding: 18px; border-radius: var(--radius-sm); border: 1px solid var(--border); text-align: center; }
        .priority-card.p0 { border-color: rgba(239,68,68,0.4); background: rgba(239,68,68,0.06); }
        .priority-card.p1 { border-color: rgba(249,115,22,0.4); background: rgba(249,115,22,0.06); }
        .priority-card.p2 { border-color: rgba(234,179,8,0.4); background: rgba(234,179,8,0.06); }
        .priority-card.p3 { border-color: rgba(14,165,233,0.4); background: rgba(14,165,233,0.06); }
        .priority-card h4 { font-size: 0.75rem; margin-bottom: 4px; font-weight: 600; color: var(--text-muted); }
        .priority-card .count { font-size: 2rem; font-weight: 800; font-family: var(--mono); }
        .priority-card .desc { color: var(--text-dim); font-size: 0.72rem; margin-top: 2px; }

        /* Charts */
        .charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .chart-card { background: var(--bg-card); border: 1px solid var(--border); padding: 24px; border-radius: var(--radius); box-shadow: var(--shadow); }
        .chart-card h3 { margin-bottom: 12px; font-weight: 600; font-size: 0.95rem; }
        .chart-wrap { height: 280px; position: relative; }

        /* CWE/OWASP */
        .ref-section { margin-bottom: 20px; background: var(--bg-card); padding: 24px; border-radius: var(--radius); border: 1px solid var(--border); box-shadow: var(--shadow); }
        .ref-section h2 { margin-bottom: 16px; font-weight: 700; font-size: 1.1rem; }
        .ref-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
        .ref-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        .ref-table th { text-align: left; padding: 6px 8px; border-bottom: 2px solid var(--border); color: var(--text-dim); font-weight: 600; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.5px; }
        .ref-table td { padding: 8px; border-bottom: 1px solid var(--border); }
        .ref-badge { border: 1px solid var(--border); border-radius: 4px; padding: 2px 6px; background: var(--bg-elevated); font-family: var(--mono); font-size: 0.78rem; white-space: nowrap; }

        /* Filters */
        .filters { background: var(--bg-card); border: 1px solid var(--border); padding: 14px 20px; border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 16px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .filters label { font-weight: 600; font-size: 0.82rem; color: var(--text-muted); }
        .filters input, .filters select { padding: 8px 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 0.82rem; min-width: 160px; background: var(--bg); color: var(--text); font-family: inherit; transition: border-color 0.2s; }
        .filters input:focus, .filters select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 2px var(--primary-glow); }
        .result-count { margin-left: auto; color: var(--text-dim); font-size: 0.8rem; font-weight: 500; }
        .pagination { display: flex; align-items: center; gap: 6px; margin-left: 12px; }
        .pagination button { padding: 6px 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--bg); color: var(--text); cursor: pointer; font-family: inherit; font-weight: 500; font-size: 0.8rem; transition: all 0.15s; }
        .pagination button:hover:not(:disabled) { border-color: var(--primary); }
        .pagination button:disabled { opacity: 0.3; cursor: not-allowed; }
        .pagination span { color: var(--text-muted); font-size: 0.8rem; }

        /* Table */
        .table-container { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        thead { background: var(--bg-elevated); border-bottom: 1px solid var(--border); }
        th { padding: 10px 10px; text-align: left; font-weight: 600; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-dim); cursor: pointer; user-select: none; white-space: nowrap; }
        th:hover { color: var(--text); }
        th .sort-icon { margin-left: 3px; opacity: 0.4; font-size: 0.65rem; }
        td { padding: 10px; border-bottom: 1px solid var(--border); font-size: 0.82rem; vertical-align: top; }
        tr { transition: background 0.15s; }

        .severity-badge { display: inline-flex; align-items: center; padding: 3px 10px; border-radius: 16px; font-weight: 600; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.3px; }
        .severity-badge.critical { background: rgba(239,68,68,0.15); color: #f87171; }
        .severity-badge.high { background: rgba(249,115,22,0.15); color: #fb923c; }
        .severity-badge.medium { background: rgba(234,179,8,0.15); color: #fbbf24; }
        .severity-badge.low { background: rgba(14,165,233,0.15); color: #38bdf8; }
        .severity-badge.info { background: rgba(139,92,246,0.15); color: #a78bfa; }

        .source-badge { display: inline-flex; padding: 2px 7px; border-radius: 4px; font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
        .source-badge.ai { background: rgba(139,92,246,0.15); color: #a78bfa; }
        .source-badge.semgrep { background: rgba(34,197,94,0.15); color: #4ade80; }
        .source-badge.custom { background: rgba(99,102,241,0.15); color: #818cf8; }
        .source-badge.secret { background: rgba(249,115,22,0.15); color: #fb923c; }

        .ai-badge { display: inline-flex; align-items: center; font-size: 0.78rem; }

        .conf-bar { display: flex; align-items: center; gap: 5px; }
        .conf-fill { height: 5px; border-radius: 3px; min-width: 6px; }
        .conf-high { background: #22c55e; }
        .conf-med { background: #eab308; }
        .conf-low { background: #ef4444; }
        .conf-text { font-size: 0.72rem; color: var(--text-dim); font-family: var(--mono); }

        .cell-file { font-family: var(--mono); font-size: 0.74rem; color: var(--text-muted); max-width: 260px; word-break: break-all; }
        .cell-line { font-family: var(--mono); font-size: 0.78rem; color: var(--text-muted); text-align: center; }
        .cell-desc { max-width: 320px; }

        /* Expandable rows */
        .expandable-content { display: none; padding: 24px; background: var(--bg-elevated); border-top: 1px solid var(--border); }
        .row-expanded .expandable-content { display: block; animation: slideDown 0.25s ease; }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
        .main-row { cursor: pointer; transition: background-color 0.15s; }
        .main-row:hover { background-color: var(--bg-hover); }
        .row-expanded .main-row { background-color: var(--bg-hover); }

        .toggle-icon { font-size: 0.9rem; transition: transform 0.25s; color: var(--primary); display: inline-block; width: 18px; text-align: center; }
        .row-expanded .toggle-icon { transform: rotate(90deg); }

        /* Detail sections inside expanded rows */
        .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; }
        .detail-section { margin-bottom: 16px; }
        .detail-section h4 { color: var(--text-dim); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; font-weight: 700; display: flex; align-items: center; gap: 6px; }
        .detail-text { font-size: 0.88rem; line-height: 1.65; color: var(--text); white-space: pre-wrap; }

        /* Code blocks with copy button */
        .code-wrapper { position: relative; margin: 8px 0 16px; }
        .code-block { background: #0d1117; color: #c9d1d9; padding: 16px; border-radius: 8px; font-family: var(--mono); font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; word-break: break-word; border: 1px solid #21262d; line-height: 1.5; }
        .code-block.exploit { border-left: 3px solid var(--critical); }
        .code-block.secure { border-left: 3px solid var(--success); }
        .code-block.snippet { border-left: 3px solid var(--primary); }
        .code-block.remediation { border-left: 3px solid var(--medium); }
        .copy-btn { position: absolute; top: 8px; right: 8px; padding: 4px 10px; border-radius: 4px; border: 1px solid #30363d; background: #161b22; color: #8b949e; cursor: pointer; font-family: var(--mono); font-size: 0.7rem; transition: all 0.15s; z-index: 2; }
        .copy-btn:hover { background: #21262d; color: #c9d1d9; border-color: #484f58; }
        .copy-btn.copied { background: rgba(34,197,94,0.2); color: #4ade80; border-color: rgba(34,197,94,0.4); }

        /* False positives */
        .fp-section { margin-top: 32px; padding: 24px; background: var(--bg-card); border: 1px solid rgba(234,179,8,0.25); border-radius: var(--radius); box-shadow: var(--shadow); }
        .fp-section h2 { color: #fbbf24; margin-bottom: 6px; font-size: 1.15rem; }
        .fp-section p { color: var(--text-muted); margin-bottom: 16px; font-size: 0.85rem; }

        /* Footer */
        .footer { text-align: center; padding: 32px 20px; color: var(--text-dim); font-size: 0.8rem; margin-top: 16px; border-top: 1px solid var(--border); }

        @media (max-width: 1200px) { .top-grid { grid-template-columns: 1fr; } .charts-row { grid-template-columns: 1fr; } .ref-grid { grid-template-columns: 1fr; } .priority-grid { grid-template-columns: repeat(2, 1fr); } .detail-grid { grid-template-columns: 1fr; } }
        @media (max-width: 768px) { .header { flex-direction: column; text-align: center; } .filters { flex-direction: column; align-items: stretch; } .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        @media print { .header-actions, .filters, .pagination { display: none !important; } }
    </style>
</head>
<body>
<div class="container" id="report-content">
    <div class="header">
        <div>
            <h1>Security Scan Report</h1>
            <div class="header-meta">
                <strong>Target:</strong> {{.Summary.TargetDirectory}} &nbsp;|&nbsp;
                <strong>Date:</strong> {{.Summary.ScanDate}} &nbsp;|&nbsp;
                <strong>Scanner:</strong> v{{.Summary.ScannerVersion}}
            </div>
        </div>
        <div class="header-actions">
            <button class="btn" onclick="toggleTheme()">Theme</button>
            <button class="btn" id="exportBtn" onclick="exportPDF()">Export PDF</button>
        </div>
    </div>

    <!-- Risk Score + Stats -->
    <div class="top-grid">
        <div class="risk-card">
            <h3>Security Score</h3>
            <div class="risk-ring">
                <svg viewBox="0 0 200 200">
                    <circle class="bg" cx="100" cy="100" r="85"/>
                    <circle class="fill" cx="100" cy="100" r="85"
                        stroke="{{if eq .RiskScore.Level "Critical Risk"}}#ef4444{{else if eq .RiskScore.Level "High Risk"}}#f97316{{else if eq .RiskScore.Level "Medium Risk"}}#eab308{{else}}#22c55e{{end}}"
                        stroke-dasharray="534" stroke-dashoffset="534"/>
                </svg>
                <div class="risk-value" style="color:{{if eq .RiskScore.Level "Critical Risk"}}#ef4444{{else if eq .RiskScore.Level "High Risk"}}#f97316{{else if eq .RiskScore.Level "Medium Risk"}}#eab308{{else}}#22c55e{{end}}">{{.RiskScore.Score}}</div>
            </div>
            <div class="risk-label">{{.RiskScore.Level}}</div>
        </div>
        <div>
            <div class="stats-grid">
                <div class="stat-card total"><div class="stat-value" style="color:var(--primary)">{{.Summary.TotalFindings}}</div><div class="stat-label">Total</div></div>
                <div class="stat-card critical"><div class="stat-value critical">{{.Summary.CriticalCount}}</div><div class="stat-label">Critical</div></div>
                <div class="stat-card high"><div class="stat-value high">{{.Summary.HighCount}}</div><div class="stat-label">High</div></div>
                <div class="stat-card medium"><div class="stat-value medium">{{.Summary.MediumCount}}</div><div class="stat-label">Medium</div></div>
                <div class="stat-card low"><div class="stat-value low">{{.Summary.LowCount}}</div><div class="stat-label">Low</div></div>
                <div class="stat-card ai-stat"><div class="stat-value" style="color:var(--success)">{{.Summary.AIValidatedCount}}</div><div class="stat-label">AI Validated</div></div>
            </div>
            <div class="priority-grid">
                <div class="priority-card p0"><h4>P0 — Immediate</h4><div class="count" style="color:var(--critical)">{{len .PriorityMatrix.P0}}</div><div class="desc">Critical + AI confirmed</div></div>
                <div class="priority-card p1"><h4>P1 — This Sprint</h4><div class="count" style="color:var(--high)">{{len .PriorityMatrix.P1}}</div><div class="desc">High priority</div></div>
                <div class="priority-card p2"><h4>P2 — Next Sprint</h4><div class="count" style="color:var(--medium)">{{len .PriorityMatrix.P2}}</div><div class="desc">Medium priority</div></div>
                <div class="priority-card p3"><h4>P3 — Backlog</h4><div class="count" style="color:var(--low)">{{len .PriorityMatrix.P3}}</div><div class="desc">Low priority</div></div>
            </div>
        </div>
    </div>

    <!-- Charts -->
    <div class="charts-row">
        <div class="chart-card">
            <h3>Severity Distribution</h3>
            <div class="chart-wrap"><canvas id="severityChart"></canvas></div>
        </div>
        <div class="chart-card">
            <h3>Top CWE Categories</h3>
            <div class="chart-wrap"><canvas id="cweChart"></canvas></div>
        </div>
    </div>

    <!-- CWE/OWASP Cross-Reference -->
    <div class="ref-section">
        <h2>CWE / OWASP Top 10 Cross-Reference</h2>
        <div class="ref-grid">
            <div>
                <h4 style="margin-bottom: 10px; color: var(--text-dim); font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">Top CWE Categories</h4>
                <table class="ref-table">
                    <thead><tr><th>CWE ID</th><th>Count</th></tr></thead>
                    <tbody>
                    {{range .CWECounts}}
                    <tr><td><span class="ref-badge">{{splitPrefix .Key}}</span><span style="font-size: 0.82rem; color: var(--text-muted); margin-left: 6px;">{{splitDesc .Key}}</span></td><td><strong>{{.Count}}</strong></td></tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
            <div>
                <h4 style="margin-bottom: 10px; color: var(--text-dim); font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">OWASP Top 10 Mapping</h4>
                <table class="ref-table">
                    <thead><tr><th>Category</th><th>Count</th></tr></thead>
                    <tbody>
                    {{range .OWASPCounts}}
                    <tr><td><span class="ref-badge">{{splitPrefix .Key}}</span><span style="font-size: 0.82rem; color: var(--text-muted); margin-left: 6px;">{{splitDesc .Key}}</span></td><td><strong>{{.Count}}</strong></td></tr>
                    {{end}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Filters -->
    <div class="filters">
        <label>Filter:</label>
        <input type="text" id="searchInput" placeholder="Search issues, files, CWE..." oninput="filterAndPaginate()">
        <select id="severityFilter" onchange="filterAndPaginate()">
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
        </select>
        <select id="sourceFilter" onchange="filterAndPaginate()">
            <option value="">All Sources</option>
            <option value="ai">AI Discovery</option>
            <option value="semgrep">Semgrep</option>
            <option value="custom">Custom Rules</option>
            <option value="secret">Secret Detection</option>
        </select>
        <span class="result-count" id="resultCount"></span>
        <div class="pagination">
            <button onclick="prevPage()" id="prevBtn">Prev</button>
            <span id="pageInfo">1 / 1</span>
            <button onclick="nextPage()" id="nextBtn">Next</button>
        </div>
    </div>

    <!-- Findings Table -->
    <div class="table-container">
        <table id="findingsTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)"># <span class="sort-icon">⇅</span></th>
                    <th onclick="sortTable(1)">Issue <span class="sort-icon">⇅</span></th>
                    <th onclick="sortTable(2)">File Path <span class="sort-icon">⇅</span></th>
                    <th onclick="sortTable(3)">Line <span class="sort-icon">⇅</span></th>
                    <th onclick="sortTable(4)">Severity <span class="sort-icon">⇅</span></th>
                    <th onclick="sortTable(5)">CWE <span class="sort-icon">⇅</span></th>
                    <th>Source</th>
                    <th>Conf.</th>
                    <th>AI</th>
                    <th>Description</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            {{range .Findings}}
            <tbody class="finding-group">
                <tr class="main-row" data-severity="{{.Severity}}" data-source="{{.Source}}" onclick="toggleRow(this)">
                    <td style="font-weight: 600; color: var(--text-dim);"><span class="toggle-icon">▸</span> {{.SrNo}}</td>
                    <td style="font-weight: 600; font-size: 0.82rem;">{{.IssueName}}</td>
                    <td class="cell-file" title="{{.FilePath}}">{{.FilePath}}</td>
                    <td class="cell-line">{{.LineNumber}}</td>
                    <td><span class="severity-badge {{.Severity}}">{{.Severity}}</span></td>
                    <td>{{if .CWE}}<span class="ref-badge">{{.CWE}}</span>{{end}}</td>
                    <td>
                        {{if contains .Source "ai"}}<span class="source-badge ai">AI</span>
                        {{else if contains .Source "semgrep"}}<span class="source-badge semgrep">Semgrep</span>
                        {{else if contains .Source "taint"}}<span class="source-badge custom">Taint</span>
                        {{else if contains .Source "ast"}}<span class="source-badge custom">AST</span>
                        {{else if contains .Source "secret"}}<span class="source-badge secret">Secret</span>
                        {{else}}<span class="source-badge custom">Rules</span>{{end}}
                    </td>
                    <td>
                        <div class="conf-bar" title="Confidence: {{confidencePct .Confidence}}">
                            <span class="conf-fill {{if ge .Confidence 0.8}}conf-high{{else if ge .Confidence 0.5}}conf-med{{else}}conf-low{{end}}" style="width: {{confidencePct .Confidence}};"></span>
                            <span class="conf-text">{{confidencePct .Confidence}}</span>
                        </div>
                    </td>
                    <td style="text-align: center;">
                        {{if eq .AiValidated "Yes"}}<span class="ai-badge" title="AI Validated">✅</span>
                        {{else if contains .AiValidated "Discovered"}}<span class="ai-badge" title="AI Discovered">🧠</span>
                        {{else if eq .AiValidated "No"}}<span class="ai-badge" title="False Positive">❌</span>
                        {{else}}<span class="ai-badge" title="Not Checked" style="color:var(--text-dim)">—</span>{{end}}
                    </td>
                    <td class="cell-desc">{{truncate .Description 70}}</td>
                    <td class="cell-desc">{{truncate .Remediation 50}}</td>
                </tr>
                <tr class="detail-row" data-severity="{{.Severity}}" data-source="{{.Source}}" style="display: none;">
                    <td colspan="11" style="padding: 0; border-bottom: none;">
                        <div class="expandable-content">
                            <div class="detail-grid">
                                <div>
                                    <div class="detail-section">
                                        <h4>Full Description</h4>
                                        <div class="detail-text">{{.Description}}</div>
                                    </div>

                                    <div class="detail-section">
                                        <h4>Remediation / Fix</h4>
                                        {{if hasCodeFence .Remediation}}
                                        <div class="detail-text" style="margin-bottom:8px;">{{truncate .Remediation 200}}</div>
                                        <div class="code-wrapper">
                                            <button class="copy-btn" onclick="copyCode(this, event)">Copy</button>
                                            <div class="code-block remediation">{{stripFences .Remediation}}</div>
                                        </div>
                                        {{else}}
                                        <div class="detail-text">{{.Remediation}}</div>
                                        {{end}}
                                    </div>

                                    {{if .ExploitPoC}}
                                    <div class="detail-section">
                                        <h4>Exploit PoC</h4>
                                        <div class="code-wrapper">
                                            <button class="copy-btn" onclick="copyCode(this, event)">Copy</button>
                                            <div class="code-block exploit">// Proof of Concept — use responsibly
{{stripFences .ExploitPoC}}</div>
                                        </div>
                                    </div>
                                    {{end}}

                                    {{if .FixedCode}}
                                    <div class="detail-section">
                                        <h4>AI-Suggested Secure Code</h4>
                                        <div class="code-wrapper">
                                            <button class="copy-btn" onclick="copyCode(this, event)">Copy</button>
                                            <div class="code-block secure">{{stripFences .FixedCode}}</div>
                                        </div>
                                    </div>
                                    {{end}}
                                </div>

                                <div>
                                    {{if .CodeSnippet}}
                                    <div class="detail-section">
                                        <h4>Vulnerable Code Snippet</h4>
                                        <div class="code-wrapper">
                                            <button class="copy-btn" onclick="copyCode(this, event)">Copy</button>
                                            <div class="code-block snippet">{{replaceNewline .CodeSnippet}}</div>
                                        </div>
                                    </div>
                                    {{end}}

                                    <div class="detail-section" style="margin-top:16px;">
                                        <h4>Metadata</h4>
                                        <table style="font-size:0.82rem; border-collapse:collapse; width:100%;">
                                            <tr><td style="padding:6px 8px; color:var(--text-dim); border-bottom:1px solid var(--border); width:120px;">CWE</td><td style="padding:6px 8px; border-bottom:1px solid var(--border);">{{if .CWE}}{{.CWE}}{{else}}N/A{{end}}</td></tr>
                                            <tr><td style="padding:6px 8px; color:var(--text-dim); border-bottom:1px solid var(--border);">OWASP</td><td style="padding:6px 8px; border-bottom:1px solid var(--border);">{{if .OWASP}}{{.OWASP}}{{else}}N/A{{end}}</td></tr>
                                            <tr><td style="padding:6px 8px; color:var(--text-dim); border-bottom:1px solid var(--border);">Confidence</td><td style="padding:6px 8px; border-bottom:1px solid var(--border);">{{confidencePct .Confidence}}</td></tr>
                                            <tr><td style="padding:6px 8px; color:var(--text-dim); border-bottom:1px solid var(--border);">Source</td><td style="padding:6px 8px; border-bottom:1px solid var(--border);">{{.Source}}</td></tr>
                                            <tr><td style="padding:6px 8px; color:var(--text-dim); border-bottom:1px solid var(--border);">AI Validated</td><td style="padding:6px 8px; border-bottom:1px solid var(--border);">{{.AiValidated}}</td></tr>
                                            <tr><td style="padding:6px 8px; color:var(--text-dim);">File</td><td style="padding:6px 8px; font-family:var(--mono); font-size:0.78rem;">{{.FilePath}}:{{.LineNumber}}</td></tr>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </td>
                </tr>
            </tbody>
            {{end}}
        </table>
    </div>

    <!-- False Positives -->
    {{if .FalsePositives}}
    <div class="fp-section">
        <h2>Manual Review — Potential False Positives ({{len .FalsePositives}})</h2>
        <p>The following findings were flagged as <strong>potential false positives</strong> by the AI validator. Listed separately for manual review.</p>
        <div class="table-container" style="margin-top: 12px;">
            <table id="fpTable">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Issue</th>
                        <th>File Path</th>
                        <th>Severity</th>
                        <th>CWE</th>
                        <th>AI Reason</th>
                    </tr>
                </thead>
                {{range .FalsePositives}}
                <tbody class="finding-group">
                    <tr class="main-row" data-severity="{{.Severity}}" data-source="{{.Source}}" onclick="toggleRow(this)">
                        <td style="font-weight: 600; color: var(--text-dim);"><span class="toggle-icon">▸</span> {{.SrNo}}</td>
                        <td style="font-weight: 600;">{{.IssueName}}</td>
                        <td class="cell-file" title="{{.FilePath}}">{{.FilePath}}:{{.LineNumber}}</td>
                        <td><span class="severity-badge {{.Severity}}">{{.Severity}}</span></td>
                        <td>{{if .CWE}}<span class="ref-badge">{{.CWE}}</span>{{end}}</td>
                        <td class="cell-desc">{{truncate .Description 70}}</td>
                    </tr>
                    <tr class="detail-row" data-severity="{{.Severity}}" data-source="{{.Source}}" style="display: none;">
                        <td colspan="6" style="padding: 0; border-bottom: none;">
                            <div class="expandable-content">
                                <div class="detail-grid">
                                    <div>
                                        <div class="detail-section"><h4>AI False Positive Explanation</h4><div class="detail-text">{{.Description}}</div></div>
                                        <div class="detail-section"><h4>Original Remediation</h4><div class="detail-text">{{.Remediation}}</div></div>
                                    </div>
                                    <div>
                                        {{if .CodeSnippet}}
                                        <div class="detail-section">
                                            <h4>Code Snippet</h4>
                                            <div class="code-wrapper">
                                                <button class="copy-btn" onclick="copyCode(this, event)">Copy</button>
                                                <div class="code-block snippet">{{replaceNewline .CodeSnippet}}</div>
                                            </div>
                                        </div>
                                        {{end}}
                                    </div>
                                </div>
                            </div>
                        </td>
                    </tr>
                </tbody>
                {{end}}
            </table>
        </div>
    </div>
    {{end}}

    <div class="footer">
        <p><strong>Generated by AI-Powered Source Code Scanner v{{.Summary.ScannerVersion}}</strong></p>
        <p style="margin-top:4px;">{{.Summary.TotalFindings}} findings &bull; {{.Summary.CriticalCount}} critical &bull; {{.Summary.HighCount}} high &bull; {{.Summary.MediumCount}} medium &bull; {{.Summary.LowCount}} low</p>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
<script>
    // Copy code to clipboard
    function copyCode(btn, event) {
        event.stopPropagation();
        const codeBlock = btn.parentElement.querySelector('.code-block');
        const text = codeBlock.textContent;
        navigator.clipboard.writeText(text).then(() => {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
        }).catch(() => {
            // Fallback for older browsers
            const ta = document.createElement('textarea');
            ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
        });
    }

    // Theme toggle
    function toggleTheme() {
        const html = document.documentElement;
        html.setAttribute('data-theme', html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    }

    // Charts
    const chartColors = { text: '#64748b', grid: 'rgba(148,163,184,0.08)' };
    new Chart(document.getElementById('severityChart'), {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [{{.Summary.CriticalCount}}, {{.Summary.HighCount}}, {{.Summary.MediumCount}}, {{.Summary.LowCount}}, {{.Summary.InfoCount}}],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#0ea5e9', '#8b5cf6'],
                borderWidth: 0, spacing: 2, borderRadius: 3
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'right', labels: { padding: 14, usePointStyle: true, pointStyle: 'circle', color: chartColors.text, font: { family: 'Inter', size: 12 } } } },
            cutout: '68%'
        }
    });

    const cweLabels = [{{range .CWECounts}}'{{.Key}}',{{end}}];
    const cweCounts = [{{range .CWECounts}}{{.Count}},{{end}}];
    new Chart(document.getElementById('cweChart'), {
        type: 'bar',
        data: { labels: cweLabels, datasets: [{ data: cweCounts, backgroundColor: '#6366f1', borderRadius: 4, barThickness: 20 }] },
        options: {
            responsive: true, maintainAspectRatio: false, indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: chartColors.grid }, ticks: { color: chartColors.text } },
                y: { grid: { display: false }, ticks: { color: chartColors.text, font: { family: 'JetBrains Mono', size: 10 } } }
            }
        }
    });

    // Pagination & Filtering
    const PAGE_SIZE = 50;
    let currentPage = 1;
    let filteredRows = [];

    function getVisibleRows() {
        const groups = Array.from(document.querySelectorAll('#findingsTable .finding-group'));
        const search = document.getElementById('searchInput').value.toLowerCase();
        const severity = document.getElementById('severityFilter').value;
        const source = document.getElementById('sourceFilter').value;
        return groups.filter(group => {
            const mainRow = group.querySelector('.main-row');
            if (!mainRow) return false;
            const text = group.textContent.toLowerCase();
            const sev = mainRow.getAttribute('data-severity') || '';
            const src = mainRow.getAttribute('data-source') || '';
            return (!search || text.includes(search)) && (!severity || sev === severity) && (!source || src.includes(source));
        });
    }

    function toggleRow(row) {
        const tbody = row.closest('tbody');
        const isExpanded = tbody.classList.contains('row-expanded');
        if (isExpanded) {
            tbody.classList.remove('row-expanded');
            setTimeout(() => { if (!tbody.classList.contains('row-expanded')) row.nextElementSibling.style.display = 'none'; }, 250);
        } else {
            row.nextElementSibling.style.display = '';
            requestAnimationFrame(() => { tbody.classList.add('row-expanded'); });
        }
    }

    function filterAndPaginate() { currentPage = 1; filteredRows = getVisibleRows(); renderPage(); }

    function renderPage() {
        const allGroups = document.querySelectorAll('#findingsTable .finding-group');
        allGroups.forEach(g => g.style.display = 'none');
        const start = (currentPage - 1) * PAGE_SIZE;
        const end = Math.min(start + PAGE_SIZE, filteredRows.length);
        const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));
        for (let i = start; i < end; i++) filteredRows[i].style.display = '';
        document.getElementById('resultCount').textContent = filteredRows.length + ' of ' + allGroups.length + ' findings';
        document.getElementById('pageInfo').textContent = currentPage + ' / ' + totalPages;
        document.getElementById('prevBtn').disabled = currentPage <= 1;
        document.getElementById('nextBtn').disabled = currentPage >= totalPages;
    }

    function prevPage() { if (currentPage > 1) { currentPage--; renderPage(); } }
    function nextPage() { const tp = Math.ceil(filteredRows.length / PAGE_SIZE); if (currentPage < tp) { currentPage++; renderPage(); } }

    // Sorting
    let sortCol = -1, sortAsc = true;
    function sortTable(col) {
        if (sortCol === col) sortAsc = !sortAsc; else { sortCol = col; sortAsc = true; }
        const table = document.querySelector('#findingsTable');
        const groups = Array.from(table.querySelectorAll('.finding-group'));
        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        groups.sort((a, b) => {
            const rowA = a.querySelector('.main-row'), rowB = b.querySelector('.main-row');
            if (!rowA || !rowB) return 0;
            let va = rowA.cells[col]?.textContent.trim() || '', vb = rowB.cells[col]?.textContent.trim() || '';
            if (col === 4) { va = sevOrder[va.toLowerCase()] ?? 5; vb = sevOrder[vb.toLowerCase()] ?? 5; }
            else if (col === 0 || col === 3) { va = parseInt(va.replace(/[^0-9-]/g, '')) || 0; vb = parseInt(vb.replace(/[^0-9-]/g, '')) || 0; }
            if (va < vb) return sortAsc ? -1 : 1;
            if (va > vb) return sortAsc ? 1 : -1;
            return 0;
        });
        groups.forEach(g => table.appendChild(g));
        filterAndPaginate();
    }

    // PDF Export
    async function exportPDF() {
        const btn = document.getElementById('exportBtn');
        btn.disabled = true; btn.textContent = 'Generating...';
        try {
            await html2pdf().set({
                margin: [0.4, 0.4], filename: 'security-report.pdf',
                image: { type: 'jpeg', quality: 0.95 },
                html2canvas: { scale: 2, useCORS: true },
                jsPDF: { unit: 'in', format: 'letter', orientation: 'landscape' },
                pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
            }).from(document.querySelector('.container')).save();
            btn.textContent = 'Downloaded!';
        } catch(e) { alert('PDF export failed'); }
        setTimeout(() => { btn.disabled = false; btn.textContent = 'Export PDF'; }, 2000);
    }

    // Init
    document.addEventListener('DOMContentLoaded', () => { filterAndPaginate(); });

    // Risk ring animation
    setTimeout(() => {
        const fill = document.querySelector('.risk-ring .fill');
        if (fill) {
            const score = {{.RiskScore.Score}};
            const offset = 534 - (534 * score / 100);
            fill.style.strokeDashoffset = offset;
        }
    }, 300);
</script>
</body>
</html>`
