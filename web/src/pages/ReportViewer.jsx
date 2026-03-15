import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { Download, Filter, ChevronDown, ChevronUp, FileText, Code, ArrowLeft, AlertTriangle, Shield, Sparkles } from 'lucide-react'
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js'
import { Doughnut, Bar } from 'react-chartjs-2'
import SeverityBadge from '../components/SeverityBadge'

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement)

export default function ReportViewer() {
    const { id } = useParams()
    const [findings, setFindings] = useState([])
    const [scanInfo, setScanInfo] = useState(null)
    const [filter, setFilter] = useState('all')
    const [expandedRow, setExpandedRow] = useState(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetchReport()
    }, [id])

    const fetchReport = async () => {
        try {
            const [scanRes, findingsRes] = await Promise.all([
                fetch(`/api/scan/${id}`),
                fetch(`/api/scan/${id}/findings`),
            ])
            if (scanRes.ok) setScanInfo(await scanRes.json())
            if (findingsRes.ok) setFindings(await findingsRes.json() || [])
        } catch (e) {
            console.error('Failed to fetch report:', e)
        } finally {
            setLoading(false)
        }
    }

    const filtered = filter === 'all' ? findings : findings.filter(f => (f.severity || '').toLowerCase() === filter)

    // Calculate stats
    const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    findings.forEach(f => {
        const s = (f.severity || '').toLowerCase()
        if (stats[s] !== undefined) stats[s]++
    })

    // CWE distribution
    const cweCounts = {}
    findings.forEach(f => { if (f.cwe) cweCounts[f.cwe] = (cweCounts[f.cwe] || 0) + 1 })
    const topCWEs = Object.entries(cweCounts).sort((a, b) => b[1] - a[1]).slice(0, 8)

    // Compute risk score (mirrors reporter/risk_scorer.go logic)
    const riskRaw = Math.min(100, stats.critical * 10 + stats.high * 5 + stats.medium * 2 + stats.low * 0.5)
    const riskLevel = riskRaw >= 75 ? 'Critical Risk' : riskRaw >= 50 ? 'High Risk' : riskRaw >= 25 ? 'Medium Risk' : 'Low Risk'
    const riskColor = riskRaw >= 75 ? '#ef4444' : riskRaw >= 50 ? '#f97316' : riskRaw >= 25 ? '#eab308' : '#22c55e'
    const aiValidatedCount = findings.filter(f => f.ai_validated === 'Yes').length

    const sevChartData = {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
            data: [stats.critical, stats.high, stats.medium, stats.low, stats.info],
            backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#6366f1'],
            borderWidth: 0,
        }],
    }

    const cweChartData = {
        labels: topCWEs.map(c => c[0]),
        datasets: [{
            label: 'Findings',
            data: topCWEs.map(c => c[1]),
            backgroundColor: 'rgba(99, 102, 241, 0.7)',
            borderColor: '#818cf8',
            borderWidth: 1,
            borderRadius: 6,
        }],
    }

    const chartOptions = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: { labels: { color: '#94a3b8', padding: 12, usePointStyle: true } },
        },
    }

    if (loading) {
        return <div style={{ textAlign: 'center', padding: '80px', color: 'var(--text-muted)' }}>Loading report...</div>
    }

    return (
        <div className="animate-fade-in">
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1>Security Report</h1>
                    <p>{scanInfo?.target || 'Scan'} — {findings.length} findings</p>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                    <a href={`/api/scan/${id}/report/html`} download className="btn btn-secondary btn-sm">
                        <Download size={14} /> HTML
                    </a>
                    <a href={`/api/scan/${id}/report/csv`} download className="btn btn-secondary btn-sm">
                        <Download size={14} /> CSV
                    </a>
                    <a href={`/api/scan/${id}/report/pdf`} download className="btn btn-secondary btn-sm">
                        <Download size={14} /> PDF
                    </a>
                </div>
            </div>

            {/* Stats */}
            <div className="stats-grid">
                {Object.entries(stats).map(([sev, count]) => (
                    <div key={sev} className="stat-card" style={{ cursor: 'pointer' }} onClick={() => setFilter(sev)}>
                        <div className="stat-card-label">{sev}</div>
                        <div className="stat-card-value" style={{ color: `var(--severity-${sev})` }}>{count}</div>
                    </div>
                ))}
            </div>

            {/* Risk Score Card */}
            <div className="card" style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '20px 28px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                    <div style={{
                        width: 64, height: 64, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                        background: `conic-gradient(${riskColor} ${riskRaw * 3.6}deg, rgba(255,255,255,0.06) 0deg)`,
                        position: 'relative'
                    }}>
                        <div style={{
                            width: 52, height: 52, borderRadius: '50%', background: 'var(--bg-secondary)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontSize: '1.1rem', fontWeight: 800, color: riskColor
                        }}>
                            {Math.round(riskRaw)}
                        </div>
                    </div>
                    <div>
                        <div style={{ fontSize: '1rem', fontWeight: 700, color: riskColor }}>{riskLevel}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                            Security Risk Score (0-100)
                        </div>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: '24px', fontSize: '0.78rem' }}>
                    <div style={{ textAlign: 'center' }}>
                        <div style={{ fontWeight: 700, fontSize: '1.1rem', color: 'var(--text-primary)' }}>{findings.length}</div>
                        <div style={{ color: 'var(--text-muted)' }}>Total</div>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                        <div style={{ fontWeight: 700, fontSize: '1.1rem', color: '#22c55e' }}>{aiValidatedCount}</div>
                        <div style={{ color: 'var(--text-muted)' }}>AI Confirmed</div>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                        <div style={{ fontWeight: 700, fontSize: '1.1rem', color: '#ef4444' }}>{stats.critical}</div>
                        <div style={{ color: 'var(--text-muted)' }}>Critical</div>
                    </div>
                </div>
            </div>

            {/* Charts */}
            <div className="grid-2" style={{ marginBottom: '32px' }}>
                <div className="card">
                    <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '16px', textAlign: 'center', textTransform: 'uppercase', letterSpacing: '1px' }}>
                        Severity Distribution
                    </h3>
                    <div style={{ maxWidth: '280px', margin: '0 auto' }}>
                        <Doughnut data={sevChartData} options={chartOptions} />
                    </div>
                </div>
                <div className="card">
                    <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '16px', textAlign: 'center', textTransform: 'uppercase', letterSpacing: '1px' }}>
                        Top CWE Categories
                    </h3>
                    <Bar data={cweChartData} options={{ ...chartOptions, indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }, y: { ticks: { color: '#94a3b8', font: { size: 11 } }, grid: { display: false } } } }} />
                </div>
            </div>

            {/* Filter Tabs */}
            <div className="tabs" style={{ maxWidth: '500px', marginBottom: '16px' }}>
                {['all', 'critical', 'high', 'medium', 'low', 'info'].map(f => (
                    <button key={f} className={`tab ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
                        {f === 'all' ? `All (${findings.length})` : `${f} (${stats[f]})`}
                    </button>
                ))}
            </div>

            {/* Findings Table */}
            <div className="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Severity</th>
                            <th>Issue</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Trust Score</th>
                            <th>AI</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.map((f, i) => (
                            <React.Fragment key={i}>
                                <tr style={{ cursor: 'pointer' }} onClick={() => setExpandedRow(expandedRow === i ? null : i)}>
                                    <td style={{ color: 'var(--text-muted)', fontWeight: 600 }}>{f.sr_no || i + 1}</td>
                                    <td><SeverityBadge severity={f.severity} /></td>
                                    <td style={{ fontWeight: 600, maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.issue_name}</td>
                                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-accent)' }}>{f.file_path?.split('/').slice(-2).join('/')}</td>
                                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>{f.line_number}</td>
                                    <td>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <div style={{ width: '32px', height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px', overflow: 'hidden' }}>
                                                <div style={{ width: `${f.trust_score || 0}%`, height: '100%', background: (f.trust_score || 0) > 80 ? '#22c55e' : (f.trust_score || 0) > 50 ? '#eab308' : '#ef4444' }} />
                                            </div>
                                            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)' }}>{Math.round(f.trust_score || 0)}%</span>
                                        </div>
                                    </td>
                                    <td>
                                        {f.ai_validated === 'Yes' ? <span style={{ color: 'var(--status-success)', fontWeight: 600, fontSize: '0.78rem' }}>✓ TP</span>
                                            : f.ai_validated?.includes('False') ? <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>✗ FP</span>
                                                : <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>—</span>}
                                    </td>
                                    <td>{expandedRow === i ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</td>
                                </tr>
                                {expandedRow === i && (
                                    <tr>
                                        <td colSpan={8} style={{ background: 'var(--bg-elevated)', padding: '20px' }}>
                                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
                                                <div>
                                                    <h4 style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                                        <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><FileText size={14} /> Description</span>
                                                        <button
                                                            className="btn btn-primary btn-sm"
                                                            style={{ padding: '4px 10px', fontSize: '0.7rem' }}
                                                            onClick={(e) => {
                                                                e.stopPropagation();
                                                                const event = new CustomEvent('qwen-chat-open', {
                                                                    detail: {
                                                                        content: `Explain this finding in detail:\nIssue: ${f.issue_name}\nFile: ${f.file_path}\nDescription: ${f.description}\nCWE: ${f.cwe}`,
                                                                        autoSend: true
                                                                    }
                                                                });
                                                                window.dispatchEvent(event);
                                                            }}
                                                        >
                                                            <Sparkles size={12} /> Explain with AI
                                                        </button>
                                                    </h4>
                                                    <p style={{ fontSize: '0.85rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>{f.description}</p>

                                                    {f.ai_reasoning && (
                                                        <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(99, 102, 241, 0.05)', borderRadius: '8px', borderLeft: '3px solid #6366f1' }}>
                                                            <h4 style={{ fontSize: '0.75rem', color: '#818cf8', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 700 }}>AI Reasoning Insight</h4>
                                                            <p style={{ fontSize: '0.82rem', lineHeight: 1.5, color: '#94a3b8', fontStyle: 'italic' }}>"{f.ai_reasoning}"</p>
                                                        </div>
                                                    )}
                                                </div>
                                                <div>
                                                    <h4 style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                        <Shield size={14} /> Remediation
                                                    </h4>
                                                    <p style={{ fontSize: '0.85rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>{f.remediation || 'No remediation provided.'}</p>

                                                    {f.exploit_path && f.exploit_path.length > 0 && (
                                                        <div style={{ marginTop: '16px' }}>
                                                            <h4 style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '10px', fontWeight: 700 }}>Exploit Path Detection</h4>
                                                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
                                                                {f.exploit_path.map((step, idx) => (
                                                                    <div key={idx} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                                                                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '12px' }}>
                                                                            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: idx === 0 ? '#ef4444' : idx === f.exploit_path.length - 1 ? '#ef4444' : 'var(--text-muted)', zIndex: 1, marginTop: '4px' }} />
                                                                            {idx < f.exploit_path.length - 1 && <div style={{ width: '2px', height: '24px', background: 'var(--border-primary)', margin: '-2px 0' }} />}
                                                                        </div>
                                                                        <div style={{ fontSize: '0.78rem', color: idx === 0 || idx === f.exploit_path.length - 1 ? 'var(--text-primary)' : 'var(--text-muted)', paddingBottom: '12px' }}>
                                                                            {step}
                                                                        </div>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>

                                            {f.exploit_poc && f.exploit_poc !== "N/A" && (
                                                <div style={{ marginTop: '20px' }}>
                                                    <h4 style={{ fontSize: '0.78rem', color: '#f87171', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 700 }}>AI-Generated Concept Exploit (PoC)</h4>
                                                    <pre style={{ background: '#1a1010', padding: '12px', borderRadius: '8px', fontSize: '0.78rem', overflow: 'auto', border: '1px solid #450a0a', color: '#fca5a5' }}>
                                                        <code>{f.exploit_poc}</code>
                                                    </pre>
                                                </div>
                                            )}

                                            {f.fixed_code && (
                                                <div style={{ marginTop: '16px' }}>
                                                    <h4 style={{ fontSize: '0.78rem', color: '#4ade80', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 700 }}>Secure Implementation Reference</h4>
                                                    <pre style={{ background: '#0a1410', padding: '12px', borderRadius: '8px', fontSize: '0.8rem', overflow: 'auto', border: '1px solid #064e3b', color: '#6ee7b7' }}>
                                                        <code>{f.fixed_code}</code>
                                                    </pre>
                                                </div>
                                            )}

                                            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-primary)', paddingTop: '12px' }}>
                                                <div style={{ display: 'flex', gap: '16px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                                    <span>Source: <strong style={{ color: 'var(--text-secondary)' }}>{f.source}</strong></span>
                                                    {f.cwe && <span>CWE: <strong style={{ color: 'var(--text-secondary)' }}>{f.cwe}</strong></span>}
                                                    {f.owasp && <span>OWASP: <strong style={{ color: 'var(--text-secondary)' }}>{f.owasp}</strong></span>}
                                                </div>
                                                <div style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                                                    Multi-Engine Trust Score: <span style={{ color: (f.trust_score || 0) > 80 ? '#22c55e' : (f.trust_score || 0) > 50 ? '#eab308' : '#ef4444' }}>{Math.round(f.trust_score || 0)}%</span>
                                                </div>
                                            </div>
                                        </td>
                                    </tr>
                                )}
                            </React.Fragment>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}
