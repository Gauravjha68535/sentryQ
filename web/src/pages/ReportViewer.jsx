import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { Download, Filter, ChevronDown, ChevronUp, FileText, Code, ArrowLeft } from 'lucide-react'
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

    const filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter)

    // Calculate stats
    const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    findings.forEach(f => { if (stats[f.severity] !== undefined) stats[f.severity]++ })

    // CWE distribution
    const cweCounts = {}
    findings.forEach(f => { if (f.cwe) cweCounts[f.cwe] = (cweCounts[f.cwe] || 0) + 1 })
    const topCWEs = Object.entries(cweCounts).sort((a, b) => b[1] - a[1]).slice(0, 8)

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
                            <th>CWE</th>
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
                                    <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{f.cwe || '—'}</td>
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
                                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                                                <div>
                                                    <h4 style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>Description</h4>
                                                    <p style={{ fontSize: '0.85rem', lineHeight: 1.6 }}>{f.description}</p>
                                                </div>
                                                <div>
                                                    <h4 style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>Remediation</h4>
                                                    <p style={{ fontSize: '0.85rem', lineHeight: 1.6 }}>{f.remediation || 'No remediation provided.'}</p>
                                                </div>
                                            </div>
                                            {f.fixed_code && (
                                                <div style={{ marginTop: '12px' }}>
                                                    <h4 style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>Suggested Fix</h4>
                                                    <pre style={{ background: '#0a0c14', padding: '12px', borderRadius: '8px', fontSize: '0.8rem', overflow: 'auto', border: '1px solid var(--border-primary)' }}>
                                                        <code>{f.fixed_code}</code>
                                                    </pre>
                                                </div>
                                            )}
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
