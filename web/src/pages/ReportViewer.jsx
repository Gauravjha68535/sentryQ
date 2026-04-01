import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { Download, Filter, ChevronDown, ChevronUp, FileText, Code, ArrowLeft, AlertTriangle, Shield, Layers } from 'lucide-react'
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
    const [reportPhase, setReportPhase] = useState('final') // 'final', 'static', 'ai'
    const [isEnsemble, setIsEnsemble] = useState(false)
    const [statusFilter, setStatusFilter] = useState('all') // 'all', 'open', 'resolved', 'ignored', 'false_positive'
    const [searchQuery, setSearchQuery] = useState('')
    const [selectedIds, setSelectedIds] = useState(new Set())

    useEffect(() => {
        fetchReport()
    }, [id])

    const fetchReport = async (phase = 'final') => {
        try {
            const phaseParam = phase && phase !== 'final' ? `?phase=${phase}` : ''
            const [scanRes, findingsRes] = await Promise.all([
                fetch(`/api/scan/${id}`),
                fetch(`/api/scan/${id}/findings${phaseParam}`),
            ])
            if (scanRes.ok) {
                const scanData = await scanRes.json()
                setScanInfo(scanData)
                // Check if this is an ensemble scan
                try {
                    const cfg = JSON.parse(scanData.config || '{}')
                    setIsEnsemble(!!cfg.enableEnsemble)
                } catch (e) { /* ignore */ }
            }
            if (findingsRes.ok) setFindings(await findingsRes.json() || [])
        } catch (e) {
            console.error('Failed to fetch report:', e)
        } finally {
            setLoading(false)
        }
    }

    const updateFindingStatus = async (dbId, newStatus) => {
        try {
            const res = await fetch(`/api/scan/${id}/finding/${dbId}/status`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus })
            })
            if (res.ok) {
                // Update local state
                setFindings(prev => prev.map(f => f.db_id === dbId ? { ...f, status: newStatus } : f))
            }
        } catch (e) { console.error('Failed to update status:', e) }
    }

    const bulkUpdateStatus = async (newStatus) => {
        const ids = [...selectedIds]
        if (ids.length === 0) return
        try {
            const res = await fetch(`/api/scan/${id}/findings/bulk-status`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ids, status: newStatus })
            })
            if (res.ok) {
                setFindings(prev => prev.map(f => selectedIds.has(f.db_id) ? { ...f, status: newStatus } : f))
                setSelectedIds(new Set())
            }
        } catch (e) { console.error('Bulk update failed:', e) }
    }

    const toggleSelect = (dbId) => {
        setSelectedIds(prev => {
            const next = new Set(prev)
            next.has(dbId) ? next.delete(dbId) : next.add(dbId)
            return next
        })
    }

    const toggleSelectAll = () => {
        if (selectedIds.size === filtered.length) {
            setSelectedIds(new Set())
        } else {
            setSelectedIds(new Set(filtered.map(f => f.db_id)))
        }
    }

    const filtered = findings.filter(f => {
        const matchesSeverity = filter === 'all' || (f.severity || '').toLowerCase() === filter
        const matchesStatus = statusFilter === 'all' || (f.status || 'open') === statusFilter
        const q = searchQuery.toLowerCase()
        const matchesSearch = !q ||
            (f.issue_name || '').toLowerCase().includes(q) ||
            (f.file_path || '').toLowerCase().includes(q) ||
            (f.description || '').toLowerCase().includes(q) ||
            (f.cwe || '').toLowerCase().includes(q)
        return matchesSeverity && matchesStatus && matchesSearch
    })

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
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
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
                    <a href={`/api/scan/${id}/report/sarif`} download className="btn btn-secondary btn-sm">
                        <Download size={14} /> SARIF
                    </a>
                </div>
            </div>

            {/* Ensemble Phase Tabs */}
            {isEnsemble && (
                <div style={{ marginBottom: '20px' }}>
                    <div style={{ display: 'flex', gap: '8px', padding: '4px', background: 'var(--bg-tertiary)', borderRadius: '10px', width: 'fit-content' }}>
                        {[
                            { key: 'final', label: '⚖️ Final Report (Judge)', color: '#f59e0b' },
                            { key: 'static', label: '📊 Static Report', color: '#6366f1' },
                            { key: 'ai', label: '🤖 AI Report', color: '#22c55e' },
                        ].map(tab => (
                            <button
                                key={tab.key}
                                onClick={() => { setReportPhase(tab.key); setLoading(true); fetchReport(tab.key) }}
                                style={{
                                    padding: '8px 16px', borderRadius: '8px', border: 'none', cursor: 'pointer',
                                    fontSize: '0.78rem', fontWeight: 600, transition: 'all 0.2s',
                                    background: reportPhase === tab.key ? tab.color : 'transparent',
                                    color: reportPhase === tab.key ? '#fff' : 'var(--text-muted)',
                                }}
                            >
                                {tab.label}
                            </button>
                        ))}
                    </div>
                    <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                        {reportPhase === 'final' && 'Showing the merged master report after AI Judge deduplication.'}
                        {reportPhase === 'static' && 'Showing raw findings from Phase 1: Static Expert (regex, AST, taint, deps, etc).'}
                        {reportPhase === 'ai' && 'Showing raw findings from Phase 2: AI Expert (LLM-based discovery).'}
                    </p>
                </div>
            )}

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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div className="tabs" style={{ maxWidth: '500px', margin: 0 }}>
                    {['all', 'critical', 'high', 'medium', 'low', 'info'].map(f => (
                        <button key={f} className={`tab ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
                            {f === 'all' ? `All (${findings.length})` : `${f} (${stats[f]})`}
                        </button>
                    ))}
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <input
                        type="text"
                        placeholder="Search issues, files, CWEs..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)', border: '1px solid var(--border-primary)', borderRadius: '6px', padding: '4px 10px', fontSize: '0.75rem', outline: 'none', width: '200px' }}
                    />
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>STATUS:</span>
                    <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)', border: '1px solid var(--border-primary)', borderRadius: '6px', padding: '4px 8px', fontSize: '0.75rem', outline: 'none' }}
                    >
                        <option value="all">All Status</option>
                        <option value="open">Open</option>
                        <option value="resolved">Resolved</option>
                        <option value="ignored">Ignored</option>
                        <option value="false_positive">False Positive</option>
                    </select>
                </div>
            </div>

            {/* Bulk Action Bar */}
            {selectedIds.size > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px', padding: '8px 14px', background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: '8px' }}>
                    <span style={{ fontSize: '0.8rem', color: '#818cf8', fontWeight: 600 }}>{selectedIds.size} selected</span>
                    {[['Open', 'open', '#6366f1'], ['Resolved', 'resolved', '#22c55e'], ['Ignored', 'ignored', '#94a3b8'], ['False Positive', 'false_positive', '#f59e0b']].map(([label, val, color]) => (
                        <button key={val} onClick={() => bulkUpdateStatus(val)}
                            style={{ padding: '3px 10px', fontSize: '0.75rem', borderRadius: '5px', border: `1px solid ${color}40`, background: `${color}18`, color, cursor: 'pointer', fontWeight: 600 }}>
                            Mark {label}
                        </button>
                    ))}
                    <button onClick={() => setSelectedIds(new Set())} style={{ marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}>Clear</button>
                </div>
            )}

            {/* Findings Table */}
            <div className="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style={{ width: '32px' }}>
                                <input type="checkbox"
                                    checked={filtered.length > 0 && selectedIds.size === filtered.length}
                                    onChange={toggleSelectAll}
                                    onClick={e => e.stopPropagation()}
                                />
                            </th>
                            <th>#</th>
                            <th>Severity</th>
                            <th>Issue</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Trust Score</th>
                            <th>AI</th>
                            <th>Status</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.map((f, i) => (
                            <React.Fragment key={i}>
                                <tr style={{ cursor: 'pointer' }} onClick={() => setExpandedRow(expandedRow === i ? null : i)}>
                                    <td onClick={e => e.stopPropagation()}>
                                        <input type="checkbox"
                                            checked={selectedIds.has(f.db_id)}
                                            onChange={() => toggleSelect(f.db_id)}
                                        />
                                    </td>
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
                                    <td>
                                        <select 
                                            value={f.status || 'open'} 
                                            onClick={(e) => e.stopPropagation()}
                                            onChange={(e) => updateFindingStatus(f.db_id, e.target.value)}
                                            style={{ 
                                                background: f.status === 'resolved' ? 'rgba(34, 197, 94, 0.1)' : f.status === 'false_positive' ? 'rgba(148, 163, 184, 0.1)' : 'transparent',
                                                color: f.status === 'resolved' ? '#22c55e' : f.status === 'false_positive' ? '#94a3b8' : 'var(--text-primary)',
                                                border: '1px solid var(--border-primary)',
                                                borderRadius: '4px',
                                                fontSize: '0.7rem',
                                                padding: '2px 4px',
                                                fontWeight: 600
                                            }}
                                        >
                                            <option value="open">OPEN</option>
                                            <option value="resolved">FIXED</option>
                                            <option value="ignored">IGNORE</option>
                                            <option value="false_positive">FP</option>
                                        </select>
                                    </td>
                                    <td>{expandedRow === i ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</td>
                                </tr>
                                {expandedRow === i && (
                                    <tr>
                                        <td colSpan={9} style={{ background: 'var(--bg-elevated)', padding: '20px' }}>

                                            {/* Description */}
                                            <div style={{ marginBottom: '16px' }}>
                                                <h4 style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                    <FileText size={14} /> Description
                                                </h4>
                                                <p style={{ fontSize: '0.85rem', lineHeight: 1.6, color: 'var(--text-secondary)', wordBreak: 'break-word', overflowWrap: 'break-word' }}>{f.description}</p>
                                            </div>

                                            {/* Vulnerable Code Snippet */}
                                            {f.code_snippet && (
                                                <div style={{ marginBottom: '16px' }}>
                                                    <h4 style={{ fontSize: '0.78rem', color: '#f87171', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                        <Code size={14} /> Vulnerable Code
                                                    </h4>
                                                    <pre style={{ background: '#1a0a0a', padding: '14px', borderRadius: '8px', fontSize: '0.78rem', border: '1px solid #450a0a', color: '#fca5a5', whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'break-word', overflowX: 'auto', maxWidth: '100%', margin: 0 }}>
                                                        <code>{f.code_snippet}</code>
                                                    </pre>
                                                </div>
                                            )}

                                            {/* Secure Fix Code */}
                                            {f.fixed_code && (
                                                <div id={`fix-section-${i}`} style={{ marginBottom: '16px' }}>
                                                    <h4 style={{ fontSize: '0.78rem', color: '#4ade80', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                        🛡️ Secure Fix
                                                    </h4>
                                                    <pre style={{ background: '#0a1410', padding: '14px', borderRadius: '8px', fontSize: '0.78rem', border: '1px solid #064e3b', color: '#6ee7b7', whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'break-word', overflowX: 'auto', maxWidth: '100%', margin: 0 }}>
                                                        <code>{f.fixed_code}</code>
                                                    </pre>
                                                </div>
                                            )}

                                            {/* AI Reasoning */}
                                            {f.ai_reasoning && (
                                                <div style={{ marginBottom: '16px', padding: '12px', background: 'rgba(99, 102, 241, 0.05)', borderRadius: '8px', borderLeft: '3px solid #6366f1' }}>
                                                    <h4 style={{ fontSize: '0.75rem', color: '#818cf8', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 700 }}>AI Reasoning Insight</h4>
                                                    <p style={{ fontSize: '0.82rem', lineHeight: 1.5, color: '#94a3b8', fontStyle: 'italic', wordBreak: 'break-word', overflowWrap: 'break-word' }}>"{f.ai_reasoning}"</p>
                                                </div>
                                            )}

                                            {/* Remediation */}
                                            <div style={{ marginBottom: '16px' }}>
                                                <h4 style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                    <Shield size={14} /> Remediation
                                                </h4>
                                                <p style={{ fontSize: '0.85rem', lineHeight: 1.6, color: 'var(--text-secondary)', wordBreak: 'break-word', overflowWrap: 'break-word' }}>{f.remediation || 'No remediation provided.'}</p>
                                            </div>

                                            {/* Exploit PoC */}
                                            {f.exploit_poc && f.exploit_poc !== "N/A" && (
                                                <div id={`poc-section-${i}`} style={{ marginBottom: '16px' }}>
                                                    <h4 style={{ fontSize: '0.78rem', color: '#f87171', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 700 }}>AI-Generated Concept Exploit (PoC)</h4>
                                                    <pre style={{ background: '#1a1010', padding: '14px', borderRadius: '8px', fontSize: '0.78rem', border: '1px solid #450a0a', color: '#fca5a5', whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'break-word', overflowX: 'auto', maxWidth: '100%', margin: 0 }}>
                                                        <code>{f.exploit_poc}</code>
                                                    </pre>
                                                </div>
                                            )}

                                            {/* Taint Flow Analysis */}
                                            {f.exploit_path && f.exploit_path.length > 0 && (
                                                <div style={{ marginBottom: '16px' }}>
                                                    <h4 style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '14px', fontWeight: 700, letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                        Taint Flow Analysis
                                                    </h4>
                                                    <div style={{ padding: '4px 8px' }}>
                                                        {f.exploit_path.map((step, idx) => {
                                                            const isSource = idx === 0;
                                                            const isSink = idx === f.exploit_path.length - 1;
                                                            return (
                                                                <div key={idx} style={{ display: 'flex', gap: '16px', position: 'relative' }}>
                                                                    {idx < f.exploit_path.length - 1 && (
                                                                        <div style={{ position: 'absolute', left: '7px', top: '24px', bottom: '-8px', width: '2px', background: 'linear-gradient(to bottom, #ef4444, #475569)', opacity: 0.4 }} />
                                                                    )}
                                                                    <div style={{ width: '16px', height: '16px', borderRadius: '50%', background: isSource ? '#ef4444' : isSink ? '#991b1b' : '#334155', border: `3px solid ${isSource || isSink ? 'rgba(239, 68, 68, 0.2)' : 'rgba(71, 85, 105, 0.1)'}`, zIndex: 2, marginTop: '4px', boxShadow: isSource ? '0 0 10px rgba(239, 68, 68, 0.4)' : 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                                                                        {isSink && <div style={{ width: '4px', height: '4px', background: '#fff', borderRadius: '50%' }} />}
                                                                    </div>
                                                                    <div style={{ paddingBottom: idx === f.exploit_path.length - 1 ? '0' : '20px', flex: 1, minWidth: 0 }}>
                                                                        <div style={{ fontSize: '0.7rem', fontWeight: 700, color: isSource ? '#ef4444' : isSink ? '#f87171' : 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
                                                                            {isSource ? 'Source' : isSink ? 'Sink' : `Hop ${idx}`}
                                                                        </div>
                                                                        <div style={{ fontSize: '0.82rem', color: isSink ? '#fca5a5' : 'var(--text-primary)', lineHeight: 1.4, fontWeight: isSource || isSink ? 600 : 400, wordBreak: 'break-word' }}>
                                                                            {step}
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            );
                                                        })}
                                                    </div>
                                                </div>
                                            )}

                                            {/* Footer: Source, CWE, OWASP, Trust Score */}
                                            <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-primary)', paddingTop: '12px', flexWrap: 'wrap', gap: '8px' }}>
                                                <div style={{ display: 'flex', gap: '16px', fontSize: '0.75rem', color: 'var(--text-muted)', flexWrap: 'wrap' }}>
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
