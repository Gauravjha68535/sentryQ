import React, { useState, useEffect, useMemo, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { Download, ChevronDown, ChevronUp, FileText, Code, Shield } from 'lucide-react'
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js'
import { Doughnut, Bar } from 'react-chartjs-2'
import SeverityBadge from '../components/SeverityBadge'
import StatCard from '../components/StatCard'
import { useToast } from '../components/Toast'

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement)

function TrustBar({ score }) {
    const color = score > 80 ? '#22c55e' : score > 50 ? '#eab308' : '#ef4444'
    return (
        <div className="trust-bar-wrap">
            <div className="trust-bar-track">
                <div className="trust-bar-fill" style={{ width: `${score || 0}%`, background: color }} />
            </div>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)' }}>{Math.round(score || 0)}%</span>
        </div>
    )
}

function TaintFlow({ steps }) {
    if (!steps?.length) return null
    return (
        <div className="taint-flow">
            {steps.map((step, idx) => {
                const isSource = idx === 0
                const isSink = idx === steps.length - 1
                const dotColor = isSource ? '#ef4444' : isSink ? '#991b1b' : '#334155'
                const dotBorder = (isSource || isSink) ? 'rgba(239,68,68,0.2)' : 'rgba(71,85,105,0.1)'
                return (
                    <div key={idx} className="taint-step" style={{ paddingBottom: isSink ? 0 : '20px' }}>
                        {!isSink && <div className="taint-step-connector" />}
                        <div className="taint-step-dot" style={{ background: dotColor, border: `3px solid ${dotBorder}`, boxShadow: isSource ? '0 0 10px rgba(239,68,68,0.4)' : 'none' }}>
                            {isSink && <div style={{ width: '4px', height: '4px', background: '#fff', borderRadius: '50%' }} />}
                        </div>
                        <div className="taint-step-body">
                            <div className="taint-step-kind" style={{ color: isSource ? '#ef4444' : isSink ? '#f87171' : 'var(--text-muted)' }}>
                                {isSource ? 'Source' : isSink ? 'Sink' : `Hop ${idx}`}
                            </div>
                            <div style={{ fontSize: '0.82rem', color: isSink ? '#fca5a5' : 'var(--text-primary)', lineHeight: 1.4, fontWeight: isSource || isSink ? 600 : 400, wordBreak: 'break-word' }}>
                                {step}
                            </div>
                        </div>
                    </div>
                )
            })}
        </div>
    )
}

function FindingDetail({ f }) {
    return (
        <td colSpan={9} className="finding-detail">
            <div className="finding-detail-section">
                <h4 className="finding-detail-label"><FileText size={14} /> Description</h4>
                <p className="finding-detail-text">{f.description}</p>
            </div>

            {f.code_snippet && (
                <div className="finding-detail-section">
                    <h4 className="finding-detail-label" style={{ color: '#f87171' }}><Code size={14} /> Vulnerable Code</h4>
                    <pre className="finding-code-block finding-code-vuln"><code>{f.code_snippet}</code></pre>
                </div>
            )}

            {f.fixed_code && (
                <div className="finding-detail-section">
                    <h4 className="finding-detail-label" style={{ color: '#4ade80' }}>🛡️ Secure Fix</h4>
                    <pre className="finding-code-block finding-code-fix"><code>{f.fixed_code}</code></pre>
                </div>
            )}

            {f.ai_reasoning && (
                <div className="ai-reasoning-box">
                    <div className="ai-reasoning-label">AI Reasoning Insight</div>
                    <p className="ai-reasoning-text">"{f.ai_reasoning}"</p>
                </div>
            )}

            <div className="finding-detail-section">
                <h4 className="finding-detail-label"><Shield size={14} /> Remediation</h4>
                <p className="finding-detail-text">{f.remediation || 'No remediation provided.'}</p>
            </div>

            {f.exploit_poc && f.exploit_poc !== 'N/A' && (
                <div className="finding-detail-section">
                    <h4 className="finding-detail-label" style={{ color: '#f87171' }}>AI-Generated Concept Exploit (PoC)</h4>
                    <pre className="finding-code-block finding-code-poc"><code>{f.exploit_poc}</code></pre>
                </div>
            )}

            {f.exploit_path?.length > 0 && (
                <div className="finding-detail-section">
                    <h4 className="finding-detail-label">Taint Flow Analysis</h4>
                    <TaintFlow steps={f.exploit_path} />
                </div>
            )}

            <div className="finding-footer">
                <div className="finding-footer-meta">
                    <span>Source: <strong style={{ color: 'var(--text-secondary)' }}>{f.source}</strong></span>
                    {f.cwe   && <span>CWE: <strong style={{ color: 'var(--text-secondary)' }}>{f.cwe}</strong></span>}
                    {f.owasp && <span>OWASP: <strong style={{ color: 'var(--text-secondary)' }}>{f.owasp}</strong></span>}
                </div>
                <div style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                    Trust Score: <span style={{ color: (f.trust_score || 0) > 80 ? '#22c55e' : (f.trust_score || 0) > 50 ? '#eab308' : '#ef4444' }}>{Math.round(f.trust_score || 0)}%</span>
                </div>
            </div>
        </td>
    )
}

export default function ReportViewer() {
    const { id } = useParams()
    const [findings, setFindings] = useState([])
    const [scanInfo, setScanInfo] = useState(null)
    const [filter, setFilter] = useState('all')
    const [expandedRow, setExpandedRow] = useState(null)
    const [loading, setLoading] = useState(true)
    const [reportPhase, setReportPhase] = useState('final')
    const [isEnsemble, setIsEnsemble] = useState(false)
    const [statusFilter, setStatusFilter] = useState('all')
    const [searchQuery, setSearchQuery] = useState('')
    const [selectedIds, setSelectedIds] = useState(new Set())
    const toast = useToast()

    const fetchReport = useCallback(async (phase = 'final') => {
        try {
            const phaseParam = phase && phase !== 'final' ? `?phase=${phase}` : ''
            const [scanRes, findingsRes] = await Promise.all([
                fetch(`/api/scan/${id}`),
                fetch(`/api/scan/${id}/findings${phaseParam}`),
            ])
            if (scanRes.ok) {
                const d = await scanRes.json()
                setScanInfo(d)
                try { setIsEnsemble(!!JSON.parse(d.config || '{}').enableEnsemble) } catch { /* ignore */ }
            }
            if (findingsRes.ok) setFindings(await findingsRes.json() || [])
        } catch { /* ignore */ }
        finally { setLoading(false) }
    }, [id])

    useEffect(() => { fetchReport() }, [fetchReport])

    const updateFindingStatus = async (dbId, newStatus) => {
        try {
            const res = await fetch(`/api/scan/${id}/finding/${dbId}/status`, {
                method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: newStatus })
            })
            if (res.ok) setFindings(prev => prev.map(f => f.db_id === dbId ? { ...f, status: newStatus } : f))
            else toast.error(`Failed to update status: server returned ${res.status}`)
        } catch { toast.error('Failed to update finding status') }
    }

    const bulkUpdateStatus = async (newStatus) => {
        const ids = [...selectedIds]
        if (!ids.length) return
        try {
            const res = await fetch(`/api/scan/${id}/findings/bulk-status`, {
                method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids, status: newStatus })
            })
            if (res.ok) {
                setFindings(prev => prev.map(f => selectedIds.has(f.db_id) ? { ...f, status: newStatus } : f))
                setSelectedIds(new Set())
                toast.success(`${ids.length} finding${ids.length > 1 ? 's' : ''} marked as ${newStatus.replace('_', ' ')}`)
            } else {
                toast.error(`Bulk update failed: server returned ${res.status}`)
            }
        } catch { toast.error('Bulk status update failed') }
    }

    const filtered = useMemo(() => findings.filter(f => {
        const q = searchQuery.toLowerCase()
        return (filter === 'all' || (f.severity || '').toLowerCase() === filter)
            && (statusFilter === 'all' || (f.status || 'open') === statusFilter)
            && (!q || (f.issue_name || '').toLowerCase().includes(q) || (f.file_path || '').toLowerCase().includes(q) || (f.description || '').toLowerCase().includes(q) || (f.cwe || '').toLowerCase().includes(q))
    }), [findings, filter, statusFilter, searchQuery])

    const toggleSelectAll = () => setSelectedIds(selectedIds.size === filtered.length ? new Set() : new Set(filtered.map(f => f.db_id)))
    const toggleSelect = (dbId) => setSelectedIds(prev => { const n = new Set(prev); n.has(dbId) ? n.delete(dbId) : n.add(dbId); return n })

    const stats = useMemo(() => {
        const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        findings.forEach(f => { const sev = (f.severity || '').toLowerCase(); if (s[sev] !== undefined) s[sev]++ })
        return s
    }, [findings])

    const topCWEs = useMemo(() => {
        const m = {}
        findings.forEach(f => { if (f.cwe) m[f.cwe] = (m[f.cwe] || 0) + 1 })
        return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8)
    }, [findings])

    const { riskRaw, riskLevel, riskColor, aiValidatedCount } = useMemo(() => {
        const raw = Math.min(100, stats.critical * 10 + stats.high * 5 + stats.medium * 2 + stats.low * 0.5)
        return {
            riskRaw: raw,
            riskLevel: raw >= 75 ? 'Critical Risk' : raw >= 50 ? 'High Risk' : raw >= 25 ? 'Medium Risk' : 'Low Risk',
            riskColor: raw >= 75 ? '#ef4444' : raw >= 50 ? '#f97316' : raw >= 25 ? '#eab308' : '#22c55e',
            aiValidatedCount: findings.filter(f => f.ai_validated === 'Yes').length,
        }
    }, [stats, findings])

    const sevChartData = useMemo(() => ({
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{ data: [stats.critical, stats.high, stats.medium, stats.low, stats.info], backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e','#6366f1'], borderWidth: 0 }],
    }), [stats])

    const cweChartData = useMemo(() => ({
        labels: topCWEs.map(c => c[0]),
        datasets: [{ label: 'Findings', data: topCWEs.map(c => c[1]), backgroundColor: 'rgba(99,102,241,0.7)', borderColor: '#818cf8', borderWidth: 1, borderRadius: 6 }],
    }), [topCWEs])

    const chartOpts = { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#94a3b8', padding: 12, usePointStyle: true } } } }

    if (loading) {
        return (
            <div className="animate-fade-in">
                <div style={{ marginBottom: '32px' }}>
                    <div className="skeleton skeleton-text" style={{ width: '200px', height: '28px', marginBottom: '10px' }} />
                    <div className="skeleton skeleton-text" style={{ width: '320px' }} />
                </div>
                <div className="stats-grid" style={{ marginBottom: '24px' }}>
                    {[1,2,3,4,5].map(i => <div key={i} className="skeleton" style={{ height: '80px', borderRadius: 'var(--radius-lg)' }} />)}
                </div>
                <div className="skeleton" style={{ height: '180px', borderRadius: 'var(--radius-lg)', marginBottom: '24px' }} />
                <div className="skeleton" style={{ height: '300px', borderRadius: 'var(--radius-lg)' }} />
            </div>
        )
    }

    return (
        <div className="animate-fade-in">
            <div className="page-header-row">
                <div>
                    <h1>Security Report</h1>
                    <p>{scanInfo?.target || 'Scan'} — {findings.length} findings</p>
                </div>
                <div className="page-actions" style={{ flexWrap: 'wrap' }}>
                    {['html','csv','pdf','sarif'].map(fmt => (
                        <a key={fmt} href={`/api/scan/${id}/report/${fmt}`} download className="btn btn-secondary btn-sm">
                            <Download size={14} /> {fmt.toUpperCase()}
                        </a>
                    ))}
                    <a href={`/api/scan/${id}/report/sbom`} download={`sentryq-sbom-${id}.cdx.json`} className="btn btn-secondary btn-sm" title="CycloneDX SBOM"><Download size={14} /> SBOM</a>
                    <a href={`/api/scan/compliance?id=${id}&framework=owasp`} download={`compliance-owasp-${id}.json`} className="btn btn-secondary btn-sm" title="OWASP Top 10"><Download size={14} /> OWASP</a>
                    <a href={`/api/scan/compliance?id=${id}&framework=pci`} download={`compliance-pci-${id}.json`} className="btn btn-secondary btn-sm" title="PCI DSS"><Download size={14} /> PCI</a>
                    <a href={`/api/scan/compliance?id=${id}&framework=nist`} download={`compliance-nist-${id}.json`} className="btn btn-secondary btn-sm" title="NIST 800-53"><Download size={14} /> NIST</a>
                    <a href={`/api/scan/${id}/report/all`} download={`sentryq-full-${id}.zip`} className="btn btn-primary btn-sm"><Download size={14} /> All (ZIP)</a>
                </div>
            </div>

            {isEnsemble && (
                <div style={{ marginBottom: '20px' }}>
                    <div style={{ display: 'flex', gap: '8px', padding: '4px', background: 'var(--bg-tertiary)', borderRadius: '10px', width: 'fit-content' }}>
                        {[{ key: 'final', label: '⚖️ Final Report (Judge)', color: '#f59e0b' }, { key: 'static', label: '📊 Static Report', color: '#6366f1' }, { key: 'ai', label: '🤖 AI Report', color: '#22c55e' }].map(t => (
                            <button key={t.key} onClick={() => { setReportPhase(t.key); setLoading(true); fetchReport(t.key) }}
                                style={{ padding: '8px 16px', borderRadius: '8px', border: 'none', cursor: 'pointer', fontSize: '0.78rem', fontWeight: 600, transition: 'all 0.2s', background: reportPhase === t.key ? t.color : 'transparent', color: reportPhase === t.key ? '#fff' : 'var(--text-muted)' }}>
                                {t.label}
                            </button>
                        ))}
                    </div>
                    <p className="form-hint" style={{ marginTop: '6px' }}>
                        {reportPhase === 'final' && 'Showing the merged master report after AI Judge deduplication.'}
                        {reportPhase === 'static' && 'Showing raw findings from Phase 1: Static Expert.'}
                        {reportPhase === 'ai' && 'Showing raw findings from Phase 2: AI Expert.'}
                    </p>
                </div>
            )}

            <div className="stats-grid">
                {Object.entries(stats).map(([sev, count]) => (
                    <StatCard key={sev} label={sev} value={count} color={`var(--severity-${sev})`} onClick={() => setFilter(sev)} />
                ))}
            </div>

            {/* Risk Score */}
            <div className="card risk-ring-wrap" style={{ marginBottom: '24px' }}>
                <div className="risk-ring-left">
                    <div style={{
                        width: 64, height: 64, borderRadius: '50%', position: 'relative',
                        background: `conic-gradient(${riskColor} ${riskRaw * 3.6}deg, rgba(255,255,255,0.06) 0deg)`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                        <div style={{ width: 52, height: 52, borderRadius: '50%', background: 'var(--bg-secondary)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.1rem', fontWeight: 800, color: riskColor }}>
                            {Math.round(riskRaw)}
                        </div>
                    </div>
                    <div>
                        <div style={{ fontSize: '1rem', fontWeight: 700, color: riskColor }}>{riskLevel}</div>
                        <div className="form-hint">Security Risk Score (0–100)</div>
                    </div>
                </div>
                <div className="risk-ring-stats">
                    <div className="risk-stat"><div className="risk-stat-value">{findings.length}</div><div className="risk-stat-label">Total</div></div>
                    <div className="risk-stat"><div className="risk-stat-value" style={{ color: '#22c55e' }}>{aiValidatedCount}</div><div className="risk-stat-label">AI Confirmed</div></div>
                    <div className="risk-stat"><div className="risk-stat-value" style={{ color: '#ef4444' }}>{stats.critical}</div><div className="risk-stat-label">Critical</div></div>
                </div>
            </div>

            {/* Charts */}
            <div className="grid-2" style={{ marginBottom: '32px' }}>
                <div className="card"><h3 className="chart-header">Severity Distribution</h3><div style={{ maxWidth: '280px', margin: '0 auto' }}><Doughnut data={sevChartData} options={chartOpts} /></div></div>
                <div className="card"><h3 className="chart-header">Top CWE Categories</h3><Bar data={cweChartData} options={{ ...chartOpts, indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } }, y: { ticks: { color: '#94a3b8', font: { size: 11 } }, grid: { display: false } } } }} /></div>
            </div>

            {/* Filter bar */}
            <div className="filter-bar">
                <div className="tabs" style={{ maxWidth: '500px', margin: 0 }}>
                    {['all','critical','high','medium','low','info'].map(f => (
                        <button key={f} className={`tab ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
                            {f === 'all' ? `All (${findings.length})` : `${f} (${stats[f]})`}
                        </button>
                    ))}
                </div>
                <div className="filter-right">
                    <input type="text" placeholder="Search issues, files, CWEs..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
                        style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)', border: '1px solid var(--border-primary)', borderRadius: '6px', padding: '4px 10px', fontSize: '0.75rem', outline: 'none', width: '200px' }} />
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>STATUS:</span>
                    <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
                        style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)', border: '1px solid var(--border-primary)', borderRadius: '6px', padding: '4px 8px', fontSize: '0.75rem', outline: 'none' }}>
                        <option value="all">All Status</option>
                        <option value="open">Open</option>
                        <option value="resolved">Resolved</option>
                        <option value="ignored">Ignored</option>
                        <option value="false_positive">False Positive</option>
                    </select>
                </div>
            </div>

            {selectedIds.size > 0 && (
                <div className="bulk-bar">
                    <span className="bulk-bar-count">{selectedIds.size} selected</span>
                    {[['Open','open','#6366f1'],['Resolved','resolved','#22c55e'],['Ignored','ignored','#94a3b8'],['False Positive','false_positive','#f59e0b']].map(([label, val, color]) => (
                        <button key={val} onClick={() => bulkUpdateStatus(val)} style={{ padding: '3px 10px', fontSize: '0.75rem', borderRadius: '5px', border: `1px solid ${color}40`, background: `${color}18`, color, cursor: 'pointer', fontWeight: 600 }}>
                            Mark {label}
                        </button>
                    ))}
                    <button onClick={() => setSelectedIds(new Set())} style={{ marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}>Clear</button>
                </div>
            )}

            <div className="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style={{ width: '32px' }}>
                                <input type="checkbox" checked={filtered.length > 0 && selectedIds.size === filtered.length} onChange={toggleSelectAll} onClick={e => e.stopPropagation()} />
                            </th>
                            <th>#</th><th>Severity</th><th>Issue</th><th>File</th><th>Line</th><th>Trust Score</th><th>AI</th><th>Status</th><th></th>
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.map((f, i) => (
                            <React.Fragment key={f.db_id ?? i}>
                                <tr style={{ cursor: 'pointer' }} onClick={() => setExpandedRow(expandedRow === i ? null : i)}>
                                    <td onClick={e => e.stopPropagation()}><input type="checkbox" checked={selectedIds.has(f.db_id)} onChange={() => toggleSelect(f.db_id)} /></td>
                                    <td style={{ color: 'var(--text-muted)', fontWeight: 600 }}>{f.sr_no || i + 1}</td>
                                    <td><SeverityBadge severity={f.severity} /></td>
                                    <td style={{ fontWeight: 600, maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.issue_name}</td>
                                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-accent)' }}>{f.file_path?.split('/').slice(-2).join('/')}</td>
                                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>{f.line_number}</td>
                                    <td><TrustBar score={f.trust_score} /></td>
                                    <td>
                                        {f.ai_validated === 'Yes'
                                            ? <span style={{ color: 'var(--text-success)', fontWeight: 600, fontSize: '0.78rem' }}>✓ TP</span>
                                            : f.ai_validated?.includes('False')
                                                ? <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>✗ FP</span>
                                                : <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>—</span>}
                                    </td>
                                    <td>
                                        <select value={f.status || 'open'} onClick={e => e.stopPropagation()} onChange={e => updateFindingStatus(f.db_id, e.target.value)}
                                            style={{ background: f.status === 'resolved' ? 'rgba(34,197,94,0.1)' : f.status === 'false_positive' ? 'rgba(148,163,184,0.1)' : 'transparent', color: f.status === 'resolved' ? '#22c55e' : f.status === 'false_positive' ? '#94a3b8' : 'var(--text-primary)', border: '1px solid var(--border-primary)', borderRadius: '4px', fontSize: '0.7rem', padding: '2px 4px', fontWeight: 600 }}>
                                            <option value="open">OPEN</option>
                                            <option value="resolved">FIXED</option>
                                            <option value="ignored">IGNORE</option>
                                            <option value="false_positive">FP</option>
                                        </select>
                                    </td>
                                    <td>{expandedRow === i ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</td>
                                </tr>
                                {expandedRow === i && <tr><FindingDetail f={f} /></tr>}
                            </React.Fragment>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    )
}
