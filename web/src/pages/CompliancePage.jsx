import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { FileCheck, RefreshCw, ChevronDown, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'

const FRAMEWORKS = [
    { id: 'owasp', label: 'OWASP Top 10' },
    { id: 'pci', label: 'PCI DSS' },
    { id: 'nist', label: 'NIST 800-53' },
]

function StatusBadge({ status }) {
    const pass = status === 'pass'
    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', gap: '4px',
            background: pass ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
            color: pass ? '#22c55e' : '#ef4444',
            fontWeight: 700, fontSize: '0.72rem', padding: '2px 10px', borderRadius: '12px', textTransform: 'uppercase'
        }}>
            {pass ? <CheckCircle size={11} /> : <XCircle size={11} />}
            {pass ? 'PASS' : 'FAIL'}
        </span>
    )
}

function SeverityBadge({ severity }) {
    const colors = {
        critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', info: '#6b7280',
    }
    const c = colors[severity?.toLowerCase()] || '#6b7280'
    return severity
        ? <span style={{ color: c, fontWeight: 600, fontSize: '0.8rem', textTransform: 'capitalize' }}>{severity}</span>
        : <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>—</span>
}

function ControlRow({ ctrl }) {
    const [open, setOpen] = useState(false)
    return (
        <>
            <tr
                onClick={() => ctrl.findings?.length > 0 && setOpen(o => !o)}
                style={{ cursor: ctrl.findings?.length > 0 ? 'pointer' : 'default' }}
            >
                <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.82rem', padding: '12px 16px', borderBottom: '1px solid var(--border-primary)' }}>
                    {ctrl.control_id}
                </td>
                <td style={{ padding: '12px 16px', fontSize: '0.85rem', borderBottom: '1px solid var(--border-primary)' }}>
                    {ctrl.control_name}
                </td>
                <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-primary)' }}>
                    <StatusBadge status={ctrl.status} />
                </td>
                <td style={{ padding: '12px 16px', textAlign: 'center', fontWeight: 600, borderBottom: '1px solid var(--border-primary)' }}>
                    {ctrl.findings?.length || 0}
                </td>
                <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-primary)' }}>
                    <SeverityBadge severity={ctrl.highest_severity} />
                </td>
                <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-primary)', color: 'var(--text-muted)' }}>
                    {ctrl.findings?.length > 0 && <ChevronDown size={14} style={{ transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />}
                </td>
            </tr>
            {open && ctrl.findings?.map((f, i) => (
                <tr key={i} style={{ background: 'var(--bg-secondary)' }}>
                    <td colSpan={6} style={{ padding: '8px 32px 8px 40px', borderBottom: '1px solid var(--border-primary)' }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'flex', gap: '12px', alignItems: 'center' }}>
                            <SeverityBadge severity={f.severity} />
                            <span style={{ fontWeight: 600 }}>{f.issue_name || f.IssueName}</span>
                            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                                {f.file_path || f.FilePath}:{f.line_number || f.LineNumber}
                            </span>
                        </div>
                    </td>
                </tr>
            ))}
        </>
    )
}

export default function CompliancePage() {
    const { id: paramID } = useParams()
    const [scanID, setScanID] = useState(paramID || '')
    const [framework, setFramework] = useState('owasp')
    const [report, setReport] = useState(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')
    const [scans, setScans] = useState([])

    useEffect(() => {
        fetch('/api/scans')
            .then(r => r.ok ? r.json() : Promise.reject('Failed'))
            .then(data => setScans(data.scans || data || []))
            .catch(() => {})
    }, [])

    useEffect(() => {
        if (paramID) load(paramID, framework)
    }, [])

    const load = async (sid, fw) => {
        if (!sid) { setError('Enter a scan ID'); return }
        setError('')
        setLoading(true)
        try {
            const res = await fetch(`/api/scan/compliance?id=${encodeURIComponent(sid)}&framework=${fw}`)
            if (!res.ok) throw new Error(await res.text())
            setReport(await res.json())
        } catch (e) {
            setError(e.message || 'Failed to load compliance report')
            setReport(null)
        } finally {
            setLoading(false)
        }
    }

    const handleLoad = () => load(scanID, framework)

    const overallColor = report?.overall_status === 'compliant' ? '#22c55e' : '#ef4444'
    const overallText = report?.overall_status === 'compliant' ? 'COMPLIANT' : 'NON-COMPLIANT'

    return (
        <div className="animate-fade-in">
            <div className="page-header">
                <h1 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <FileCheck size={24} /> Compliance Report
                </h1>
                <p>Map scan findings to compliance frameworks</p>
            </div>

            {/* Controls */}
            <div className="card" style={{ marginBottom: '24px' }}>
                <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: '200px' }}>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                            Scan ID
                        </label>
                        {scans.length > 0 ? (
                            <select className="input" value={scanID} onChange={e => setScanID(e.target.value)} style={{ appearance: 'auto' }}>
                                <option value="">Select a scan…</option>
                                {scans.map(s => <option key={s.id} value={s.id}>{s.target || s.id} — {s.created_at?.slice(0, 10) || ''}</option>)}
                            </select>
                        ) : (
                            <input className="input" type="text" value={scanID} onChange={e => setScanID(e.target.value)} placeholder="Scan ID" />
                        )}
                    </div>
                    <div>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                            Framework
                        </label>
                        <div style={{ display: 'flex', gap: '6px' }}>
                            {FRAMEWORKS.map(fw => (
                                <button key={fw.id} type="button"
                                    onClick={() => setFramework(fw.id)}
                                    style={{
                                        padding: '8px 14px', borderRadius: '6px', fontSize: '0.8rem', fontWeight: 600,
                                        border: '1px solid var(--border-primary)', cursor: 'pointer',
                                        background: framework === fw.id ? 'var(--accent-primary)' : 'var(--bg-secondary)',
                                        color: framework === fw.id ? '#fff' : 'var(--text-secondary)',
                                    }}
                                >
                                    {fw.label}
                                </button>
                            ))}
                        </div>
                    </div>
                    <button className="btn btn-primary" onClick={handleLoad} disabled={loading} style={{ height: '42px', minWidth: '110px' }}>
                        {loading ? <><RefreshCw size={14} className="animate-spin" /> Loading…</> : <><FileCheck size={14} /> Load</>}
                    </button>
                </div>
                {error && <p style={{ color: 'var(--text-danger)', fontSize: '0.82rem', marginTop: '10px' }}>{error}</p>}
            </div>

            {report && (
                <>
                    {/* Overall status + summary */}
                    <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '20px', alignItems: 'center' }}>
                        <div style={{
                            display: 'flex', alignItems: 'center', gap: '8px',
                            background: overallColor === '#22c55e' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                            border: `1px solid ${overallColor}`, borderRadius: '10px', padding: '12px 20px'
                        }}>
                            {report.overall_status === 'compliant'
                                ? <CheckCircle size={20} style={{ color: '#22c55e' }} />
                                : <AlertTriangle size={20} style={{ color: '#ef4444' }} />}
                            <span style={{ fontSize: '1rem', fontWeight: 800, color: overallColor }}>{overallText}</span>
                        </div>
                        {[
                            { label: 'Controls', value: report.summary?.total_controls ?? 0, color: '#94a3b8' },
                            { label: 'Passing', value: report.summary?.passing_controls ?? 0, color: '#22c55e' },
                            { label: 'Failing', value: report.summary?.failing_controls ?? 0, color: '#ef4444' },
                            { label: 'Findings', value: report.summary?.total_findings ?? 0, color: '#6366f1' },
                        ].map(({ label, value, color }) => (
                            <div key={label} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-primary)', borderRadius: '10px', padding: '12px 20px', textAlign: 'center', minWidth: '90px' }}>
                                <div style={{ fontSize: '1.5rem', fontWeight: 800, color }}>{value}</div>
                                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{label}</div>
                            </div>
                        ))}
                    </div>

                    {/* Controls table */}
                    <div style={{ background: 'var(--bg-card)', borderRadius: '12px', overflow: 'hidden', border: '1px solid var(--border-primary)' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr style={{ background: 'var(--bg-secondary)' }}>
                                    {['Control ID', 'Control Name', 'Status', 'Findings', 'Highest Severity', ''].map(h => (
                                        <th key={h} style={{ padding: '12px 16px', textAlign: 'left', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>
                                            {h}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {(report.controls || []).map((ctrl, i) => <ControlRow key={i} ctrl={ctrl} />)}
                            </tbody>
                        </table>
                    </div>
                    <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '8px' }}>
                        Framework: {report.framework} &nbsp;|&nbsp; Generated: {report.generated_at}
                    </p>
                </>
            )}
        </div>
    )
}
