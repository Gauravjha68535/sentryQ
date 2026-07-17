import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { FileCheck, RefreshCw, ChevronDown, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge'

const FRAMEWORKS = [
    { id: 'owasp', label: 'OWASP Top 10' },
    { id: 'pci',   label: 'PCI DSS' },
    { id: 'nist',  label: 'NIST 800-53' },
]

function StatusBadge({ status }) {
    const pass = status === 'pass'
    return (
        <span className={`badge ${pass ? 'badge-success' : 'badge-danger'}`}>
            {pass ? <CheckCircle size={11} /> : <XCircle size={11} />}
            {pass ? 'PASS' : 'FAIL'}
        </span>
    )
}

function ControlRow({ ctrl }) {
    const [open, setOpen] = useState(false)
    const hasFindings = ctrl.findings?.length > 0
    return (
        <>
            <tr onClick={() => hasFindings && setOpen(o => !o)} style={{ cursor: hasFindings ? 'pointer' : 'default' }}>
                <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.82rem' }}>{ctrl.control_id}</td>
                <td style={{ fontSize: '0.85rem' }}>{ctrl.control_name}</td>
                <td><StatusBadge status={ctrl.status} /></td>
                <td style={{ textAlign: 'center', fontWeight: 600 }}>{ctrl.findings?.length || 0}</td>
                <td><SeverityBadge severity={ctrl.highest_severity} /></td>
                <td>{hasFindings && <ChevronDown size={14} style={{ transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />}</td>
            </tr>
            {open && ctrl.findings?.map((f, i) => (
                <tr key={i} style={{ background: 'var(--bg-secondary)' }}>
                    <td colSpan={6} style={{ padding: '8px 32px 8px 40px' }}>
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
        fetch('/api/scans').then(r => r.ok ? r.json() : Promise.reject()).then(d => setScans(d.scans || d || [])).catch(() => {})
    }, [])

    useEffect(() => { if (paramID) load(paramID, framework) }, [])

    const load = async (sid, fw) => {
        if (!sid) { setError('Enter a scan ID'); return }
        setError(''); setLoading(true)
        try {
            const res = await fetch(`/api/scan/compliance?id=${encodeURIComponent(sid)}&framework=${fw}`)
            if (!res.ok) throw new Error(await res.text())
            setReport(await res.json())
        } catch (e) { setError(e.message || 'Failed to load compliance report'); setReport(null) }
        finally { setLoading(false) }
    }

    const overallColor = report?.overall_status === 'compliant' ? '#22c55e' : '#ef4444'

    return (
        <div className="animate-fade-in">
            <div className="page-header-row">
                <div>
                    <h1 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}><FileCheck size={24} /> Compliance Report</h1>
                    <p>Map scan findings to compliance frameworks</p>
                </div>
            </div>

            <div className="card" style={{ marginBottom: '24px' }}>
                <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: '200px' }}>
                        <label className="form-label">Scan</label>
                        {scans.length > 0
                            ? <select className="input" value={scanID} onChange={e => setScanID(e.target.value)} style={{ appearance: 'auto' }}>
                                <option value="">Select a scan…</option>
                                {scans.map(s => <option key={s.id} value={s.id}>{s.target || s.id} — {s.created_at?.slice(0, 10) || ''}</option>)}
                              </select>
                            : <input className="input" type="text" value={scanID} onChange={e => setScanID(e.target.value)} placeholder="Scan ID" />}
                    </div>
                    <div>
                        <label className="form-label">Framework</label>
                        <div style={{ display: 'flex', gap: '6px' }}>
                            {FRAMEWORKS.map(fw => (
                                <button key={fw.id} type="button" onClick={() => setFramework(fw.id)} style={{
                                    padding: '8px 14px', borderRadius: '6px', fontSize: '0.8rem', fontWeight: 600,
                                    border: '1px solid var(--border-primary)', cursor: 'pointer',
                                    background: framework === fw.id ? 'var(--accent-primary)' : 'var(--bg-secondary)',
                                    color: framework === fw.id ? '#fff' : 'var(--text-secondary)',
                                }}>
                                    {fw.label}
                                </button>
                            ))}
                        </div>
                    </div>
                    <button className="btn btn-primary" onClick={() => load(scanID, framework)} disabled={loading} style={{ height: '42px', minWidth: '110px' }}>
                        {loading ? <><RefreshCw size={14} className="animate-spin" /> Loading…</> : <><FileCheck size={14} /> Load</>}
                    </button>
                </div>
                {error && <p style={{ color: 'var(--text-danger)', fontSize: '0.82rem', marginTop: '10px' }}>{error}</p>}
            </div>

            {report && (
                <>
                    <div className="compliance-summary">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: overallColor === '#22c55e' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)', border: `1px solid ${overallColor}`, borderRadius: '10px', padding: '12px 20px' }}>
                            {report.overall_status === 'compliant' ? <CheckCircle size={20} style={{ color: '#22c55e' }} /> : <AlertTriangle size={20} style={{ color: '#ef4444' }} />}
                            <span style={{ fontSize: '1rem', fontWeight: 800, color: overallColor }}>{report.overall_status === 'compliant' ? 'COMPLIANT' : 'NON-COMPLIANT'}</span>
                        </div>
                        {[
                            { label: 'Controls', value: report.summary?.total_controls ?? 0,   color: '#94a3b8' },
                            { label: 'Passing',  value: report.summary?.passing_controls ?? 0, color: '#22c55e' },
                            { label: 'Failing',  value: report.summary?.failing_controls ?? 0, color: '#ef4444' },
                            { label: 'Findings', value: report.summary?.total_findings ?? 0,   color: '#6366f1' },
                        ].map(({ label, value, color }) => (
                            <div key={label} className="card" style={{ padding: '12px 20px', textAlign: 'center', minWidth: '90px' }}>
                                <div style={{ fontSize: '1.5rem', fontWeight: 800, color }}>{value}</div>
                                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{label}</div>
                            </div>
                        ))}
                    </div>

                    <div className="table-container">
                        <table>
                            <thead>
                                <tr>
                                    {['Control ID', 'Control Name', 'Status', 'Findings', 'Highest Severity', ''].map(h => (
                                        <th key={h}>{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {(report.controls || []).map((ctrl, i) => <ControlRow key={i} ctrl={ctrl} />)}
                            </tbody>
                        </table>
                    </div>
                    <p className="form-hint" style={{ marginTop: '8px' }}>
                        Framework: {report.framework} &nbsp;|&nbsp; Generated: {report.generated_at}
                    </p>
                </>
            )}
        </div>
    )
}
