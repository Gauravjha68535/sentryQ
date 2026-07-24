import React, { useState, useEffect } from 'react'
import { GitCompare, AlertTriangle, CheckCircle, MinusCircle, RefreshCw } from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge'

function FindingCard({ finding }) {
    return (
        <div className="finding-card">
            <div className="finding-card-title">
                <SeverityBadge severity={finding.severity} />
                <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{finding.issue_name || finding.IssueName}</span>
            </div>
            <div className="finding-card-meta">
                {finding.file_path || finding.FilePath} : {finding.line_number || finding.LineNumber}
            </div>
        </div>
    )
}

function DiffColumn({ title, icon, color, findings }) {
    return (
        <div className="diff-col" style={{ borderColor: color }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem', fontWeight: 700, marginBottom: '12px', color }}>
                {icon}
                {title}
                <span className="badge" style={{ background: color, color: '#fff', marginLeft: '4px' }}>{findings.length}</span>
            </h3>
            {findings.length === 0
                ? <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>None.</p>
                : findings.map((f, i) => <FindingCard key={i} finding={f} />)}
        </div>
    )
}

export default function ScanDiff() {
    const [scanA, setScanA] = useState('')
    const [scanB, setScanB] = useState('')
    const [scans, setScans] = useState([])
    const [diff, setDiff] = useState(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')

    useEffect(() => {
        fetch('/api/scans')
            .then(r => r.ok ? r.json() : Promise.reject())
            .then(d => setScans(d || []))
            .catch(() => {})
    }, [])

    const compare = async () => {
        if (!scanA || !scanB) { setError('Select two scan IDs to compare'); return }
        if (scanA === scanB) { setError('Select two different scans'); return }
        setError(''); setLoading(true)
        try {
            const res = await fetch(`/api/scans/diff?a=${encodeURIComponent(scanA)}&b=${encodeURIComponent(scanB)}`)
            if (!res.ok) throw new Error(await res.text())
            setDiff(await res.json())
        } catch (e) { setError(e.message || 'Comparison failed') }
        finally { setLoading(false) }
    }

    const scanSelect = (value, onChange) => (
        scans.length > 0
            ? <select className="input" value={value} onChange={e => onChange(e.target.value)} style={{ appearance: 'auto' }}>
                <option value="">Select a scan…</option>
                {scans.map(s => <option key={s.id} value={s.id}>{s.target || s.id} — {s.created_at?.slice(0, 10) || ''}</option>)}
              </select>
            : <input className="input" type="text" value={value} onChange={e => onChange(e.target.value)} placeholder="Scan ID" />
    )

    return (
        <div className="animate-fade-in">
            <div className="page-header-row">
                <div>
                    <h1 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}><GitCompare size={24} /> Compare Scans</h1>
                    <p>Diff two scan results to see new, fixed, and persisting findings</p>
                </div>
            </div>

            <div className="card" style={{ marginBottom: '24px' }}>
                <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: '200px' }}>
                        <label className="form-label">Scan A (baseline)</label>
                        {scanSelect(scanA, setScanA)}
                    </div>
                    <div style={{ flex: 1, minWidth: '200px' }}>
                        <label className="form-label">Scan B (compare to)</label>
                        {scanSelect(scanB, setScanB)}
                    </div>
                    <button className="btn btn-primary" onClick={compare} disabled={loading} style={{ height: '42px', minWidth: '130px' }}>
                        {loading ? <><RefreshCw size={14} className="animate-spin" /> Comparing…</> : <><GitCompare size={14} /> Compare</>}
                    </button>
                </div>
                {error && <p style={{ color: 'var(--text-danger)', fontSize: '0.82rem', marginTop: '10px' }}>{error}</p>}
            </div>

            {diff && (
                <>
                    <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginBottom: '20px' }}>
                        {[
                            { label: 'Total A', value: diff.total_a ?? 0, color: '#94a3b8' },
                            { label: 'Total B', value: diff.total_b ?? 0, color: '#94a3b8' },
                            { label: 'Delta', value: (diff.total_b ?? 0) - (diff.total_a ?? 0), color: '#6366f1', prefix: true },
                            { label: 'Critical Δ', value: diff.delta_critical ?? 0, color: '#ef4444', prefix: true },
                            { label: 'High Δ', value: diff.delta_high ?? 0, color: '#f97316', prefix: true },
                        ].map(({ label, value, color, prefix }) => (
                            <div key={label} className="card" style={{ padding: '12px 20px', textAlign: 'center', minWidth: '100px' }}>
                                <div style={{ fontSize: '1.6rem', fontWeight: 800, color }}>{prefix && value > 0 ? '+' : ''}{value}</div>
                                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>{label}</div>
                            </div>
                        ))}
                    </div>

                    <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                        <DiffColumn title="New Findings"   icon={<AlertTriangle size={16} />} color="#ef4444" findings={diff.new_findings || []} />
                        <DiffColumn title="Fixed Findings" icon={<CheckCircle size={16} />}   color="#22c55e" findings={diff.fixed_findings || []} />
                        <DiffColumn title="Persisting"     icon={<MinusCircle size={16} />}   color="#94a3b8" findings={diff.persisting_findings || []} />
                    </div>
                </>
            )}
        </div>
    )
}
