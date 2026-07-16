import React, { useState, useEffect } from 'react'
import { GitCompare, AlertTriangle, CheckCircle, MinusCircle, RefreshCw } from 'lucide-react'

const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

function SeverityBadge({ severity }) {
    const colors = {
        critical: { bg: 'rgba(239,68,68,0.15)', color: '#ef4444' },
        high: { bg: 'rgba(249,115,22,0.15)', color: '#f97316' },
        medium: { bg: 'rgba(245,158,11,0.15)', color: '#f59e0b' },
        low: { bg: 'rgba(59,130,246,0.15)', color: '#3b82f6' },
        info: { bg: 'rgba(107,114,128,0.15)', color: '#6b7280' },
    }
    const c = colors[severity?.toLowerCase()] || colors.info
    return (
        <span style={{
            background: c.bg, color: c.color, fontWeight: 700, fontSize: '0.7rem',
            padding: '2px 8px', borderRadius: '10px', textTransform: 'uppercase', letterSpacing: '0.04em'
        }}>
            {severity || 'info'}
        </span>
    )
}

function FindingCard({ finding }) {
    return (
        <div style={{ padding: '10px 12px', borderRadius: '8px', background: 'var(--bg-secondary)', marginBottom: '6px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <SeverityBadge severity={finding.severity} />
                <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{finding.issue_name || finding.IssueName}</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {finding.file_path || finding.FilePath} : {finding.line_number || finding.LineNumber}
            </div>
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
            .then(r => r.ok ? r.json() : Promise.reject('Failed'))
            .then(data => setScans(data.scans || data || []))
            .catch(() => {})
    }, [])

    const compare = async () => {
        if (!scanA || !scanB) { setError('Select two scan IDs to compare'); return }
        if (scanA === scanB) { setError('Select two different scans'); return }
        setError('')
        setLoading(true)
        try {
            const res = await fetch(`/api/scans/diff?a=${encodeURIComponent(scanA)}&b=${encodeURIComponent(scanB)}`)
            if (!res.ok) throw new Error(await res.text())
            setDiff(await res.json())
        } catch (e) {
            setError(e.message || 'Comparison failed')
        } finally {
            setLoading(false)
        }
    }

    const colStyle = (accent) => ({
        flex: 1,
        background: 'var(--bg-card)',
        border: `1px solid ${accent}`,
        borderRadius: '10px',
        padding: '16px',
        minWidth: 0,
    })

    return (
        <div className="animate-fade-in">
            <div className="page-header">
                <h1 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <GitCompare size={24} /> Compare Scans
                </h1>
                <p>Diff two scan results to see new, fixed, and persisting findings</p>
            </div>

            {/* Inputs */}
            <div className="card" style={{ marginBottom: '24px' }}>
                <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: '200px' }}>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                            Scan A (baseline)
                        </label>
                        {scans.length > 0 ? (
                            <select className="input" value={scanA} onChange={e => setScanA(e.target.value)} style={{ appearance: 'auto' }}>
                                <option value="">Select a scan…</option>
                                {scans.map(s => <option key={s.id} value={s.id}>{s.target || s.id} — {s.created_at?.slice(0, 10) || ''}</option>)}
                            </select>
                        ) : (
                            <input className="input" type="text" value={scanA} onChange={e => setScanA(e.target.value)} placeholder="Scan ID A" />
                        )}
                    </div>
                    <div style={{ flex: 1, minWidth: '200px' }}>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                            Scan B (compare to)
                        </label>
                        {scans.length > 0 ? (
                            <select className="input" value={scanB} onChange={e => setScanB(e.target.value)} style={{ appearance: 'auto' }}>
                                <option value="">Select a scan…</option>
                                {scans.map(s => <option key={s.id} value={s.id}>{s.target || s.id} — {s.created_at?.slice(0, 10) || ''}</option>)}
                            </select>
                        ) : (
                            <input className="input" type="text" value={scanB} onChange={e => setScanB(e.target.value)} placeholder="Scan ID B" />
                        )}
                    </div>
                    <button className="btn btn-primary" onClick={compare} disabled={loading} style={{ height: '42px', minWidth: '130px' }}>
                        {loading ? <><RefreshCw size={14} className="animate-spin" /> Comparing…</> : <><GitCompare size={14} /> Compare</>}
                    </button>
                </div>
                {error && <p style={{ color: 'var(--text-danger)', fontSize: '0.82rem', marginTop: '10px' }}>{error}</p>}
            </div>

            {diff && (
                <>
                    {/* Summary bar */}
                    <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginBottom: '20px' }}>
                        {[
                            { label: 'Total A', value: diff.total_a ?? 0, color: '#94a3b8' },
                            { label: 'Total B', value: diff.total_b ?? 0, color: '#94a3b8' },
                            { label: 'Delta', value: (diff.total_b ?? 0) - (diff.total_a ?? 0), color: '#6366f1', prefix: true },
                            { label: 'Critical Δ', value: (diff.delta_critical ?? 0), color: '#ef4444', prefix: true },
                            { label: 'High Δ', value: (diff.delta_high ?? 0), color: '#f97316', prefix: true },
                        ].map(({ label, value, color, prefix }) => (
                            <div key={label} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-primary)', borderRadius: '10px', padding: '12px 20px', textAlign: 'center', minWidth: '100px' }}>
                                <div style={{ fontSize: '1.6rem', fontWeight: 800, color }}>
                                    {prefix && value > 0 ? '+' : ''}{value}
                                </div>
                                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>{label}</div>
                            </div>
                        ))}
                    </div>

                    {/* Three-column diff */}
                    <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
                        <div style={colStyle('#ef4444')}>
                            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem', fontWeight: 700, marginBottom: '12px', color: '#ef4444' }}>
                                <AlertTriangle size={16} /> New Findings
                                <span style={{ background: '#ef4444', color: '#fff', borderRadius: '10px', padding: '1px 8px', fontSize: '0.72rem' }}>{(diff.new_findings || []).length}</span>
                            </h3>
                            {(diff.new_findings || []).length === 0
                                ? <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>No new findings.</p>
                                : (diff.new_findings || []).map((f, i) => <FindingCard key={i} finding={f} />)}
                        </div>

                        <div style={colStyle('#22c55e')}>
                            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem', fontWeight: 700, marginBottom: '12px', color: '#22c55e' }}>
                                <CheckCircle size={16} /> Fixed Findings
                                <span style={{ background: '#22c55e', color: '#fff', borderRadius: '10px', padding: '1px 8px', fontSize: '0.72rem' }}>{(diff.fixed_findings || []).length}</span>
                            </h3>
                            {(diff.fixed_findings || []).length === 0
                                ? <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>No fixed findings.</p>
                                : (diff.fixed_findings || []).map((f, i) => <FindingCard key={i} finding={f} />)}
                        </div>

                        <div style={colStyle('#94a3b8')}>
                            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem', fontWeight: 700, marginBottom: '12px', color: '#94a3b8' }}>
                                <MinusCircle size={16} /> Persisting
                                <span style={{ background: '#94a3b8', color: '#fff', borderRadius: '10px', padding: '1px 8px', fontSize: '0.72rem' }}>{(diff.persisting_findings || []).length}</span>
                            </h3>
                            {(diff.persisting_findings || []).length === 0
                                ? <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>No persisting findings.</p>
                                : (diff.persisting_findings || []).map((f, i) => <FindingCard key={i} finding={f} />)}
                        </div>
                    </div>
                </>
            )}
        </div>
    )
}
