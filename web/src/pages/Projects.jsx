import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Layers, TrendingDown, TrendingUp, Minus, RefreshCw, ExternalLink, BarChart2, AlertTriangle, ShieldCheck } from 'lucide-react'
import {
    Chart as ChartJS, CategoryScale, LinearScale, PointElement,
    LineElement, Tooltip, Legend, Filler
} from 'chart.js'
import { Line } from 'react-chartjs-2'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler)

// ─── Trend badge ─────────────────────────────────────────────────────────────
function TrendBadge({ trend, delta }) {
    const map = {
        improving: { icon: <TrendingDown size={13} />, color: '#22c55e', label: `${Math.abs(delta)} less` },
        worsening: { icon: <TrendingUp size={13} />, color: '#ef4444', label: `+${delta} more` },
        stable:    { icon: <Minus size={13} />,       color: '#94a3b8', label: 'no change' },
        new:       { icon: <ShieldCheck size={13} />, color: '#6366f1', label: 'first scan' },
    }
    const t = map[trend] || map.new
    return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px',
            color: t.color, fontSize: '0.75rem', fontWeight: 600 }}>
            {t.icon}{t.label}
        </span>
    )
}

// ─── Inline mini trend chart ──────────────────────────────────────────────────
function MiniChart({ points }) {
    if (!points || points.length < 2) return <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Not enough data</span>
    const labels = points.map(p => p.date.slice(5, 16))
    const data = {
        labels,
        datasets: [
            {
                label: 'Total', data: points.map(p => p.total_findings),
                borderColor: '#6366f1', backgroundColor: 'rgba(99,102,241,0.08)',
                tension: 0.3, fill: true, pointRadius: 2,
            },
            {
                label: 'Critical', data: points.map(p => p.critical_count),
                borderColor: '#ef4444', backgroundColor: 'transparent',
                tension: 0.3, fill: false, pointRadius: 2,
            },
        ]
    }
    const opts = {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
        scales: {
            x: { ticks: { color: '#64748b', font: { size: 9 }, maxTicksLimit: 6 }, grid: { display: false } },
            y: { ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true },
        }
    }
    return <div style={{ height: '120px' }}><Line data={data} options={opts} /></div>
}

// ─── Single project card ──────────────────────────────────────────────────────
function ProjectCard({ project, expanded, onToggle, navigate }) {
    const [trend, setTrend] = useState(null)
    const [loadingTrend, setLoadingTrend] = useState(false)
    const abortRef = useRef(null)

    useEffect(() => {
        if (!expanded) return
        if (trend) return // already loaded
        if (abortRef.current) abortRef.current.abort()
        abortRef.current = new AbortController()
        setLoadingTrend(true)
        fetch(`/api/projects/trend?target=${encodeURIComponent(project.target)}&limit=20`, { signal: abortRef.current.signal })
            .then(r => r.ok ? r.json() : [])
            .then(pts => { if (!abortRef.current?.signal.aborted) setTrend(pts) })
            .catch(() => {})
            .finally(() => setLoadingTrend(false))
        return () => abortRef.current?.abort()
    }, [expanded, project.target])

    const sev = (label, count, color) => (
        <div style={{ textAlign: 'center', minWidth: '60px' }}>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color }}>{count}</div>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{label}</div>
        </div>
    )

    return (
        <div className="card" style={{ marginBottom: '12px', transition: 'box-shadow 0.2s' }}>
            {/* Header row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap', cursor: 'pointer' }}
                onClick={onToggle}>
                <div style={{ flex: 1, minWidth: '160px' }}>
                    <div style={{ fontWeight: 700, fontSize: '0.95rem', fontFamily: 'var(--font-mono)',
                        color: 'var(--text-primary)', marginBottom: '2px' }}>
                        {project.display_name}
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {project.total_scans} scan{project.total_scans !== 1 ? 's' : ''} &nbsp;·&nbsp;
                        Last: {project.last_scan_at ? new Date(project.last_scan_at).toLocaleDateString() : '—'}
                    </div>
                </div>

                {/* Severity counts */}
                <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
                    {sev('Critical', project.critical_count, '#ef4444')}
                    {sev('High',     project.high_count,     '#f97316')}
                    {sev('Total',    project.total_findings,  '#6366f1')}
                </div>

                {/* Trend + actions */}
                <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginLeft: 'auto' }}>
                    <TrendBadge trend={project.trend} delta={project.trend_delta} />
                    <button className="btn btn-secondary btn-sm" onClick={e => { e.stopPropagation(); navigate(`/scan/${project.last_scan_id}/report`) }}
                        title="View latest report">
                        <ExternalLink size={13} /> Report
                    </button>
                    <button className="btn btn-secondary btn-sm" onClick={e => { e.stopPropagation(); onToggle() }}
                        title={expanded ? 'Hide trend' : 'Show trend'}>
                        <BarChart2 size={13} /> {expanded ? 'Hide' : 'Trend'}
                    </button>
                </div>
            </div>

            {/* Trend chart — expanded */}
            {expanded && (
                <div style={{ marginTop: '16px', borderTop: '1px solid var(--border-primary)', paddingTop: '16px' }}>
                    {loadingTrend
                        ? <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem', padding: '20px 0' }}>
                            <RefreshCw size={14} className="animate-spin" style={{ display: 'inline', marginRight: '6px' }} />
                            Loading trend data…
                          </div>
                        : <MiniChart points={trend} />}
                </div>
            )}
        </div>
    )
}

// ─── Main Projects page ───────────────────────────────────────────────────────
export default function Projects() {
    const [projects, setProjects] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState('')
    const [search, setSearch] = useState('')
    const [expandedId, setExpandedId] = useState(null)
    const navigate = useNavigate()
    const abortRef = useRef(null)

    const load = () => {
        if (abortRef.current) abortRef.current.abort()
        abortRef.current = new AbortController()
        setLoading(true); setError('')
        fetch('/api/projects', { signal: abortRef.current.signal })
            .then(r => r.ok ? r.json() : Promise.reject(r.statusText))
            .then(d => setProjects(d || []))
            .catch(e => { if (e.name !== 'AbortError') setError('Failed to load projects') })
            .finally(() => setLoading(false))
    }

    useEffect(() => { load(); return () => abortRef.current?.abort() }, [])

    const filtered = projects.filter(p =>
        !search || p.display_name.toLowerCase().includes(search.toLowerCase()) ||
        p.target.toLowerCase().includes(search.toLowerCase())
    )

    // Aggregate stats
    const totalProjects = projects.length
    const totalCritical = projects.reduce((s, p) => s + p.critical_count, 0)
    const totalFindings = projects.reduce((s, p) => s + p.total_findings, 0)
    const improving = projects.filter(p => p.trend === 'improving').length
    const worsening = projects.filter(p => p.trend === 'worsening').length

    return (
        <div className="animate-fade-in">
            <div className="page-header-row">
                <div>
                    <h1 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <Layers size={24} /> Projects
                    </h1>
                    <p>Multi-repo security overview — all scanned codebases in one place</p>
                </div>
                <div className="page-actions">
                    <button className="btn btn-secondary" onClick={load} disabled={loading}>
                        <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
                    </button>
                </div>
            </div>

            {/* Aggregate stat cards */}
            {!loading && projects.length > 0 && (
                <div className="stats-grid" style={{ marginBottom: '24px' }}>
                    {[
                        { label: 'Projects',       value: totalProjects, color: '#6366f1' },
                        { label: 'Total Findings', value: totalFindings, color: '#94a3b8' },
                        { label: 'Critical (all)', value: totalCritical, color: '#ef4444' },
                        { label: 'Improving',      value: improving,     color: '#22c55e' },
                        { label: 'Worsening',      value: worsening,     color: '#f97316' },
                    ].map(({ label, value, color }) => (
                        <div key={label} className="card" style={{ padding: '16px', textAlign: 'center' }}>
                            <div style={{ fontSize: '1.8rem', fontWeight: 800, color }}>{value}</div>
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>{label}</div>
                        </div>
                    ))}
                </div>
            )}

            {/* Search */}
            {projects.length > 3 && (
                <div style={{ marginBottom: '16px' }}>
                    <input className="input" placeholder="Search projects…" value={search}
                        onChange={e => setSearch(e.target.value)}
                        style={{ maxWidth: '320px', fontSize: '0.85rem' }} />
                </div>
            )}

            {/* Error */}
            {error && <p style={{ color: 'var(--text-danger)', marginBottom: '16px' }}>{error}</p>}

            {/* Loading skeleton */}
            {loading && [1, 2, 3].map(i => (
                <div key={i} className="skeleton" style={{ height: '80px', borderRadius: 'var(--radius-lg)', marginBottom: '12px' }} />
            ))}

            {/* Empty state */}
            {!loading && filtered.length === 0 && !error && (
                <div className="card" style={{ textAlign: 'center', padding: '48px' }}>
                    <AlertTriangle size={36} style={{ color: 'var(--text-muted)', marginBottom: '12px' }} />
                    <h3 style={{ color: 'var(--text-secondary)', marginBottom: '8px' }}>
                        {search ? 'No projects match your search' : 'No completed scans yet'}
                    </h3>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        {search ? 'Try a different search term.' : 'Run a scan to see your projects here.'}
                    </p>
                    {!search && (
                        <button className="btn btn-primary" style={{ marginTop: '16px' }}
                            onClick={() => navigate('/scan/new')}>
                            Start a Scan
                        </button>
                    )}
                </div>
            )}

            {/* Project cards */}
            {!loading && filtered.map(p => (
                <ProjectCard
                    key={p.target}
                    project={p}
                    expanded={expandedId === p.target}
                    onToggle={() => setExpandedId(v => v === p.target ? null : p.target)}
                    navigate={navigate}
                />
            ))}
        </div>
    )
}
