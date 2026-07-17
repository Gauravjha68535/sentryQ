import { useState, useEffect, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { PlusCircle, Clock, CheckCircle, XCircle, Trash2, ScanSearch, Sun, Moon } from 'lucide-react'
import { motion } from 'framer-motion'
import SeverityBadge from '../components/SeverityBadge'
import StatCard from '../components/StatCard'
import { useToast } from '../components/Toast'
import { useConfirm } from '../components/ConfirmModal'
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler } from 'chart.js'
import { Line } from 'react-chartjs-2'
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler)

export default function Dashboard() {
    const [scans, setScans] = useState([])
    const [loading, setLoading] = useState(true)
    const [fetchError, setFetchError] = useState(false)
    const [isLightMode, setIsLightMode] = useState(() => document.documentElement.getAttribute('data-theme') === 'light')
    const navigate = useNavigate()
    const toast = useToast()
    const confirm = useConfirm()

    const toggleTheme = () => {
        const newTheme = isLightMode ? 'dark' : 'light'
        setIsLightMode(!isLightMode)
        document.documentElement.setAttribute('data-theme', newTheme)
        localStorage.setItem('theme', newTheme)
    }

    const fetchScans = useCallback(async () => {
        try {
            const res = await fetch('/api/scans')
            if (res.ok) {
                setScans(await res.json() || [])
                setFetchError(false)
            } else {
                setFetchError(true)
            }
        } catch {
            setFetchError(true)
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => {
        fetchScans()
        const interval = setInterval(fetchScans, 5000)
        return () => clearInterval(interval)
    }, [fetchScans])

    const deleteScan = async (id, e) => {
        e.stopPropagation()
        const ok = await confirm('Delete this scan and all its data? This cannot be undone.', 'Delete Scan')
        if (!ok) return
        try {
            const res = await fetch(`/api/scan/${id}`, { method: 'DELETE' })
            if (!res.ok) throw new Error(`HTTP ${res.status}`)
            toast.success('Scan deleted')
            fetchScans()
        } catch (err) {
            toast.error(`Failed to delete scan: ${err.message}`)
        }
    }

    const statusIcon = (status) => {
        switch (status) {
            case 'running':   return <Clock size={16} className="animate-pulse" style={{ color: 'var(--status-running)' }} />
            case 'completed': return <CheckCircle size={16} style={{ color: 'var(--status-success)' }} />
            case 'failed':    return <XCircle size={16} style={{ color: 'var(--status-failed)' }} />
            default:          return <Clock size={16} style={{ color: 'var(--text-muted)' }} />
        }
    }

    const { totalFindings, completedScans, criticalTotal, highTotal } = useMemo(() => ({
        totalFindings:  scans.reduce((s, x) => s + (x.total_findings || 0), 0),
        completedScans: scans.filter(s => s.status === 'completed').length,
        criticalTotal:  scans.reduce((s, x) => s + (x.critical_count || 0), 0),
        highTotal:      scans.reduce((s, x) => s + (x.high_count || 0), 0),
    }), [scans])

    const trendData = useMemo(() => {
        const completed = [...scans]
            .filter(s => s.status === 'completed' && s.created_at)
            .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
            .slice(-10)
        return {
            labels: completed.map(s => new Date(s.created_at).toLocaleDateString()),
            datasets: [
                { label: 'Total Findings', data: completed.map(s => s.total_findings || 0), borderColor: '#6366f1', backgroundColor: 'rgba(99,102,241,0.1)', fill: true, tension: 0.4, pointRadius: 4 },
                { label: 'Critical + High', data: completed.map(s => (s.critical_count || 0) + (s.high_count || 0)), borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.08)', fill: true, tension: 0.4, pointRadius: 4 },
            ],
        }
    }, [scans])

    const policyBadge = (scan) => {
        try {
            const cfg = typeof scan.config === 'string' ? JSON.parse(scan.config) : (scan.config || {})
            const hasPolicy = cfg.policyFailOn || (cfg.maxCritical >= 0 && cfg.maxCritical !== -1) || (cfg.maxHigh >= 0 && cfg.maxHigh !== -1) || (cfg.maxTotal >= 0 && cfg.maxTotal !== -1)
            if (!hasPolicy) return null
            const violated = (
                (cfg.maxCritical >= 0 && scan.critical_count > cfg.maxCritical) ||
                (cfg.maxHigh >= 0 && scan.high_count > cfg.maxHigh) ||
                (cfg.maxTotal >= 0 && scan.total_findings > cfg.maxTotal) ||
                (cfg.policyFailOn === 'critical' && scan.critical_count > 0) ||
                (cfg.policyFailOn === 'high' && (scan.critical_count + scan.high_count) > 0)
            )
            return <span className={`policy-badge ${violated ? 'policy-fail' : 'policy-pass'}`}>{violated ? '✗ POLICY FAIL' : '✓ POLICY PASS'}</span>
        } catch { return null }
    }

    return (
        <div className="animate-fade-in">
            <div className="page-header-row">
                <div>
                    <h1>Dashboard</h1>
                    <p>Welcome to SentryQ — your AI-powered code analysis platform</p>
                </div>
                <div className="page-actions">
                    <button className="btn btn-secondary" onClick={toggleTheme} aria-label="Toggle Theme" title={isLightMode ? 'Switch to Dark Mode' : 'Switch to Light Mode'} style={{ padding: '8px' }}>
                        {isLightMode ? <Moon size={18} /> : <Sun size={18} />}
                    </button>
                    <button className="btn btn-primary" onClick={() => navigate('/scan/new')}>
                        <PlusCircle size={18} /> New Scan
                    </button>
                </div>
            </div>

            {fetchError && (
                <div className="toast toast-error" style={{ marginBottom: '16px', position: 'static', animation: 'none' }}>
                    <XCircle size={15} /> Unable to reach the backend. Check that SentryQ is running and refresh.
                </div>
            )}

            <div className="stats-grid">
                <StatCard label="Total Scans" value={scans.length} />
                <StatCard label="Completed" value={completedScans} color="var(--status-success)" />
                <StatCard label="Total Findings" value={totalFindings} />
                <StatCard label="Critical + High" value={criticalTotal + highTotal} color="var(--severity-critical)" />
            </div>

            {trendData.labels.length >= 2 && (
                <div className="card" style={{ marginBottom: '24px', padding: '20px' }}>
                    <h3 className="chart-header">Findings Trend (Last 10 Scans)</h3>
                    <div style={{ height: '180px' }}>
                        <Line data={trendData} options={{
                            responsive: true, maintainAspectRatio: false,
                            plugins: { legend: { labels: { color: 'var(--text-secondary)', font: { size: 11 } } } },
                            scales: {
                                x: { ticks: { color: 'var(--text-muted)', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.05)' } },
                                y: { ticks: { color: 'var(--text-muted)', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
                            },
                        }} />
                    </div>
                </div>
            )}

            {loading ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {[1, 2, 3].map(i => <div key={i} className="skeleton skeleton-card" />)}
                </div>
            ) : scans.length === 0 ? (
                <div className="card text-center" style={{ padding: '60px 40px' }}>
                    <ScanSearch size={48} style={{ color: 'var(--text-muted)', marginBottom: '16px' }} />
                    <h3 style={{ marginBottom: '8px', color: 'var(--text-secondary)' }}>No scans yet</h3>
                    <p style={{ color: 'var(--text-muted)', marginBottom: '24px' }}>Start your first security scan to see results here.</p>
                    <button className="btn btn-primary" onClick={() => navigate('/scan/new')}>
                        <PlusCircle size={18} /> Start First Scan
                    </button>
                </div>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {scans.map(scan => (
                        <motion.div
                            key={scan.id}
                            className="card"
                            whileHover={{ scale: 1.005, boxShadow: '0 0 0 1px var(--accent-primary), 0 0 20px rgba(99,102,241,0.15)' }}
                            style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '16px' }}
                            onClick={() => navigate(scan.status === 'completed' ? `/scan/${scan.id}/report` : `/scan/${scan.id}`)}
                        >
                            {statusIcon(scan.status)}
                            <div style={{ flex: 1 }}>
                                <div style={{ fontWeight: 600, fontSize: '0.92rem', marginBottom: '4px' }}>
                                    {scan.target || 'Unnamed Scan'}
                                </div>
                                <div className="scan-meta">
                                    <span>{scan.source_type === 'git' ? '🔗 Git Clone' : '📁 Upload'}</span>
                                    <span>{new Date(scan.created_at).toLocaleString()}</span>
                                </div>
                            </div>
                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                {scan.status === 'completed' && (
                                    <>
                                        {scan.critical_count > 0 && <SeverityBadge severity="critical" />}
                                        {scan.high_count > 0 && <SeverityBadge severity="high" />}
                                        <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
                                            {scan.total_findings} findings
                                        </span>
                                        {policyBadge(scan)}
                                    </>
                                )}
                                {scan.status === 'running' && (
                                    <span style={{ fontSize: '0.78rem', color: 'var(--status-running)', fontWeight: 600 }}>Scanning...</span>
                                )}
                            </div>
                            <button className="btn btn-danger btn-sm" onClick={(e) => deleteScan(scan.id, e)} style={{ padding: '6px 8px' }}>
                                <Trash2 size={14} />
                            </button>
                        </motion.div>
                    ))}
                </div>
            )}
        </div>
    )
}
