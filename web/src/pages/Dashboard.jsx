import React, { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { PlusCircle, Clock, AlertTriangle, CheckCircle, XCircle, Trash2, ScanSearch } from 'lucide-react'
import { motion } from 'framer-motion'
import SeverityBadge from '../components/SeverityBadge'
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler } from 'chart.js'
import { Line } from 'react-chartjs-2'
ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler)

export default function Dashboard() {
    const [scans, setScans] = useState([])
    const [loading, setLoading] = useState(true)
    const navigate = useNavigate()

    useEffect(() => {
        fetchScans()
        const interval = setInterval(fetchScans, 5000)
        return () => clearInterval(interval)
    }, [])

    const fetchScans = async () => {
        try {
            const res = await fetch('/api/scans')
            if (res.ok) {
                const data = await res.json()
                setScans(data || [])
            }
        } catch (e) {
            console.error('Failed to fetch scans:', e)
        } finally {
            setLoading(false)
        }
    }

    const deleteScan = async (id, e) => {
        e.stopPropagation()
        if (!confirm('Delete this scan and all its data?')) return
        try {
            await fetch(`/api/scan/${id}`, { method: 'DELETE' })
            fetchScans()
        } catch (e) {
            console.error('Delete failed:', e)
        }
    }

    const statusIcon = (status) => {
        switch (status) {
            case 'running': return <Clock size={16} className="animate-pulse" style={{ color: 'var(--status-running)' }} />
            case 'completed': return <CheckCircle size={16} style={{ color: 'var(--status-success)' }} />
            case 'failed': return <XCircle size={16} style={{ color: 'var(--status-failed)' }} />
            default: return <Clock size={16} style={{ color: 'var(--text-muted)' }} />
        }
    }

    const { totalFindings, completedScans, criticalTotal, highTotal } = useMemo(() => ({
        totalFindings: scans.reduce((sum, s) => sum + (s.total_findings || 0), 0),
        completedScans: scans.filter(s => s.status === 'completed').length,
        criticalTotal: scans.reduce((sum, s) => sum + (s.critical_count || 0), 0),
        highTotal: scans.reduce((sum, s) => sum + (s.high_count || 0), 0),
    }), [scans])

    const trendData = useMemo(() => {
        const completed = [...scans]
            .filter(s => s.status === 'completed')
            .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
            .slice(-10)
        return {
            labels: completed.map(s => new Date(s.created_at).toLocaleDateString()),
            datasets: [
                {
                    label: 'Total Findings',
                    data: completed.map(s => s.total_findings || 0),
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99,102,241,0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                },
                {
                    label: 'Critical + High',
                    data: completed.map(s => (s.critical_count || 0) + (s.high_count || 0)),
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239,68,68,0.08)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                },
            ],
        }
    }, [scans])

    return (
        <div className="animate-fade-in">
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1>Dashboard</h1>
                    <p>Welcome to SentryQ — your AI-powered code analysis platform</p>
                </div>
                <button className="btn btn-primary" onClick={() => navigate('/scan/new')}>
                    <PlusCircle size={18} /> New Scan
                </button>
            </div>

            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-card-label">Total Scans</div>
                    <div className="stat-card-value">{scans.length}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-card-label">Completed</div>
                    <div className="stat-card-value" style={{ color: 'var(--status-success)' }}>{completedScans}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-card-label">Total Findings</div>
                    <div className="stat-card-value">{totalFindings}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-card-label">Critical + High</div>
                    <div className="stat-card-value" style={{ color: 'var(--severity-critical)' }}>{criticalTotal + highTotal}</div>
                </div>
            </div>

            {trendData.labels.length >= 2 && (
                <div className="card" style={{ marginBottom: '24px', padding: '20px' }}>
                    <h3 style={{ fontSize: '0.85rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '16px', fontWeight: 700, letterSpacing: '0.05em' }}>Findings Trend (Last 10 Scans)</h3>
                    <div style={{ height: '180px' }}>
                        <Line data={trendData} options={{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: { legend: { labels: { color: 'var(--text-secondary)', font: { size: 11 } } } },
                            scales: {
                                x: { ticks: { color: 'var(--text-muted)', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.05)' } },
                                y: { ticks: { color: 'var(--text-muted)', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
                            },
                        }} />
                    </div>
                </div>
            )}

            {scans.length === 0 && !loading ? (
                <div className="card" style={{ textAlign: 'center', padding: '60px 40px' }}>
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
                            whileHover={{ scale: 1.01, border: '1px solid var(--accent-primary)' }}
                            style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '16px' }}
                            onClick={() => navigate(scan.status === 'completed' ? `/scan/${scan.id}/report` : `/scan/${scan.id}`)}
                        >
                            {statusIcon(scan.status)}
                            <div style={{ flex: 1 }}>
                                <div style={{ fontWeight: 600, fontSize: '0.92rem', marginBottom: '4px' }}>
                                    {scan.target || 'Unnamed Scan'}
                                </div>
                                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'flex', gap: '12px' }}>
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
                                    </>
                                )}
                                {scan.status === 'running' && (
                                    <span style={{ fontSize: '0.78rem', color: 'var(--status-running)', fontWeight: 600 }}>
                                        Scanning...
                                    </span>
                                )}
                            </div>
                            <button
                                className="btn btn-danger btn-sm"
                                onClick={(e) => deleteScan(scan.id, e)}
                                style={{ padding: '6px 8px' }}
                            >
                                <Trash2 size={14} />
                            </button>
                        </motion.div>
                    ))}
                </div>
            )}
        </div>
    )
}
