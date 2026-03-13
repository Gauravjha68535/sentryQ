import React, { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { CheckCircle, XCircle, Loader2, FileText } from 'lucide-react'

export default function ScanProgress() {
    const { id } = useParams()
    const navigate = useNavigate()
    const [status, setStatus] = useState('connecting')
    const [logs, setLogs] = useState([])
    const [progress, setProgress] = useState(0)
    const [phase, setPhase] = useState('Initializing...')
    const [findingsCount, setFindingsCount] = useState(0)
    const terminalRef = useRef(null)
    const wsRef = useRef(null)

    useEffect(() => {
        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
        const wsUrl = `${protocol}://${window.location.host}/ws/scan/${id}`
        const ws = new WebSocket(wsUrl)
        wsRef.current = ws

        ws.onopen = () => {
            setStatus('running')
            addLog('Connected to scan engine...', 'info')
        }

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data)
                switch (msg.type) {
                    case 'log':
                        addLog(msg.message, msg.level || 'info')
                        break
                    case 'progress':
                        setProgress(msg.percent || 0)
                        setPhase(msg.phase || '')
                        break
                    case 'findings_update':
                        setFindingsCount(msg.count || 0)
                        break
                    case 'complete':
                        setStatus('completed')
                        setProgress(100)
                        setPhase('Scan Complete')
                        addLog('✅ Scan completed successfully!', 'success')
                        break
                    case 'error':
                        setStatus('failed')
                        addLog(`❌ Error: ${msg.message}`, 'error')
                        break
                    default:
                        addLog(msg.message || JSON.stringify(msg), 'info')
                }
            } catch {
                addLog(event.data, 'info')
            }
        }

        ws.onclose = () => {
            if (status === 'running') {
                addLog('Connection closed.', 'warning')
            }
        }

        ws.onerror = () => {
            setStatus('failed')
            addLog('WebSocket connection error.', 'error')
        }

        // Also poll status via REST as fallback
        const pollInterval = setInterval(async () => {
            try {
                const res = await fetch(`/api/scan/${id}`)
                if (res.ok) {
                    const data = await res.json()
                    if (data.status === 'completed') {
                        setStatus('completed')
                        setProgress(100)
                        clearInterval(pollInterval)
                    } else if (data.status === 'failed') {
                        setStatus('failed')
                        clearInterval(pollInterval)
                    }
                    if (data.total_findings) setFindingsCount(data.total_findings)
                }
            } catch { /* ignore */ }
        }, 3000)

        return () => {
            ws.close()
            clearInterval(pollInterval)
        }
    }, [id])

    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight
        }
    }, [logs])

    const addLog = (message, level = 'info') => {
        setLogs(prev => [...prev, { message, level, time: new Date().toLocaleTimeString() }])
    }

    return (
        <div className="animate-fade-in">
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1>
                        {status === 'completed' ? '✅ Scan Complete' : status === 'failed' ? '❌ Scan Failed' : '🔍 Scanning...'}
                    </h1>
                    <p>Scan ID: <code style={{ fontSize: '0.82rem', background: 'var(--bg-elevated)', padding: '2px 8px', borderRadius: '4px' }}>{id}</code></p>
                </div>
                {status === 'completed' && (
                    <button className="btn btn-primary" onClick={() => navigate(`/scan/${id}/report`)}>
                        <FileText size={18} /> View Report
                    </button>
                )}
            </div>

            {/* Progress Bar */}
            <div className="card" style={{ marginBottom: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>{phase}</span>
                    <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent-primary-hover)' }}>{progress}%</span>
                </div>
                <div className="progress-bar-container">
                    <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
                </div>
            </div>

            {/* Stats Row */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
                <div className="stat-card">
                    <div className="stat-card-label">Status</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        {status === 'running' && <Loader2 size={20} className="animate-spin" style={{ color: 'var(--status-running)' }} />}
                        {status === 'completed' && <CheckCircle size={20} style={{ color: 'var(--status-success)' }} />}
                        {status === 'failed' && <XCircle size={20} style={{ color: 'var(--status-failed)' }} />}
                        <span style={{ fontSize: '1rem', fontWeight: 700, textTransform: 'capitalize' }}>{status}</span>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-card-label">Findings</div>
                    <div className="stat-card-value">{findingsCount}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-card-label">Log Lines</div>
                    <div className="stat-card-value">{logs.length}</div>
                </div>
            </div>

            {/* Terminal */}
            <div className="terminal" ref={terminalRef}>
                {logs.map((log, i) => (
                    <div key={i} className={`terminal-line ${log.level}`}>
                        <span style={{ color: 'var(--text-muted)', marginRight: '8px', fontSize: '0.72rem' }}>{log.time}</span>
                        {log.message}
                    </div>
                ))}
                {status === 'running' && (
                    <div className="terminal-line" style={{ opacity: 0.5 }}>
                        <span className="animate-pulse">█</span>
                    </div>
                )}
            </div>
        </div>
    )
}
