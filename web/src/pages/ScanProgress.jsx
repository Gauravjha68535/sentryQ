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
        if (Notification.permission === 'default') Notification.requestPermission()
    }, [])

    useEffect(() => {
        let reconnectTimer = null
        let reconnectDelay = 1000
        let destroyed = false
        const maxReconnectDelay = 16000

        const connect = () => {
            if (destroyed) return
            const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
            const wsUrl = `${protocol}://${window.location.host}/ws/scan/${id}`
            const ws = new WebSocket(wsUrl)
            wsRef.current = ws

            ws.onopen = () => {
                reconnectDelay = 1000 // reset backoff on successful connect
                setStatus(prev => prev === 'connecting' ? 'running' : prev)
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
                            if (document.visibilityState !== 'visible' || !document.hasFocus()) {
                                if (Notification.permission === 'granted') {
                                    new Notification('SentryQ: Scan Complete', { body: `Scan ${id} finished successfully.`, icon: '/favicon.ico' })
                                }
                            }
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

            ws.onclose = (event) => {
                if (destroyed) return
                // Don't reconnect if scan is already done
                setStatus(prev => {
                    if (prev === 'completed' || prev === 'failed' || prev === 'stopped') return prev
                    addLog(`Connection lost — reconnecting in ${reconnectDelay / 1000}s...`, 'warning')
                    reconnectTimer = setTimeout(() => {
                        reconnectDelay = Math.min(reconnectDelay * 2, maxReconnectDelay)
                        connect()
                    }, reconnectDelay)
                    return prev
                })
            }

            ws.onerror = () => {
                // onclose fires after onerror, so reconnect is handled there
                addLog('WebSocket error.', 'warning')
            }
        }

        connect()

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
            destroyed = true
            clearTimeout(reconnectTimer)
            if (wsRef.current) wsRef.current.close()
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
                        {status === 'completed' ? '✅ Scan Complete' : status === 'failed' ? '❌ Scan Failed' : status === 'stopping' || status === 'stopped' ? '🛑 Stopped' : '🔍 Scanning...'}
                    </h1>
                    <p>Scan ID: <code style={{ fontSize: '0.82rem', background: 'var(--bg-elevated)', padding: '2px 8px', borderRadius: '4px' }}>{id}</code></p>
                </div>
                <div style={{ display: 'flex', gap: '12px' }}>
                    {status === 'running' && (
                        <button
                            className="btn"
                            style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.2)' }}
                            onClick={async () => {
                                if (window.confirm("Are you sure you want to stop this scan?")) {
                                    try {
                                        const res = await fetch(`/api/scan/${id}/stop`, {
                                            method: 'POST',
                                            headers: { 'X-API-Key': localStorage.getItem('sentryq_api_key') || '' }
                                        })
                                        if (res.ok) setStatus('stopping')
                                    } catch (e) {
                                        console.error("Failed to stop scan", e)
                                    }
                                }
                            }}
                        >
                            Stop Scan
                        </button>
                    )}
                    {(status === 'stopping' || status === 'stopped') && (
                        <button
                            className="btn"
                            style={{ background: 'rgba(107, 114, 128, 0.1)', color: '#6b7280', border: '1px solid rgba(107, 114, 128, 0.2)', cursor: 'not-allowed' }}
                            disabled
                        >
                            Stopping...
                        </button>
                    )}
                    {status === 'completed' && (
                        <button className="btn btn-primary" onClick={() => navigate(`/scan/${id}/report`)}>
                            <FileText size={18} /> View Report
                        </button>
                    )}
                </div>
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
