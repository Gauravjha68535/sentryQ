import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { CheckCircle, XCircle, Loader2, FileText, PauseCircle, Bell } from 'lucide-react'
import StatCard from '../components/StatCard'
import { useConfirm } from '../components/ConfirmModal'
import { useToast } from '../components/Toast'

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
    const statusRef = useRef('connecting')
    const [notifGranted, setNotifGranted] = useState(
        typeof Notification !== 'undefined' && Notification.permission === 'granted'
    )
    const confirm = useConfirm()
    const toast = useToast()

    const requestNotifications = useCallback(async () => {
        if (!('Notification' in window)) return
        const perm = await Notification.requestPermission()
        setNotifGranted(perm === 'granted')
        if (perm === 'granted') toast.success('Desktop notifications enabled')
    }, [toast])

    useEffect(() => {
        let reconnectTimer = null
        let reconnectDelay = 1000
        let destroyed = false
        const maxReconnectDelay = 16000

        const connect = () => {
            if (destroyed) return
            const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
            const ws = new WebSocket(`${protocol}://${window.location.host}/ws/scan/${id}`)
            wsRef.current = ws

            ws.onopen = () => {
                reconnectDelay = 1000
                setStatus(prev => prev === 'connecting' ? 'running' : prev)
                addLog('Connected to scan engine...', 'info')
            }

            ws.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data)
                    switch (msg.type) {
                        case 'log':           addLog(msg.message, msg.level || 'info'); break
                        case 'progress':      setProgress(msg.percent || 0); setPhase(msg.phase || ''); break
                        case 'findings_update': setFindingsCount(msg.count || 0); break
                        case 'complete':
                            statusRef.current = 'completed'
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
                        case 'paused':  statusRef.current = 'paused';   setStatus('paused');   break
                        case 'resumed': statusRef.current = 'running';  setStatus('running');  break
                        case 'error':
                            statusRef.current = 'failed'
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
                if (destroyed) return
                const cur = statusRef.current
                if (cur === 'completed' || cur === 'failed' || cur === 'stopped' || cur === 'stopping') return
                addLog(`Connection lost — reconnecting in ${reconnectDelay / 1000}s...`, 'warning')
                reconnectTimer = setTimeout(() => {
                    reconnectDelay = Math.min(reconnectDelay * 2, maxReconnectDelay)
                    connect()
                }, reconnectDelay)
            }

            ws.onerror = () => { addLog('WebSocket error.', 'warning') }
        }

        connect()

        const pollInterval = setInterval(async () => {
            try {
                const res = await fetch(`/api/scan/${id}`)
                if (res.ok) {
                    const data = await res.json()
                    if (data.status === 'completed') { statusRef.current = 'completed'; setStatus('completed'); setProgress(100); clearInterval(pollInterval) }
                    else if (data.status === 'failed') { statusRef.current = 'failed'; setStatus('failed'); clearInterval(pollInterval) }
                    else if (data.status === 'stopped') { statusRef.current = 'stopped'; setStatus('stopped'); clearInterval(pollInterval) }
                    else if (data.status === 'paused') { statusRef.current = 'paused'; setStatus('paused') }
                    if (data.total_findings) setFindingsCount(data.total_findings)
                }
            } catch { /* ignore poll errors */ }
        }, 3000)

        return () => {
            destroyed = true
            clearTimeout(reconnectTimer)
            if (wsRef.current) wsRef.current.close()
            clearInterval(pollInterval)
        }
    }, [id])

    useEffect(() => {
        if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }, [logs])

    const addLog = (message, level = 'info') =>
        setLogs(prev => [...prev, { message, level, time: new Date().toLocaleTimeString() }])

    const apiPost = async (action) => {
        try {
            const res = await fetch(`/api/scan/${id}/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' } })
            return res.ok
        } catch { return false }
    }

    const statusTitle = {
        completed: '✅ Scan Complete',
        failed:    '❌ Scan Failed',
        stopping:  '🛑 Stopping...',
        stopped:   '🛑 Stopped',
        paused:    '⏸ Paused',
    }[status] ?? '🔍 Scanning...'

    return (
        <div className="animate-fade-in">
            <div className="page-header-row">
                <div>
                    <h1>{statusTitle}</h1>
                    <p>Scan ID: <code className="scan-id">{id}</code></p>
                </div>
                <div className="page-actions">
                    {'Notification' in window && Notification.permission !== 'denied' && !notifGranted && (
                        <button className="btn btn-secondary btn-sm" onClick={requestNotifications} title="Get a desktop notification when the scan finishes">
                            <Bell size={14} /> Notify me
                        </button>
                    )}
                    {status === 'running' && (
                        <button className="btn" style={{ background: 'rgba(234,179,8,0.1)', color: '#eab308', border: '1px solid rgba(234,179,8,0.2)' }}
                            onClick={async () => { if (await apiPost('pause')) { statusRef.current = 'paused'; setStatus('paused') } }}>
                            ⏸ Pause
                        </button>
                    )}
                    {status === 'paused' && (
                        <button className="btn" style={{ background: 'rgba(34,197,94,0.1)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.2)' }}
                            onClick={async () => { if (await apiPost('resume')) { statusRef.current = 'running'; setStatus('running') } }}>
                            ▶ Resume
                        </button>
                    )}
                    {(status === 'running' || status === 'paused') && (
                        <button className="btn" style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}
                            onClick={async () => {
                                const ok = await confirm('Stop this scan? Progress so far will be saved.', 'Stop Scan')
                                if (ok) {
                                    if (await apiPost('stop')) { statusRef.current = 'stopping'; setStatus('stopping') }
                                    else toast.error('Failed to stop scan')
                                }
                            }}>
                            Stop Scan
                        </button>
                    )}
                    {(status === 'stopping' || status === 'stopped') && (
                        <button className="btn" style={{ background: 'rgba(107,114,128,0.1)', color: '#6b7280', border: '1px solid rgba(107,114,128,0.2)', cursor: 'not-allowed' }} disabled>
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

            <div className="card" style={{ marginBottom: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                    <span className="phase-text">{phase}</span>
                    <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent-primary-hover)' }}>{progress}%</span>
                </div>
                <div className="progress-bar-container">
                    <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
                </div>
            </div>

            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
                <div className="stat-card">
                    <div className="stat-card-label">Status</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        {status === 'running'   && <Loader2 size={20} className="animate-spin" style={{ color: 'var(--status-running)' }} />}
                        {status === 'completed' && <CheckCircle size={20} style={{ color: 'var(--status-success)' }} />}
                        {status === 'failed'    && <XCircle size={20} style={{ color: 'var(--status-failed)' }} />}
                        {status === 'paused'    && <PauseCircle size={20} style={{ color: '#eab308' }} />}
                        <span style={{ fontSize: '1rem', fontWeight: 700, textTransform: 'capitalize' }}>{status}</span>
                    </div>
                </div>
                <StatCard label="Findings" value={findingsCount} />
                <StatCard label="Log Lines" value={logs.length} />
            </div>

            <div className="terminal" ref={terminalRef}>
                {logs.map((log, i) => (
                    <div key={i} className={`terminal-line ${log.level}`}>
                        <span style={{ color: 'var(--text-muted)', marginRight: '8px', fontSize: '0.72rem' }}>{log.time}</span>
                        {log.message}
                    </div>
                ))}
                {(status === 'running' || status === 'paused') && (
                    <div className="terminal-line terminal-cursor">
                        <span className={status === 'running' ? 'animate-pulse' : ''}>█</span>
                    </div>
                )}
            </div>
        </div>
    )
}
