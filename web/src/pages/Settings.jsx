import React, { useState, useEffect } from 'react'
import { Save, RefreshCw, Cpu, Server, HardDrive } from 'lucide-react'

export default function Settings() {
    const [settings, setSettings] = useState({
        ollama_host: 'localhost:11434',
        default_model: '',
    })
    const [saved, setSaved] = useState(false)
    const [systemStatus, setSystemStatus] = useState(null)

    useEffect(() => {
        fetchSettings()
        fetchSystemStatus()
    }, [])

    const fetchSettings = async () => {
        try {
            const res = await fetch('/api/settings')
            if (res.ok) {
                const data = await res.json()
                setSettings(data)
            }
        } catch { /* use defaults */ }
    }

    const fetchSystemStatus = async () => {
        try {
            const res = await fetch('/api/system/status')
            if (res.ok) setSystemStatus(await res.json())
        } catch { /* ignore */ }
    }

    const handleChange = (e) => {
        const { name, value } = e.target;
        setSettings(prev => ({ ...prev, [name]: value }));
    };

    const saveSettings = async () => {
        try {
            const res = await fetch('/api/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings),
            })
            if (res.ok) {
                setSaved(true)
                setTimeout(() => setSaved(false), 3000)
            }
        } catch (e) {
            alert(`Failed to save: ${e.message}`)
        }
    }

    return (
        <div className="animate-fade-in">
            <div className="page-header">
                <h1>Settings</h1>
                <p>Configure your scanner preferences and AI model connection</p>
            </div>

            <div className="grid-2">
                {/* AI Configuration */}
                <div className="card">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '24px' }}>
                        <Cpu size={20} style={{ color: 'var(--accent-primary-hover)' }} />
                        <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>AI Configuration</h3>
                    </div>

                    <div style={{ marginBottom: '20px' }}>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                            Ollama Host
                        </label>
                        <input
                            className="input"
                            type="text"
                            name="ollama_host"
                            value={settings.ollama_host}
                            onChange={handleChange}
                            placeholder="localhost:11434"
                        />
                        <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                            Use <code>host:port</code> format. For remote GPU servers, use the server's IP (e.g., <code>192.168.1.42:11434</code>)
                        </p>
                    </div>

                    <div style={{ marginBottom: '20px' }}>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                            Default AI Model
                        </label>
                        <input
                            className="input"
                            type="text"
                            name="default_model"
                            value={settings.default_model}
                            onChange={handleChange}
                            placeholder="Enter default model (e.g. qwen2.5-coder)"
                        />
                    </div>

                    <button className="btn btn-primary" onClick={saveSettings}>
                        <Save size={16} /> {saved ? '✓ Saved!' : 'Save Settings'}
                    </button>
                </div>

                {/* System Diagnostics */}
                <div className="card">
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <Server size={20} style={{ color: 'var(--accent-primary-hover)' }} />
                            <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>System Diagnostics</h3>
                        </div>
                        <button className="btn btn-secondary btn-sm" onClick={fetchSystemStatus}>
                            <RefreshCw size={14} /> Refresh
                        </button>
                    </div>

                    {systemStatus ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            {Object.entries(systemStatus).map(([key, val]) => (
                                <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border-primary)' }}>
                                    <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 500 }}>{key}</span>
                                    <span style={{ fontSize: '0.85rem', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                                        {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                                    </span>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>Loading diagnostics...</p>
                    )}
                </div>
            </div>
        </div>
    )
}
