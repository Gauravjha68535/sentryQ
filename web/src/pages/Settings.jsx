import React, { useState, useEffect } from 'react'
import { Save, RefreshCw, Cpu, Server, CheckCircle2, XCircle, Play, List } from 'lucide-react'

export default function Settings() {
    const [settings, setSettings] = useState({
        ollama_host: 'localhost:11434',
        default_model: '',
        ai_provider: 'ollama',
        custom_api_url: '',
        custom_api_key: '',
        custom_model: ''
    })
    const [saved, setSaved] = useState(false)
    const [systemStatus, setSystemStatus] = useState(null)
    const [testResult, setTestResult] = useState(null)
    const [testing, setTesting] = useState(false)
    const [fetchingModels, setFetchingModels] = useState(false)
    const [availableModels, setAvailableModels] = useState([])

    useEffect(() => {
        fetchSettings()
        fetchSystemStatus()
    }, [])

    const fetchSettings = async () => {
        try {
            const res = await fetch('/api/settings')
            if (res.ok) {
                const data = await res.json()
                setSettings({
                    ollama_host: data.ollama_host || 'localhost:11434',
                    default_model: data.default_model || '',
                    ai_provider: data.ai_provider || 'ollama',
                    custom_api_url: data.custom_api_url || '',
                    custom_api_key: data.custom_api_key || '',
                    custom_model: data.custom_model || ''
                })
            }
        } catch (e) {
            console.warn('[Settings] Failed to fetch settings, using defaults:', e)
        }
    }

    const fetchSystemStatus = async () => {
        try {
            const res = await fetch('/api/system/status')
            if (res.ok) setSystemStatus(await res.json())
        } catch (e) {
            console.warn('[Settings] Failed to fetch system status:', e)
        }
    }

    const handleChange = (e) => {
        const { name, value } = e.target;
        setSettings(prev => ({ ...prev, [name]: value }));
    };

    const handleProviderChange = (provider) => {
        setSettings(prev => ({ ...prev, ai_provider: provider }));
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

    const testCustomEndpoint = async () => {
        if (!settings.custom_api_url || !settings.custom_model) {
            setTestResult({ success: false, message: 'URL and Model Name are required to test' })
            return
        }
        setTesting(true)
        setTestResult(null)
        try {
            const res = await fetch('/api/custom-endpoint/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: settings.custom_api_url,
                    api_key: settings.custom_api_key,
                    model: settings.custom_model
                })
            })
            if (!res.ok) throw new Error(`HTTP ${res.status}`)
            const data = await res.json()
            setTestResult(data)
        } catch (e) {
            setTestResult({ success: false, message: e.message })
        } finally {
            setTesting(false)
        }
    }

    const fetchCustomModels = async () => {
        if (!settings.custom_api_url) {
            setTestResult({ success: false, message: 'URL is required to fetch models' })
            return
        }
        setFetchingModels(true)
        try {
            const params = new URLSearchParams({
                url: settings.custom_api_url,
                api_key: settings.custom_api_key
            })
            const res = await fetch(`/api/custom-endpoint/models?${params}`)
            if (!res.ok) throw new Error(`HTTP ${res.status}`)
            const data = await res.json()
            if (data.error) {
                setTestResult({ success: false, message: data.error })
            } else {
                setAvailableModels(data.models || [])
                setTestResult({ success: true, message: `Found ${data.models?.length || 0} models` })
            }
        } catch (e) {
            setTestResult({ success: false, message: e.message })
        } finally {
            setFetchingModels(false)
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
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                        <Cpu size={20} style={{ color: 'var(--accent-primary-hover)' }} />
                        <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>AI Configuration</h3>
                    </div>

                    <div style={{ marginBottom: '24px' }}>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '10px', display: 'block' }}>
                            Active Backend Provider
                        </label>
                        <div style={{ display: 'flex', gap: '12px', background: 'var(--bg-tertiary)', padding: '4px', borderRadius: '8px' }}>
                            <button
                                style={{
                                    flex: 1, padding: '8px 12px', borderRadius: '6px', fontSize: '0.85rem', fontWeight: 600, border: 'none', cursor: 'pointer',
                                    background: settings.ai_provider === 'ollama' ? 'var(--bg-secondary)' : 'transparent',
                                    color: settings.ai_provider === 'ollama' ? 'var(--text-primary)' : 'var(--text-muted)',
                                    boxShadow: settings.ai_provider === 'ollama' ? '0 2px 4px rgba(0,0,0,0.1)' : 'none',
                                    transition: 'all 0.2s'
                                }}
                                onClick={() => handleProviderChange('ollama')}
                            >
                                Ollama
                            </button>
                            <button
                                style={{
                                    flex: 1, padding: '8px 12px', borderRadius: '6px', fontSize: '0.85rem', fontWeight: 600, border: 'none', cursor: 'pointer',
                                    background: settings.ai_provider === 'openai' ? 'var(--bg-secondary)' : 'transparent',
                                    color: settings.ai_provider === 'openai' ? 'var(--text-primary)' : 'var(--text-muted)',
                                    boxShadow: settings.ai_provider === 'openai' ? '0 2px 4px rgba(0,0,0,0.1)' : 'none',
                                    transition: 'all 0.2s'
                                }}
                                onClick={() => handleProviderChange('openai')}
                            >
                                Custom API (OpenAI)
                            </button>
                        </div>
                    </div>

                    {settings.ai_provider === 'ollama' && (
                        <div className="animate-fade-in">
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
                                    Use <code>host:port</code> format.
                                </p>
                            </div>

                            <div style={{ marginBottom: '20px' }}>
                                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                                    Default Model Name
                                </label>
                                <input
                                    className="input"
                                    type="text"
                                    name="default_model"
                                    value={settings.default_model}
                                    onChange={handleChange}
                                    placeholder="e.g. qwen2.5-coder:7b"
                                />
                            </div>
                        </div>
                    )}

                    {settings.ai_provider === 'openai' && (
                        <div className="animate-fade-in" style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', marginBottom: '20px', border: '1px solid var(--border-primary)' }}>
                            <div style={{ marginBottom: '16px' }}>
                                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                                    API Base URL
                                </label>
                                <input
                                    className="input"
                                    type="text"
                                    name="custom_api_url"
                                    value={settings.custom_api_url}
                                    onChange={handleChange}
                                    placeholder="http://10.10.0.11:5005"
                                    style={{ background: 'var(--bg-secondary)' }}
                                />
                                <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                                    Point to an OpenAI-compatible endpoint (vLLM, TGI, LiteLLM)
                                </p>
                            </div>

                            <div style={{ marginBottom: '16px' }}>
                                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                                    API Key (Optional)
                                </label>
                                <input
                                    className="input"
                                    type="password"
                                    name="custom_api_key"
                                    value={settings.custom_api_key}
                                    onChange={handleChange}
                                    placeholder="sk-..."
                                    style={{ background: 'var(--bg-secondary)' }}
                                />
                            </div>

                            <div style={{ marginBottom: '16px' }}>
                                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                                    Model Name
                                </label>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                    {availableModels.length > 0 ? (
                                        <select
                                            className="input"
                                            name="custom_model"
                                            value={settings.custom_model}
                                            onChange={handleChange}
                                            style={{ background: 'var(--bg-secondary)' }}
                                        >
                                            <option value="">Select a model...</option>
                                            {availableModels.map(m => <option key={m} value={m}>{m}</option>)}
                                        </select>
                                    ) : (
                                        <input
                                            className="input"
                                            type="text"
                                            name="custom_model"
                                            value={settings.custom_model}
                                            onChange={handleChange}
                                            placeholder="e.g. Qwen/Qwen3.5-35B-A3B-FP8"
                                            style={{ background: 'var(--bg-secondary)' }}
                                        />
                                    )}
                                    <button 
                                        className="btn btn-secondary" 
                                        onClick={fetchCustomModels}
                                        disabled={fetchingModels}
                                        title="Fetch models from /v1/models"
                                    >
                                        <List size={16} />
                                    </button>
                                </div>
                            </div>
                            
                            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                                <button 
                                    className="btn btn-secondary btn-sm" 
                                    onClick={testCustomEndpoint}
                                    disabled={testing}
                                >
                                    <Play size={14} /> {testing ? 'Testing...' : 'Test Connection'}
                                </button>
                                
                                {testResult && (
                                    <span style={{ 
                                        display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', fontWeight: 500,
                                        color: testResult.success ? 'var(--text-success)' : 'var(--text-danger)'
                                    }}>
                                        {testResult.success ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
                                        {testResult.message}
                                    </span>
                                )}
                            </div>
                        </div>
                    )}

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
