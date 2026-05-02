import React, { useState, useEffect } from 'react'
import { Save, RefreshCw, Cpu, Server, CheckCircle2, XCircle, Play, List, ExternalLink } from 'lucide-react'

const CLAUDE_MODELS = [
    'claude-opus-4-7',
    'claude-sonnet-4-6',
    'claude-haiku-4-5-20251001',
]

const GEMINI_MODELS = [
    'gemini-2.0-flash',
    'gemini-2.5-flash-preview-04-17',
    'gemini-2.5-pro-preview-05-06',
    'gemini-1.5-pro',
    'gemini-1.5-flash',
]

const OPENAI_PRESETS = [
    { label: 'OpenAI', url: 'https://api.openai.com' },
    { label: 'Groq', url: 'https://api.groq.com/openai' },
    { label: 'OpenRouter', url: 'https://openrouter.ai/api' },
    { label: 'Together AI', url: 'https://api.together.xyz' },
    { label: 'Mistral', url: 'https://api.mistral.ai' },
]

const PROVIDERS = [
    { id: 'ollama', label: 'Ollama', category: 'local' },
    { id: 'lmstudio', label: 'LM Studio', category: 'local' },
    { id: 'claude', label: 'Claude', category: 'cloud' },
    { id: 'gemini', label: 'Gemini', category: 'cloud' },
    { id: 'openai', label: 'Custom API', category: 'cloud' },
]

export default function Settings() {
    const [settings, setSettings] = useState({
        ai_provider: 'ollama',
        default_model: '',
        ollama_host: 'localhost:11434',
        lmstudio_host: 'localhost:1234',
        lmstudio_model: '',
        custom_api_url: '',
        custom_api_key: '',
        custom_model: '',
        claude_api_key: '',
        claude_model: 'claude-sonnet-4-6',
        gemini_api_key: '',
        gemini_model: 'gemini-2.0-flash',
    })
    const [keySet, setKeySet] = useState({ custom: false, claude: false, gemini: false })
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

    // Clear test result whenever provider changes
    useEffect(() => {
        setTestResult(null)
        setAvailableModels([])
    }, [settings.ai_provider])

    const fetchSettings = async () => {
        try {
            const res = await fetch('/api/settings')
            if (!res.ok) return
            const data = await res.json()
            setKeySet({
                custom: !!data.custom_api_key_set,
                claude: !!data.claude_api_key_set,
                gemini: !!data.gemini_api_key_set,
            })
            setSettings(prev => ({
                ...prev,
                ai_provider: data.ai_provider || 'ollama',
                default_model: data.default_model || '',
                ollama_host: data.ollama_host || 'localhost:11434',
                lmstudio_host: data.lmstudio_host || 'localhost:1234',
                lmstudio_model: data.lmstudio_model || '',
                custom_api_url: data.custom_api_url || '',
                custom_api_key: '',
                custom_model: data.custom_model || '',
                claude_api_key: '',
                claude_model: data.claude_model || 'claude-sonnet-4-6',
                gemini_api_key: '',
                gemini_model: data.gemini_model || 'gemini-2.0-flash',
            }))
        } catch (e) {
            console.warn('[Settings] Failed to fetch settings:', e)
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
        const { name, value } = e.target
        setSettings(prev => ({ ...prev, [name]: value }))
    }

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
                fetchSettings()
            }
        } catch (e) {
            alert(`Failed to save: ${e.message}`)
        }
    }

    const testConnection = async () => {
        const provider = settings.ai_provider
        setTesting(true)
        setTestResult(null)
        try {
            const body = { provider }
            if (provider === 'claude') {
                body.api_key = settings.claude_api_key
                body.model = settings.claude_model
            } else if (provider === 'gemini') {
                body.api_key = settings.gemini_api_key
                body.model = settings.gemini_model
            } else if (provider === 'lmstudio') {
                body.url = `http://${settings.lmstudio_host}`
                body.api_key = ''
                body.model = settings.lmstudio_model
            } else {
                body.url = settings.custom_api_url
                body.api_key = settings.custom_api_key
                body.model = settings.custom_model
            }

            const res = await fetch('/api/custom-endpoint/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            })
            if (!res.ok) throw new Error(`HTTP ${res.status}`)
            setTestResult(await res.json())
        } catch (e) {
            setTestResult({ success: false, message: e.message })
        } finally {
            setTesting(false)
        }
    }

    const fetchModels = async () => {
        const provider = settings.ai_provider
        setFetchingModels(true)
        try {
            let url = `/api/custom-endpoint/models?provider=${provider}`
            if (provider === 'lmstudio') {
                url += `&url=${encodeURIComponent('http://' + settings.lmstudio_host)}`
            } else if (provider === 'openai') {
                url += `&url=${encodeURIComponent(settings.custom_api_url)}&api_key=${encodeURIComponent(settings.custom_api_key)}`
            }
            const res = await fetch(url)
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

    const activeProvider = settings.ai_provider
    const localProviders = PROVIDERS.filter(p => p.category === 'local')
    const cloudProviders = PROVIDERS.filter(p => p.category === 'cloud')

    const tabStyle = (id) => ({
        flex: 1,
        padding: '8px 10px',
        borderRadius: '6px',
        fontSize: '0.82rem',
        fontWeight: 600,
        border: 'none',
        cursor: 'pointer',
        transition: 'all 0.2s',
        background: activeProvider === id ? 'var(--bg-secondary)' : 'transparent',
        color: activeProvider === id ? 'var(--text-primary)' : 'var(--text-muted)',
        boxShadow: activeProvider === id ? '0 2px 4px rgba(0,0,0,0.1)' : 'none',
    })

    const labelStyle = {
        fontSize: '0.82rem',
        fontWeight: 600,
        color: 'var(--text-secondary)',
        marginBottom: '8px',
        display: 'block',
    }

    const hintStyle = {
        fontSize: '0.72rem',
        color: 'var(--text-muted)',
        marginTop: '6px',
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
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                        <Cpu size={20} style={{ color: 'var(--accent-primary-hover)' }} />
                        <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>AI Provider</h3>
                    </div>

                    {/* Local providers */}
                    <div style={{ marginBottom: '16px' }}>
                        <label style={{ ...labelStyle, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: '0.72rem' }}>
                            Local
                        </label>
                        <div style={{ display: 'flex', gap: '8px', background: 'var(--bg-tertiary)', padding: '4px', borderRadius: '8px' }}>
                            {localProviders.map(p => (
                                <button key={p.id} style={tabStyle(p.id)} onClick={() => setSettings(prev => ({ ...prev, ai_provider: p.id }))}>
                                    {p.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Cloud providers */}
                    <div style={{ marginBottom: '24px' }}>
                        <label style={{ ...labelStyle, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: '0.72rem' }}>
                            Cloud
                        </label>
                        <div style={{ display: 'flex', gap: '8px', background: 'var(--bg-tertiary)', padding: '4px', borderRadius: '8px' }}>
                            {cloudProviders.map(p => (
                                <button key={p.id} style={tabStyle(p.id)} onClick={() => setSettings(prev => ({ ...prev, ai_provider: p.id }))}>
                                    {p.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* ── Ollama ── */}
                    {activeProvider === 'ollama' && (
                        <div className="animate-fade-in">
                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>Ollama Host</label>
                                <input className="input" type="text" name="ollama_host" value={settings.ollama_host} onChange={handleChange} placeholder="localhost:11434" />
                                <p style={hintStyle}>Use <code>host:port</code> format for local or remote Ollama.</p>
                            </div>
                            <div style={{ marginBottom: '20px' }}>
                                <label style={labelStyle}>Default Model</label>
                                <input className="input" type="text" name="default_model" value={settings.default_model} onChange={handleChange} placeholder="qwen2.5-coder:7b" />
                            </div>
                        </div>
                    )}

                    {/* ── LM Studio ── */}
                    {activeProvider === 'lmstudio' && (
                        <div className="animate-fade-in" style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', marginBottom: '20px', border: '1px solid var(--border-primary)' }}>
                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>LM Studio Host</label>
                                <input className="input" type="text" name="lmstudio_host" value={settings.lmstudio_host} onChange={handleChange} placeholder="localhost:1234" style={{ background: 'var(--bg-secondary)' }} />
                                <p style={hintStyle}>LM Studio exposes an OpenAI-compatible API on port 1234 by default.</p>
                            </div>
                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>Model</label>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                    {availableModels.length > 0 ? (
                                        <select className="input" name="lmstudio_model" value={settings.lmstudio_model} onChange={handleChange} style={{ background: 'var(--bg-secondary)' }}>
                                            <option value="">Select a model...</option>
                                            {availableModels.map(m => <option key={m} value={m}>{m}</option>)}
                                        </select>
                                    ) : (
                                        <input className="input" type="text" name="lmstudio_model" value={settings.lmstudio_model} onChange={handleChange} placeholder="e.g. qwen2.5-coder-7b" style={{ background: 'var(--bg-secondary)' }} />
                                    )}
                                    <button className="btn btn-secondary" onClick={fetchModels} disabled={fetchingModels} title="Fetch models from LM Studio">
                                        <List size={16} />
                                    </button>
                                </div>
                            </div>
                            <TestButton testing={testing} onTest={testConnection} result={testResult} />
                        </div>
                    )}

                    {/* ── Claude ── */}
                    {activeProvider === 'claude' && (
                        <div className="animate-fade-in" style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', marginBottom: '20px', border: '1px solid var(--border-primary)' }}>
                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>
                                    Anthropic API Key
                                    {keySet.claude && <span style={{ marginLeft: '8px', fontSize: '0.72rem', color: 'var(--text-success)', fontWeight: 500 }}>● key saved</span>}
                                </label>
                                <input className="input" type="password" name="claude_api_key" value={settings.claude_api_key} onChange={handleChange} placeholder={keySet.claude ? 'Enter new key to replace…' : 'sk-ant-...'} style={{ background: 'var(--bg-secondary)' }} />
                                <p style={hintStyle}>Get your key at <a href="https://console.anthropic.com/settings/api-keys" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-primary)' }}>console.anthropic.com <ExternalLink size={10} style={{ display: 'inline' }} /></a></p>
                            </div>
                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>Model</label>
                                <select className="input" name="claude_model" value={settings.claude_model} onChange={handleChange} style={{ background: 'var(--bg-secondary)' }}>
                                    {CLAUDE_MODELS.map(m => <option key={m} value={m}>{m}</option>)}
                                </select>
                            </div>
                            <TestButton testing={testing} onTest={testConnection} result={testResult} />
                        </div>
                    )}

                    {/* ── Gemini ── */}
                    {activeProvider === 'gemini' && (
                        <div className="animate-fade-in" style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', marginBottom: '20px', border: '1px solid var(--border-primary)' }}>
                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>
                                    Google AI API Key
                                    {keySet.gemini && <span style={{ marginLeft: '8px', fontSize: '0.72rem', color: 'var(--text-success)', fontWeight: 500 }}>● key saved</span>}
                                </label>
                                <input className="input" type="password" name="gemini_api_key" value={settings.gemini_api_key} onChange={handleChange} placeholder={keySet.gemini ? 'Enter new key to replace…' : 'AIza...'} style={{ background: 'var(--bg-secondary)' }} />
                                <p style={hintStyle}>Get your key at <a href="https://aistudio.google.com/apikey" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-primary)' }}>aistudio.google.com <ExternalLink size={10} style={{ display: 'inline' }} /></a></p>
                            </div>
                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>Model</label>
                                <select className="input" name="gemini_model" value={settings.gemini_model} onChange={handleChange} style={{ background: 'var(--bg-secondary)' }}>
                                    {GEMINI_MODELS.map(m => <option key={m} value={m}>{m}</option>)}
                                </select>
                            </div>
                            <TestButton testing={testing} onTest={testConnection} result={testResult} />
                        </div>
                    )}

                    {/* ── Custom API (OpenAI-compatible) ── */}
                    {activeProvider === 'openai' && (
                        <div className="animate-fade-in" style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', marginBottom: '20px', border: '1px solid var(--border-primary)' }}>
                            {/* Quick presets */}
                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>Quick Presets</label>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                                    {OPENAI_PRESETS.map(preset => (
                                        <button
                                            key={preset.label}
                                            className="btn btn-secondary btn-sm"
                                            onClick={() => setSettings(prev => ({ ...prev, custom_api_url: preset.url }))}
                                            style={{ fontSize: '0.75rem' }}
                                        >
                                            {preset.label}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>API Base URL</label>
                                <input className="input" type="text" name="custom_api_url" value={settings.custom_api_url} onChange={handleChange} placeholder="https://api.openai.com" style={{ background: 'var(--bg-secondary)' }} />
                                <p style={hintStyle}>Any OpenAI-compatible endpoint (OpenAI, Groq, vLLM, LiteLLM…)</p>
                            </div>

                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>
                                    API Key
                                    {keySet.custom && <span style={{ marginLeft: '8px', fontSize: '0.72rem', color: 'var(--text-success)', fontWeight: 500 }}>● key saved</span>}
                                </label>
                                <input className="input" type="password" name="custom_api_key" value={settings.custom_api_key} onChange={handleChange} placeholder={keySet.custom ? 'Enter new key to replace…' : 'sk-...'} style={{ background: 'var(--bg-secondary)' }} />
                            </div>

                            <div style={{ marginBottom: '16px' }}>
                                <label style={labelStyle}>Model</label>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                    {availableModels.length > 0 ? (
                                        <select className="input" name="custom_model" value={settings.custom_model} onChange={handleChange} style={{ background: 'var(--bg-secondary)' }}>
                                            <option value="">Select a model...</option>
                                            {availableModels.map(m => <option key={m} value={m}>{m}</option>)}
                                        </select>
                                    ) : (
                                        <input className="input" type="text" name="custom_model" value={settings.custom_model} onChange={handleChange} placeholder="e.g. gpt-4o, llama-3.1-70b" style={{ background: 'var(--bg-secondary)' }} />
                                    )}
                                    <button className="btn btn-secondary" onClick={fetchModels} disabled={fetchingModels} title="Fetch models from /v1/models">
                                        <List size={16} />
                                    </button>
                                </div>
                            </div>

                            <TestButton testing={testing} onTest={testConnection} result={testResult} />
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

function TestButton({ testing, onTest, result }) {
    return (
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <button className="btn btn-secondary btn-sm" onClick={onTest} disabled={testing}>
                <Play size={14} /> {testing ? 'Testing…' : 'Test Connection'}
            </button>
            {result && (
                <span style={{
                    display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', fontWeight: 500,
                    color: result.success ? 'var(--text-success)' : 'var(--text-danger)'
                }}>
                    {result.success ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
                    {result.message}
                </span>
            )}
        </div>
    )
}
