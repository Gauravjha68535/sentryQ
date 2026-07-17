import React, { useState, useEffect } from 'react'
import { Save, RefreshCw, Cpu, Server, CheckCircle2, XCircle, Play, List, ExternalLink, Bell } from 'lucide-react'
import { useToast } from '../components/Toast'
import FormField from '../components/FormField'

const CLAUDE_MODELS = ['claude-opus-4-8', 'claude-sonnet-4-6', 'claude-haiku-4-5-20251001']
const GEMINI_MODELS = ['gemini-2.0-flash', 'gemini-2.5-flash-preview-04-17', 'gemini-2.5-pro-preview-05-06', 'gemini-1.5-pro', 'gemini-1.5-flash']
const OPENAI_PRESETS = [
    { label: 'OpenAI', url: 'https://api.openai.com' },
    { label: 'Groq', url: 'https://api.groq.com/openai' },
    { label: 'OpenRouter', url: 'https://openrouter.ai/api' },
    { label: 'Together AI', url: 'https://api.together.xyz' },
    { label: 'Mistral', url: 'https://api.mistral.ai' },
]
const LOCAL_PROVIDERS  = [{ id: 'ollama', label: 'Ollama' }, { id: 'lmstudio', label: 'LM Studio' }]
const CLOUD_PROVIDERS  = [{ id: 'claude', label: 'Claude' }, { id: 'gemini', label: 'Gemini' }, { id: 'openai', label: 'Custom API' }]

function TestButton({ testing, onTest, result }) {
    return (
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <button className="btn btn-secondary btn-sm" onClick={onTest} disabled={testing}>
                <Play size={14} /> {testing ? 'Testing…' : 'Test Connection'}
            </button>
            {result && (
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', fontWeight: 500, color: result.success ? 'var(--text-success)' : 'var(--text-danger)' }}>
                    {result.success ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
                    {result.message}
                </span>
            )}
        </div>
    )
}

export default function Settings() {
    const toast = useToast()
    const [settings, setSettings] = useState({
        ai_provider: 'ollama', default_model: '', ollama_host: 'localhost:11434',
        lmstudio_host: 'localhost:1234', lmstudio_model: '',
        custom_api_url: '', custom_api_key: '', custom_model: '',
        claude_api_key: '', claude_model: 'claude-sonnet-4-6',
        gemini_api_key: '', gemini_model: 'gemini-2.0-flash', webhook_urls: '',
    })
    const [keySet, setKeySet] = useState({ custom: false, claude: false, gemini: false })
    const [saved, setSaved] = useState(false)
    const [systemStatus, setSystemStatus] = useState(null)
    const [testResult, setTestResult] = useState(null)
    const [testing, setTesting] = useState(false)
    const [fetchingModels, setFetchingModels] = useState(false)
    const [availableModels, setAvailableModels] = useState([])

    useEffect(() => { fetchSettings(); fetchSystemStatus() }, [])
    useEffect(() => { setTestResult(null); setAvailableModels([]) }, [settings.ai_provider])

    const fetchSettings = async () => {
        try {
            const res = await fetch('/api/settings')
            if (!res.ok) return
            const d = await res.json()
            setKeySet({ custom: !!d.custom_api_key_set, claude: !!d.claude_api_key_set, gemini: !!d.gemini_api_key_set })
            setSettings(prev => ({
                ...prev,
                ai_provider: d.ai_provider || 'ollama', default_model: d.default_model || '',
                ollama_host: d.ollama_host || 'localhost:11434', lmstudio_host: d.lmstudio_host || 'localhost:1234',
                lmstudio_model: d.lmstudio_model || '', custom_api_url: d.custom_api_url || '',
                custom_api_key: '', custom_model: d.custom_model || '', claude_api_key: '',
                claude_model: d.claude_model || 'claude-sonnet-4-6', gemini_api_key: '',
                gemini_model: d.gemini_model || 'gemini-2.0-flash', webhook_urls: d.webhook_urls || '',
            }))
        } catch (e) { console.warn('[Settings] Failed to fetch settings:', e) }
    }

    const fetchSystemStatus = async () => {
        try { const r = await fetch('/api/system/status'); if (r.ok) setSystemStatus(await r.json()) } catch {}
    }

    const set = (name, value) => setSettings(prev => ({ ...prev, [name]: value }))
    const handleChange = e => set(e.target.name, e.target.value)

    const saveSettings = async () => {
        try {
            const res = await fetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings) })
            if (res.ok) {
                toast.success('Settings saved')
                setSaved(true)
                setTimeout(() => setSaved(false), 3000)
                fetchSettings()
            } else {
                toast.error('Failed to save settings')
            }
        } catch (e) { toast.error(`Failed to save: ${e.message}`) }
    }

    const testConnection = async () => {
        setTesting(true); setTestResult(null)
        try {
            const provider = settings.ai_provider
            const body = { provider,
                ...(provider === 'claude'   ? { api_key: settings.claude_api_key, model: settings.claude_model } : {}),
                ...(provider === 'gemini'   ? { api_key: settings.gemini_api_key, model: settings.gemini_model } : {}),
                ...(provider === 'lmstudio' ? { url: `http://${settings.lmstudio_host}`, api_key: '', model: settings.lmstudio_model } : {}),
                ...(provider === 'openai'   ? { url: settings.custom_api_url, api_key: settings.custom_api_key, model: settings.custom_model } : {}),
            }
            const res = await fetch('/api/custom-endpoint/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
            if (!res.ok) throw new Error(`HTTP ${res.status}`)
            setTestResult(await res.json())
        } catch (e) { setTestResult({ success: false, message: e.message }) }
        finally { setTesting(false) }
    }

    const fetchModels = async () => {
        const provider = settings.ai_provider
        setFetchingModels(true)
        try {
            let url = `/api/custom-endpoint/models?provider=${provider}`
            if (provider === 'lmstudio') url += `&url=${encodeURIComponent('http://' + settings.lmstudio_host)}`
            else if (provider === 'openai') url += `&url=${encodeURIComponent(settings.custom_api_url)}&api_key=${encodeURIComponent(settings.custom_api_key)}`
            const res = await fetch(url)
            const data = await res.json()
            if (data.error) setTestResult({ success: false, message: data.error })
            else { setAvailableModels(data.models || []); setTestResult({ success: true, message: `Found ${data.models?.length || 0} models` }) }
        } catch (e) { setTestResult({ success: false, message: e.message }) }
        finally { setFetchingModels(false) }
    }

    const p = settings.ai_provider
    const keyHint = (field) => keySet[field] ? <span style={{ marginLeft: '8px', fontSize: '0.72rem', color: 'var(--text-success)', fontWeight: 500 }}>● key saved</span> : null

    return (
        <div className="animate-fade-in">
            <div className="page-header">
                <h1>Settings</h1>
                <p>Configure your scanner preferences and AI model connection</p>
            </div>

            <div className="grid-2">
                {/* AI Configuration */}
                <div className="card">
                    <div className="section-title" style={{ marginBottom: '20px' }}>
                        <Cpu size={20} style={{ color: 'var(--accent-primary-hover)' }} />
                        <h3>AI Provider</h3>
                    </div>

                    <div style={{ marginBottom: '16px' }}>
                        <label className="form-label" style={{ textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: '0.72rem' }}>Local</label>
                        <div className="provider-tab-group">
                            {LOCAL_PROVIDERS.map(pr => <button key={pr.id} className={`provider-tab ${p === pr.id ? 'active' : ''}`} onClick={() => set('ai_provider', pr.id)}>{pr.label}</button>)}
                        </div>
                    </div>

                    <div style={{ marginBottom: '24px' }}>
                        <label className="form-label" style={{ textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: '0.72rem' }}>Cloud</label>
                        <div className="provider-tab-group">
                            {CLOUD_PROVIDERS.map(pr => <button key={pr.id} className={`provider-tab ${p === pr.id ? 'active' : ''}`} onClick={() => set('ai_provider', pr.id)}>{pr.label}</button>)}
                        </div>
                    </div>

                    {/* Ollama */}
                    {p === 'ollama' && (
                        <div className="animate-fade-in">
                            <FormField label="Ollama Host" hint={<>Use <code>host:port</code> format for local or remote Ollama.</>} style={{ marginBottom: '16px' }}>
                                <input className="input" type="text" name="ollama_host" value={settings.ollama_host} onChange={handleChange} placeholder="localhost:11434" />
                            </FormField>
                            <FormField label="Default Model" style={{ marginBottom: '20px' }}>
                                <input className="input" type="text" name="default_model" value={settings.default_model} onChange={handleChange} placeholder="qwen2.5-coder:7b" />
                            </FormField>
                        </div>
                    )}

                    {/* LM Studio */}
                    {p === 'lmstudio' && (
                        <div className="animate-fade-in" style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', marginBottom: '20px', border: '1px solid var(--border-primary)' }}>
                            <FormField label="LM Studio Host" hint="LM Studio exposes an OpenAI-compatible API on port 1234 by default." style={{ marginBottom: '16px' }}>
                                <input className="input" type="text" name="lmstudio_host" value={settings.lmstudio_host} onChange={handleChange} placeholder="localhost:1234" style={{ background: 'var(--bg-secondary)' }} />
                            </FormField>
                            <FormField label="Model" style={{ marginBottom: '16px' }}>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                    {availableModels.length > 0
                                        ? <select className="input" name="lmstudio_model" value={settings.lmstudio_model} onChange={handleChange} style={{ background: 'var(--bg-secondary)' }}><option value="">Select a model...</option>{availableModels.map(m => <option key={m} value={m}>{m}</option>)}</select>
                                        : <input className="input" type="text" name="lmstudio_model" value={settings.lmstudio_model} onChange={handleChange} placeholder="e.g. qwen2.5-coder-7b" style={{ background: 'var(--bg-secondary)' }} />}
                                    <button className="btn btn-secondary" onClick={fetchModels} disabled={fetchingModels} title="Fetch models"><List size={16} /></button>
                                </div>
                            </FormField>
                            <TestButton testing={testing} onTest={testConnection} result={testResult} />
                        </div>
                    )}

                    {/* Claude */}
                    {p === 'claude' && (
                        <div className="animate-fade-in" style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', marginBottom: '20px', border: '1px solid var(--border-primary)' }}>
                            <FormField label={<>Anthropic API Key {keyHint('claude')}</>} hint={<>Get your key at <a href="https://console.anthropic.com/settings/api-keys" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-primary)' }}>console.anthropic.com <ExternalLink size={10} style={{ display: 'inline' }} /></a></>} style={{ marginBottom: '16px' }}>
                                <input className="input" type="password" name="claude_api_key" value={settings.claude_api_key} onChange={handleChange} placeholder={keySet.claude ? 'Enter new key to replace…' : 'sk-ant-...'} style={{ background: 'var(--bg-secondary)' }} />
                            </FormField>
                            <FormField label="Model" style={{ marginBottom: '16px' }}>
                                <select className="input" name="claude_model" value={settings.claude_model} onChange={handleChange} style={{ background: 'var(--bg-secondary)' }}>
                                    {CLAUDE_MODELS.map(m => <option key={m} value={m}>{m}</option>)}
                                </select>
                            </FormField>
                            <TestButton testing={testing} onTest={testConnection} result={testResult} />
                        </div>
                    )}

                    {/* Gemini */}
                    {p === 'gemini' && (
                        <div className="animate-fade-in" style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', marginBottom: '20px', border: '1px solid var(--border-primary)' }}>
                            <FormField label={<>Google AI API Key {keyHint('gemini')}</>} hint={<>Get your key at <a href="https://aistudio.google.com/apikey" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-primary)' }}>aistudio.google.com <ExternalLink size={10} style={{ display: 'inline' }} /></a></>} style={{ marginBottom: '16px' }}>
                                <input className="input" type="password" name="gemini_api_key" value={settings.gemini_api_key} onChange={handleChange} placeholder={keySet.gemini ? 'Enter new key to replace…' : 'AIza...'} style={{ background: 'var(--bg-secondary)' }} />
                            </FormField>
                            <FormField label="Model" style={{ marginBottom: '16px' }}>
                                <select className="input" name="gemini_model" value={settings.gemini_model} onChange={handleChange} style={{ background: 'var(--bg-secondary)' }}>
                                    {GEMINI_MODELS.map(m => <option key={m} value={m}>{m}</option>)}
                                </select>
                            </FormField>
                            <TestButton testing={testing} onTest={testConnection} result={testResult} />
                        </div>
                    )}

                    {/* Custom API */}
                    {p === 'openai' && (
                        <div className="animate-fade-in" style={{ background: 'var(--bg-tertiary)', padding: '16px', borderRadius: '8px', marginBottom: '20px', border: '1px solid var(--border-primary)' }}>
                            <FormField label="Quick Presets" style={{ marginBottom: '16px' }}>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                                    {OPENAI_PRESETS.map(pr => <button key={pr.label} className="btn btn-secondary btn-sm" onClick={() => set('custom_api_url', pr.url)} style={{ fontSize: '0.75rem' }}>{pr.label}</button>)}
                                </div>
                            </FormField>
                            <FormField label="API Base URL" hint="Any OpenAI-compatible endpoint (OpenAI, Groq, vLLM, LiteLLM…)" style={{ marginBottom: '16px' }}>
                                <input className="input" type="text" name="custom_api_url" value={settings.custom_api_url} onChange={handleChange} placeholder="https://api.openai.com" style={{ background: 'var(--bg-secondary)' }} />
                            </FormField>
                            <FormField label={<>API Key {keyHint('custom')}</>} style={{ marginBottom: '16px' }}>
                                <input className="input" type="password" name="custom_api_key" value={settings.custom_api_key} onChange={handleChange} placeholder={keySet.custom ? 'Enter new key to replace…' : 'sk-...'} style={{ background: 'var(--bg-secondary)' }} />
                            </FormField>
                            <FormField label="Model" style={{ marginBottom: '16px' }}>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                    {availableModels.length > 0
                                        ? <select className="input" name="custom_model" value={settings.custom_model} onChange={handleChange} style={{ background: 'var(--bg-secondary)' }}><option value="">Select a model...</option>{availableModels.map(m => <option key={m} value={m}>{m}</option>)}</select>
                                        : <input className="input" type="text" name="custom_model" value={settings.custom_model} onChange={handleChange} placeholder="e.g. gpt-4o, llama-3.1-70b" style={{ background: 'var(--bg-secondary)' }} />}
                                    <button className="btn btn-secondary" onClick={fetchModels} disabled={fetchingModels} title="Fetch models from /v1/models"><List size={16} /></button>
                                </div>
                            </FormField>
                            <TestButton testing={testing} onTest={testConnection} result={testResult} />
                        </div>
                    )}

                    <button className="btn btn-primary" onClick={saveSettings}>
                        <Save size={16} /> {saved ? '✓ Saved!' : 'Save Settings'}
                    </button>
                </div>

                {/* Notifications */}
                <div className="card">
                    <div className="section-title" style={{ marginBottom: '20px' }}>
                        <Bell size={20} style={{ color: 'var(--accent-primary-hover)' }} />
                        <h3>Notifications</h3>
                    </div>
                    <FormField label="Webhook URLs" hint="Comma-separated webhook URLs. A JSON payload is POSTed after every scan completes." style={{ marginBottom: '16px' }}>
                        <textarea className="input" name="webhook_urls" rows={4} value={settings.webhook_urls} onChange={handleChange}
                            placeholder="https://hooks.slack.com/..., https://discord.com/api/webhooks/..."
                            style={{ resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', width: '100%' }} />
                    </FormField>
                    <button className="btn btn-primary" onClick={saveSettings}>
                        <Save size={16} /> {saved ? '✓ Saved!' : 'Save Notifications'}
                    </button>
                </div>

                {/* System Diagnostics */}
                <div className="card">
                    <div className="section-header">
                        <div className="section-title">
                            <Server size={20} style={{ color: 'var(--accent-primary-hover)' }} />
                            <h3>System Diagnostics</h3>
                        </div>
                        <button className="btn btn-secondary btn-sm" onClick={fetchSystemStatus}><RefreshCw size={14} /> Refresh</button>
                    </div>
                    {systemStatus ? (
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                            {Object.entries(systemStatus).map(([key, val]) => (
                                <div key={key} className="status-row">
                                    <span className="status-key">{key}</span>
                                    <span className="status-val">{typeof val === 'object' ? JSON.stringify(val) : String(val)}</span>
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
