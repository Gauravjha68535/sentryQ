import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, GitBranch, FolderUp, Play, Cpu, Search, Shield, Lock, Brain, Box, FileCheck, Globe, Sparkles, FolderOpen, Layers } from 'lucide-react'

const defaultConfig = {
    enableDeepScan: false,
    enableAI: false,
    enableEnsemble: false,
    aiModel: '',
    ollamaHost: 'localhost:11434',
    consolidationModel: '',
    consolidationOllamaHost: '',
    judgeModel: '',
    judgeOllamaHost: '',
    enableMLFPReduction: false,
    customRulesDir: '',
}

export default function NewScan() {
    const [tab, setTab] = useState('upload')
    const [config, setConfig] = useState(defaultConfig)
    const [files, setFiles] = useState(null)
    const [gitUrl, setGitUrl] = useState('')
    const [dragover, setDragover] = useState(false)
    const [uploading, setUploading] = useState(false)
    const [availableModels, setAvailableModels] = useState([])
    const [loadingModels, setLoadingModels] = useState(true)
    const navigate = useNavigate()

    React.useEffect(() => {
        fetchSettings()
        fetchInstalledModels()
    }, [])

    const fetchSettings = async () => {
        try {
            const res = await fetch('/api/settings')
            if (res.ok) {
                const data = await res.json()
                if (data.ollama_host) {
                    setConfig(prev => ({ ...prev, ollamaHost: data.ollama_host }))
                }
            }
        } catch (e) {
            console.error("Failed to fetch settings", e)
        }
    }

    const fetchInstalledModels = async (host = null) => {
        setLoadingModels(true)
        if (host) setAvailableModels([]) // Indicate refresh for remote host
        try {
            const modelUrl = host ? `/api/models?host=${encodeURIComponent(host)}` : '/api/models'
            const res = await fetch(modelUrl)
            if (res.ok) {
                const data = await res.json()
                const models = data.models || []
                setAvailableModels(models)

                if (models.length > 0) {
                    setConfig(prev => {
                        const newConfig = { ...prev }
                        // If host is provided, update selections even if already set
                        if (host || !newConfig.aiModel) newConfig.aiModel = models[0]
                        if (host || !newConfig.consolidationModel) newConfig.consolidationModel = models[models.length - 1]
                        return newConfig
                    })
                } else if (host) {
                    alert(`No models found on Ollama host: ${host}.`)
                }
            } else {
                if (host) alert(`Failed to fetch models from ${host}`)
            }
        } catch (e) {
            console.error("Failed to fetch models", e)
            if (host) alert(`Connection error to ${host}.`)
        } finally {
            setLoadingModels(false)
        }
    }

    const handleDrop = (e) => {
        e.preventDefault()
        setDragover(false)
        const items = e.dataTransfer.items
        if (items && items.length > 0) {
            setFiles(e.dataTransfer.files)
        }
    }

    const handleFileSelect = (e) => {
        setFiles(e.target.files)
    }

    const startScan = async () => {
        setUploading(true)
        try {
            let res
            if (tab === 'upload' && files) {
                const formData = new FormData()
                for (let i = 0; i < files.length; i++) {
                    formData.append('files', files[i])
                }
                formData.append('config', JSON.stringify(config))
                res = await fetch('/api/scan/upload', { method: 'POST', body: formData })
            } else if (tab === 'git' && gitUrl.trim()) {
                res = await fetch('/api/scan/git', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: gitUrl.trim(), config }),
                })
            } else {
                alert('Please provide a folder or Git URL')
                setUploading(false)
                return
            }

            if (res.ok) {
                const data = await res.json()
                navigate(`/scan/${data.scan_id}`)
            } else {
                const err = await res.text()
                alert(`Scan failed to start: ${err}`)
            }
        } catch (e) {
            alert(`Error: ${e.message}`)
        } finally {
            setUploading(false)
        }
    }

    return (
        <div className="animate-fade-in">
            <div className="page-header">
                <h1>New Security Scan</h1>
                <p>Upload a project folder or provide a Git repository URL to start scanning</p>
            </div>

            {/* Source Selection Tabs */}
            <div className="tabs" style={{ maxWidth: '360px' }}>
                <button className={`tab ${tab === 'upload' ? 'active' : ''}`} onClick={() => setTab('upload')}>
                    <FolderUp size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} /> Upload Folder
                </button>
                <button className={`tab ${tab === 'git' ? 'active' : ''}`} onClick={() => setTab('git')}>
                    <GitBranch size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} /> Git Repository
                </button>
            </div>

            <div className="grid-2">
                {/* Left: Source */}
                <div>
                    {tab === 'upload' ? (
                        <div
                            className={`upload-zone ${dragover ? 'dragover' : ''}`}
                            onDragOver={(e) => { e.preventDefault(); setDragover(true) }}
                            onDragLeave={() => setDragover(false)}
                            onDrop={handleDrop}
                            onClick={() => document.getElementById('file-input').click()}
                        >
                            <input
                                id="file-input"
                                type="file"
                                webkitdirectory="true"
                                directory="true"
                                multiple
                                style={{ display: 'none' }}
                                onChange={handleFileSelect}
                            />
                            <div className="upload-zone-icon">📁</div>
                            <h3>{files ? `${files.length} files selected` : 'Drop your project folder here'}</h3>
                            <p>{files ? 'Click to change selection' : 'or click to browse files'}</p>
                        </div>
                    ) : (
                        <div className="card" style={{ padding: '32px' }}>
                            <div style={{ marginBottom: '16px' }}>
                                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                                    Repository URL
                                </label>
                                <input
                                    className="input"
                                    type="text"
                                    placeholder="https://github.com/user/repo.git"
                                    value={gitUrl}
                                    onChange={(e) => setGitUrl(e.target.value)}
                                />
                            </div>
                            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                Supports GitHub, GitLab, and Bitbucket public repositories. The repository will be cloned to a temporary directory for scanning.
                            </p>
                        </div>
                    )}
                </div>

                {/* Right: Scan Config */}
                <div className="card">
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '8px' }}>Scan Configuration</h3>
                    <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '20px', lineHeight: 1.5 }}>
                        Pattern matching, AST analysis, taint analysis, and secret detection run automatically on every scan.
                    </p>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        {/* Deep Scan Toggle */}
                        <div style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '16px', borderRadius: '10px',
                            transition: 'all 0.2s ease',
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <div style={{
                                    width: 36, height: 36, borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    background: config.enableDeepScan ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                                    color: config.enableDeepScan ? '#fff' : 'var(--text-muted)', transition: 'all 0.2s'
                                }}>
                                    <Shield size={18} />
                                </div>
                                <div>
                                    <div style={{ fontSize: '0.88rem', fontWeight: 700 }}>Deep Scan</div>
                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.4, marginTop: '2px' }}>
                                        {config.enableEnsemble ? 'Automatically included in Ensemble Audit' : 'Dependency vulnerabilities, Semgrep rules, supply chain, container (Docker/K8s), and Threat Intel'}
                                    </div>
                                </div>
                            </div>
                            <input
                                type="checkbox"
                                className="checkbox-custom"
                                checked={config.enableDeepScan}
                                onChange={() => setConfig(prev => ({ ...prev, enableDeepScan: !prev.enableDeepScan }))}
                            />
                        </div>

                        {/* AI-Powered Toggle */}
                        <div style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '16px', borderRadius: '10px',
                            transition: 'all 0.2s ease',
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <div style={{
                                    width: 36, height: 36, borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    background: config.enableAI ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                                    color: config.enableAI ? '#fff' : 'var(--text-muted)', transition: 'all 0.2s'
                                }}>
                                    <Brain size={18} />
                                </div>
                                <div>
                                    <div style={{ fontSize: '0.88rem', fontWeight: 700 }}>AI-Powered</div>
                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.4, marginTop: '2px' }}>
                                        {config.enableEnsemble ? 'Automatically included in Ensemble Audit' : 'AI discovery, validation & auto-consolidation (requires Ollama)'}
                                    </div>
                                </div>
                            </div>
                            <input
                                type="checkbox"
                                className="checkbox-custom"
                                checked={config.enableAI}
                                onChange={() => setConfig(prev => ({ ...prev, enableAI: !prev.enableAI }))}
                            />
                        </div>

                        {/* Ensemble Audit Toggle */}
                        <div style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '16px', borderRadius: '10px',
                            transition: 'all 0.2s ease'
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <div style={{
                                    width: 36, height: 36, borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    background: config.enableEnsemble ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                                    color: config.enableEnsemble ? '#fff' : 'var(--text-muted)', transition: 'all 0.2s'
                                }}>
                                    <Layers size={18} />
                                </div>
                                <div>
                                    <div style={{ fontSize: '0.88rem', fontWeight: 700 }}>Ensemble Audit
                                        <span style={{ fontSize: '0.62rem', fontWeight: 600, padding: '2px 6px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--accent-primary)', borderRadius: '4px', marginLeft: '8px' }}>ADVANCED</span>
                                    </div>
                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.4, marginTop: '2px' }}>
                                        3-phase pipeline: Static scan → AI scan → Judge LLM merge. Designed for thorough, long-running audits.
                                    </div>
                                </div>
                            </div>
                            <input
                                type="checkbox"
                                className="checkbox-custom"
                                checked={config.enableEnsemble}
                                onChange={() => setConfig(prev => ({
                                    ...prev,
                                    enableEnsemble: !prev.enableEnsemble,
                                    enableDeepScan: !prev.enableEnsemble ? true : prev.enableDeepScan,
                                    enableAI: !prev.enableEnsemble ? true : prev.enableAI
                                }))}
                            />
                        </div>
                    </div>

                    {/* Ollama Host Configuration - Consolidated & Prominent */}
                    <div style={{ 
                        marginTop: '8px', 
                        padding: '16px', 
                        borderRadius: '12px', 
                        background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(139, 92, 246, 0.08) 100%)', 
                        border: '2px solid rgba(99, 102, 241, 0.25)',
                        boxShadow: '0 4px 12px rgba(0,0,0,0.05)'
                    }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                            <label style={{ fontSize: '0.9rem', fontWeight: 800, color: '#6366f1', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <Globe size={16} /> Ollama Host API
                            </label>
                            {loadingModels && <span className="animate-spin" style={{ fontSize: '0.75rem', color: '#6366f1' }}>⏳</span>}
                        </div>
                        
                        <div style={{ display: 'flex', gap: '10px' }}>
                            <input
                                className="input"
                                type="text"
                                value={config.ollamaHost}
                                onChange={(e) => setConfig(prev => ({ ...prev, ollamaHost: e.target.value }))}
                                placeholder="localhost:11434 or 192.168.1.100:11434"
                                style={{ flex: 1, fontSize: '0.95rem', padding: '10px 12px', background: 'var(--bg-primary)', border: '1px solid rgba(99, 102, 241, 0.2)' }}
                            />
                            <button
                                type="button"
                                className="btn btn-primary"
                                onClick={() => fetchInstalledModels(config.ollamaHost)}
                                disabled={loadingModels || !config.ollamaHost}
                                style={{ 
                                    background: 'var(--accent-primary)', 
                                    padding: '0 20px', 
                                    height: '42px', 
                                    fontWeight: 800, 
                                    fontSize: '0.82rem', 
                                    display: 'flex', 
                                    alignItems: 'center', 
                                    gap: '8px',
                                    whiteSpace: 'nowrap',
                                    minWidth: '150px',
                                    boxShadow: '0 4px 15px rgba(99, 102, 241, 0.4)'
                                }}
                            >
                                <Play size={14} fill="currentColor" /> REFRESH MODELS
                            </button>
                        </div>
                        <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '10px', lineHeight: 1.4 }}>
                            Enter your host (e.g., your friend's <b>IP:11434</b>) and click refresh to load available models.
                        </p>
                    </div>

                    {/* AI Model Selections (visible when AI or Ensemble enabled) */}
                    {(config.enableAI || config.enableEnsemble) && (
                        <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px', animation: 'fadeIn 0.3s ease' }}>
                            <div>
                                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                                    Discovery & Validation Model
                                </label>
                                {availableModels.length > 0 ? (
                                    <select
                                        className="input"
                                        value={config.aiModel}
                                        onChange={(e) => setConfig(prev => ({ ...prev, aiModel: e.target.value }))}
                                        style={{ appearance: 'auto' }}
                                    >
                                        {availableModels.map(model => (
                                            <option key={model} value={model}>{model}</option>
                                        ))}
                                    </select>
                                ) : (
                                    <input
                                        className="input"
                                        type="text"
                                        value={config.aiModel}
                                        onChange={(e) => setConfig(prev => ({ ...prev, aiModel: e.target.value }))}
                                        placeholder="e.g. qwen2.5-coder:7b"
                                    />
                                )}
                            </div>

                            <div>
                                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                                    Final Consolidation Model (Larger LLM)
                                </label>
                                {availableModels.length > 0 ? (
                                    <select
                                        className="input"
                                        value={config.consolidationModel}
                                        onChange={(e) => setConfig(prev => ({ ...prev, consolidationModel: e.target.value }))}
                                        style={{ appearance: 'auto' }}
                                    >
                                        {availableModels.map(model => (
                                            <option key={`consol-${model}`} value={model}>{model}</option>
                                        ))}
                                    </select>
                                ) : (
                                    <input
                                        className="input"
                                        type="text"
                                        value={config.consolidationModel}
                                        onChange={(e) => setConfig(prev => ({ ...prev, consolidationModel: e.target.value }))}
                                        placeholder="e.g. qwen2.5-coder:14b"
                                    />
                                )}
                            </div>

                            {config.enableEnsemble && (
                                <div style={{ 
                                    padding: '16px', 
                                    borderRadius: '12px', 
                                    background: 'rgba(99, 102, 241, 0.04)', 
                                    border: '1px solid rgba(99, 102, 241, 0.12)',
                                    marginTop: '8px'
                                }}>
                                    <label style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-primary)', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <Layers size={14} /> Judge Model Configuration
                                    </label>
                                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
                                        The Judge LLM merges independent scan reports into a single consolidated finding.
                                    </div>
                                    {availableModels.length > 0 ? (
                                        <select
                                            className="input"
                                            value={config.judgeModel || config.consolidationModel}
                                            onChange={(e) => setConfig(prev => ({ ...prev, judgeModel: e.target.value }))}
                                            style={{ appearance: 'auto', background: 'var(--bg-secondary)' }}
                                        >
                                            {availableModels.map(model => (
                                                <option key={`judge-${model}`} value={model}>{model}</option>
                                            ))}
                                        </select>
                                    ) : (
                                        <input
                                            className="input"
                                            type="text"
                                            value={config.judgeModel}
                                            onChange={(e) => setConfig(prev => ({ ...prev, judgeModel: e.target.value }))}
                                            placeholder="e.g. llama3.1:8b"
                                            style={{ background: 'var(--bg-secondary)' }}
                                        />
                                    )}
                                </div>
                            )}
                        </div>
                    )}




                    {/* ML FP Reduction Toggle (only when AI or Ensemble enabled) */}
                    {(config.enableAI || config.enableEnsemble) && (
                        <div style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '16px', borderRadius: '10px',
                            transition: 'all 0.2s ease', animation: 'fadeIn 0.3s ease'
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <div style={{
                                    width: 36, height: 36, borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    background: config.enableMLFPReduction ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                                    color: config.enableMLFPReduction ? '#fff' : 'var(--text-muted)', transition: 'all 0.2s'
                                }}>
                                    <Sparkles size={18} />
                                </div>
                                <div>
                                    <div style={{ fontSize: '0.88rem', fontWeight: 700 }}>ML False Positive Reduction</div>
                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.4, marginTop: '2px' }}>
                                        Filter likely false positives using historical similarity analysis
                                    </div>
                                </div>
                            </div>
                            <input
                                type="checkbox"
                                className="checkbox-custom"
                                checked={config.enableMLFPReduction}
                                onChange={() => setConfig(prev => ({ ...prev, enableMLFPReduction: !prev.enableMLFPReduction }))}
                            />
                        </div>
                    )}

                    {/* Custom Rules Directory */}
                    <div style={{ padding: '12px 16px', borderRadius: '8px', background: 'var(--bg-secondary)' }}>
                        <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <FolderOpen size={14} /> Custom Rules Directory
                        </label>
                        <input
                            className="input"
                            type="text"
                            value={config.customRulesDir}
                            onChange={(e) => setConfig(prev => ({ ...prev, customRulesDir: e.target.value }))}
                            placeholder="rules (default)"
                            style={{ width: '100%' }}
                        />
                        <p style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                            Leave empty to use the built-in rules directory
                        </p>
                    </div>

                    {/* Always-on info */}
                    <div style={{
                        marginTop: '8px', padding: '12px 14px', borderRadius: '8px',
                        background: 'rgba(34, 197, 94, 0.06)', border: '1px solid rgba(34, 197, 94, 0.15)',
                        fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.5
                    }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px', fontWeight: 600, color: '#22c55e' }}>
                            <Lock size={12} /> Always Active
                        </div>
                        Pattern matching • AST analysis • Taint/data flow • Secret detection • Reachability analysis
                    </div>
                </div>
            </div>

            {/* Start Button */}
            <div style={{ marginTop: '32px', textAlign: 'center' }}>
                <button
                    className="btn btn-primary btn-lg"
                    onClick={startScan}
                    disabled={uploading || (tab === 'upload' && !files) || (tab === 'git' && !gitUrl.trim())}
                >
                    {uploading ? (
                        <><span className="animate-spin" style={{ display: 'inline-block' }}>⏳</span> Starting Scan...</>
                    ) : (
                        <><Play size={20} /> Start Security Scan</>
                    )}
                </button>
            </div>
        </div>
    )
}
