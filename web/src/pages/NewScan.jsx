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

    const fetchInstalledModels = async () => {
        try {
            const res = await fetch('/api/models')
            if (res.ok) {
                const data = await res.json()
                setAvailableModels(data.models || [])

                // Set default models if empty
                if (data.models && data.models.length > 0) {
                    setConfig(prev => {
                        const newConfig = { ...prev }
                        if (!newConfig.aiModel) newConfig.aiModel = data.models[0]
                        if (!newConfig.consolidationModel) newConfig.consolidationModel = data.models[data.models.length - 1] // Pick highest/last as fallback larger model
                        return newConfig
                    })
                }
            }
        } catch (e) {
            console.error("Failed to fetch models", e)
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
                            border: `1px solid ${config.enableDeepScan && !config.enableEnsemble ? 'var(--accent-primary)' : 'var(--border-primary)'}`,
                            background: config.enableDeepScan && !config.enableEnsemble ? 'rgba(99, 102, 241, 0.06)' : 'transparent',
                            transition: 'all 0.2s ease',
                            opacity: config.enableEnsemble ? 0.5 : 1,
                            pointerEvents: config.enableEnsemble ? 'none' : 'auto'
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
                            <label className="toggle">
                                <input
                                    type="checkbox"
                                    checked={config.enableDeepScan}
                                    onChange={() => setConfig(prev => ({ ...prev, enableDeepScan: !prev.enableDeepScan }))}
                                />
                                <span className="toggle-slider" />
                            </label>
                        </div>

                        {/* AI-Powered Toggle */}
                        <div style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '16px', borderRadius: '10px',
                            border: `1px solid ${config.enableAI && !config.enableEnsemble ? 'var(--accent-primary)' : 'var(--border-primary)'}`,
                            background: config.enableAI && !config.enableEnsemble ? 'rgba(99, 102, 241, 0.06)' : 'transparent',
                            transition: 'all 0.2s ease',
                            opacity: config.enableEnsemble ? 0.5 : 1,
                            pointerEvents: config.enableEnsemble ? 'none' : 'auto'
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
                            <label className="toggle">
                                <input
                                    type="checkbox"
                                    checked={config.enableAI}
                                    onChange={() => setConfig(prev => ({ ...prev, enableAI: !prev.enableAI }))}
                                />
                                <span className="toggle-slider" />
                            </label>
                        </div>

                        {/* Ensemble Audit Toggle */}
                        <div style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '16px', borderRadius: '10px',
                            border: `1px solid ${config.enableEnsemble ? '#f59e0b' : 'var(--border-primary)'}`,
                            background: config.enableEnsemble ? 'rgba(245, 158, 11, 0.08)' : 'transparent',
                            transition: 'all 0.2s ease'
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <div style={{
                                    width: 36, height: 36, borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    background: config.enableEnsemble ? '#f59e0b' : 'var(--bg-tertiary)',
                                    color: config.enableEnsemble ? '#fff' : 'var(--text-muted)', transition: 'all 0.2s'
                                }}>
                                    <Layers size={18} />
                                </div>
                                <div>
                                    <div style={{ fontSize: '0.88rem', fontWeight: 700 }}>Ensemble Audit
                                        <span style={{ fontSize: '0.62rem', fontWeight: 600, padding: '2px 6px', background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', borderRadius: '4px', marginLeft: '8px' }}>ADVANCED</span>
                                    </div>
                                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', lineHeight: 1.4, marginTop: '2px' }}>
                                        3-phase pipeline: Static scan → AI scan → Judge LLM merge. Designed for thorough, long-running audits.
                                    </div>
                                </div>
                            </div>
                            <label className="toggle">
                                <input
                                    type="checkbox"
                                    checked={config.enableEnsemble}
                                    onChange={() => setConfig(prev => ({
                                        ...prev,
                                        enableEnsemble: !prev.enableEnsemble,
                                        enableDeepScan: !prev.enableEnsemble ? true : prev.enableDeepScan,
                                        enableAI: !prev.enableEnsemble ? true : prev.enableAI
                                    }))}
                                />
                                <span className="toggle-slider" />
                            </label>
                        </div>
                    </div>

                    {/* AI Configuration (visible when AI or Ensemble enabled) */}
                    {(config.enableAI || config.enableEnsemble) && (
                        <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px', animation: 'fadeIn 0.3s ease' }}>
                            <div>
                                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                                    Ollama Host API
                                </label>
                                <input
                                    className="input"
                                    type="text"
                                    value={config.ollamaHost}
                                    onChange={(e) => setConfig(prev => ({ ...prev, ollamaHost: e.target.value }))}
                                    placeholder="localhost:11434"
                                />
                            </div>

                            <div>
                                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                                    Discovery & Validation Model {loadingModels && <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>(Loading...)</span>}
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
                                        <option value="custom" disabled>---</option>
                                        {!availableModels.includes(config.aiModel) && config.aiModel !== '' && (
                                            <option value={config.aiModel}>{config.aiModel} (Custom)</option>
                                        )}
                                    </select>
                                ) : (
                                    <input
                                        className="input"
                                        type="text"
                                        value={config.aiModel}
                                        onChange={(e) => setConfig(prev => ({ ...prev, aiModel: e.target.value }))}
                                        placeholder="Enter model name (e.g. deepseek-r1:7b)"
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
                                            <option key={`consolidation-${model}`} value={model}>{model}</option>
                                        ))}
                                        <option value="custom" disabled>---</option>
                                        {!availableModels.includes(config.consolidationModel) && config.consolidationModel !== '' && (
                                            <option value={config.consolidationModel}>{config.consolidationModel} (Custom)</option>
                                        )}
                                    </select>
                                ) : (
                                    <input
                                        className="input"
                                        type="text"
                                        value={config.consolidationModel}
                                        onChange={(e) => setConfig(prev => ({ ...prev, consolidationModel: e.target.value }))}
                                        placeholder="Enter larger model (e.g. qwen2.5-coder:14b)"
                                    />
                                )}
                                <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                                    {availableModels.length > 0
                                        ? `Found ${availableModels.length} installed models in Ollama.`
                                        : "Model must be installed in Ollama. Run `ollama list` to check."}
                                </p>
                            </div>

                            {/* Judge Model (only for Ensemble) */}
                            {config.enableEnsemble && (
                                <>
                                    <div style={{ marginTop: '8px', padding: '12px', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.06)', border: '1px solid rgba(245, 158, 11, 0.15)' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px', fontWeight: 600, fontSize: '0.78rem', color: '#f59e0b' }}>
                                            <Layers size={12} /> Judge LLM Configuration
                                        </div>

                                        <div style={{ marginBottom: '12px' }}>
                                            <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px', display: 'block' }}>
                                                Judge Model (merges both reports)
                                            </label>
                                            {availableModels.length > 0 ? (
                                                <select
                                                    className="input"
                                                    value={config.judgeModel || config.consolidationModel}
                                                    onChange={(e) => setConfig(prev => ({ ...prev, judgeModel: e.target.value }))}
                                                    style={{ appearance: 'auto' }}
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
                                                    placeholder="Enter judge model (e.g. qwen2.5:32b)"
                                                />
                                            )}
                                        </div>

                                        <div>
                                            <label style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px', display: 'block' }}>
                                                Judge Ollama Host (optional, for remote server)
                                            </label>
                                            <input
                                                className="input"
                                                type="text"
                                                value={config.judgeOllamaHost}
                                                onChange={(e) => setConfig(prev => ({ ...prev, judgeOllamaHost: e.target.value }))}
                                                placeholder="Same as above (or e.g. 192.168.1.50:11434)"
                                            />
                                        </div>
                                    </div>
                                </>
                            )}
                        </div>
                    )}




                    {/* ML FP Reduction Toggle (only when AI or Ensemble enabled) */}
                    {(config.enableAI || config.enableEnsemble) && (
                        <div style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '16px', borderRadius: '10px',
                            border: `1px solid ${config.enableMLFPReduction ? '#06b6d4' : 'var(--border-primary)'}`,
                            background: config.enableMLFPReduction ? 'rgba(6, 182, 212, 0.06)' : 'transparent',
                            transition: 'all 0.2s ease', animation: 'fadeIn 0.3s ease'
                        }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <div style={{
                                    width: 36, height: 36, borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    background: config.enableMLFPReduction ? '#06b6d4' : 'var(--bg-tertiary)',
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
                            <label className="toggle">
                                <input
                                    type="checkbox"
                                    checked={config.enableMLFPReduction}
                                    onChange={() => setConfig(prev => ({ ...prev, enableMLFPReduction: !prev.enableMLFPReduction }))}
                                />
                                <span className="toggle-slider" />
                            </label>
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
