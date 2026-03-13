import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, GitBranch, FolderUp, Play, Cpu, Search, Bug, Shield, FileCode, Lock, Box, Brain } from 'lucide-react'

const defaultConfig = {
    enableAI: false,
    enableAIDiscovery: false,
    enableSemgrep: false,
    enableDeps: true,
    enableSecrets: true,
    enableSupplyChain: false,
    enableCompliance: false,
    enableThreatIntel: false,
    enableConsolidated: false,
    aiModel: 'deepseek-r1:7b',
}

export default function NewScan() {
    const [tab, setTab] = useState('upload')
    const [config, setConfig] = useState(defaultConfig)
    const [files, setFiles] = useState(null)
    const [gitUrl, setGitUrl] = useState('')
    const [dragover, setDragover] = useState(false)
    const [uploading, setUploading] = useState(false)
    const navigate = useNavigate()

    const toggles = [
        { key: 'enableAI', label: 'AI Validation', desc: 'Validate findings with LLM', icon: <Brain size={16} /> },
        { key: 'enableAIDiscovery', label: 'AI Discovery', desc: 'Discover new vulns with AI', icon: <Search size={16} /> },
        { key: 'enableSemgrep', label: 'Semgrep Analysis', desc: 'Run Semgrep rules', icon: <FileCode size={16} /> },
        { key: 'enableDeps', label: 'Dependency Scan', desc: 'Check for vulnerable deps', icon: <Box size={16} /> },
        { key: 'enableSecrets', label: 'Secret Detection', desc: 'Find hardcoded secrets', icon: <Lock size={16} /> },
        { key: 'enableSupplyChain', label: 'Supply Chain', desc: 'SBOM + license checks', icon: <Shield size={16} /> },
        { key: 'enableCompliance', label: 'Compliance', desc: 'PCI-DSS, HIPAA, SOC2', icon: <Shield size={16} /> },
        { key: 'enableThreatIntel', label: 'Threat Intelligence', desc: 'CVE + EPSS enrichment', icon: <Bug size={16} /> },
        { key: 'enableConsolidated', label: 'Consolidated Mode', desc: 'Merge static + AI results', icon: <Cpu size={16} /> },
    ]

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
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '20px' }}>Scanner Configuration</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        {toggles.map(t => (
                            <div key={t.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-primary)' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>{t.icon}</span>
                                    <div>
                                        <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{t.label}</div>
                                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{t.desc}</div>
                                    </div>
                                </div>
                                <label className="toggle">
                                    <input
                                        type="checkbox"
                                        checked={config[t.key]}
                                        onChange={() => setConfig(prev => ({ ...prev, [t.key]: !prev[t.key] }))}
                                    />
                                    <span className="toggle-slider" />
                                </label>
                            </div>
                        ))}
                    </div>

                    <div style={{ marginTop: '20px' }}>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                            AI Model
                        </label>
                        <input
                            className="input"
                            type="text"
                            value={config.aiModel}
                            onChange={(e) => setConfig(prev => ({ ...prev, aiModel: e.target.value }))}
                            placeholder="deepseek-r1:7b"
                        />
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
