import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { GitBranch, FolderUp, Play, Shield, Lock, Brain, Globe, Sparkles, FolderOpen, Layers, AlertTriangle, GitPullRequest, Bell, GitMerge, Upload } from 'lucide-react'
import CollapsibleSection from '../components/CollapsibleSection'
import OptionToggleRow from '../components/OptionToggleRow'
import FormField from '../components/FormField'
import { useToast } from '../components/Toast'

const defaultConfig = {
    enableDeepScan: false, enableAI: false, enableEnsemble: false,
    aiModel: '', ollamaHost: 'localhost:11434',
    consolidationModel: '', consolidationOllamaHost: '',
    judgeModel: '', judgeOllamaHost: '',
    enableMLFPReduction: false, customRulesDir: '',
    policyFailOn: '', maxCritical: -1, maxHigh: -1, maxMedium: -1, maxTotal: -1,
    prProvider: '', prToken: '', prRepo: '', prNumber: 0, mrIid: 0,
    webhookUrls: '', incrementalScan: false, baseBranch: 'main',
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
    const [policyOpen, setPolicyOpen] = useState(false)
    const [prOpen, setPrOpen] = useState(false)
    const [notifOpen, setNotifOpen] = useState(false)
    const [incrOpen, setIncrOpen] = useState(false)
    const navigate = useNavigate()
    const toast = useToast()

    const setCfg = (patch) => setConfig(prev => ({ ...prev, ...patch }))

    React.useEffect(() => {
        const ac = new AbortController()
        fetchSettings(ac.signal)
        fetchModels(null, ac.signal)
        return () => ac.abort()
    }, [])

    const fetchSettings = async (signal) => {
        try {
            const res = await fetch('/api/settings', { signal })
            if (res.ok) {
                const d = await res.json()
                setCfg({ ollamaHost: d.ollama_host || 'localhost:11434', aiProvider: d.ai_provider || 'ollama', customApiUrl: d.custom_api_url || '', customApiKey: d.custom_api_key || '' })
            }
        } catch (e) { if (e.name !== 'AbortError') console.error('Failed to fetch settings', e) }
    }

    const fetchModels = async (explicitHost = null, signal = null) => {
        setLoadingModels(true)
        if (explicitHost) setAvailableModels([])
        try {
            const isCustom = config.aiProvider === 'openai'
            const host = explicitHost || (isCustom ? config.customApiUrl : config.ollamaHost)
            if (!host) { setLoadingModels(false); return }
            // API key goes in the Authorization header — never in a URL query param
            // (URLs appear in server logs, browser history, and proxy logs).
            // If the key is the masked sentinel "***" from settings, omit it and
            // let the backend use the stored key via its own settings.
            const fetchOpts = { ...(signal ? { signal } : {}) }
            const url = isCustom
                ? `/api/custom-endpoint/models?${new URLSearchParams({ url: host })}`
                : `/api/models?host=${encodeURIComponent(host)}`
            if (isCustom && config.customApiKey && config.customApiKey !== '***') {
                fetchOpts.headers = { Authorization: `Bearer ${config.customApiKey}` }
            }
            const res = await fetch(url, fetchOpts)
            if (res.ok) {
                const data = await res.json()
                const models = data.models || []
                if (data.error) throw new Error(data.error)
                setAvailableModels(models)
                if (models.length > 0) {
                    setConfig(prev => ({
                        ...prev,
                        ...(explicitHost || !prev.aiModel ? { aiModel: models[0] } : {}),
                        ...(explicitHost || !prev.consolidationModel ? { consolidationModel: models[models.length - 1] } : {}),
                    }))
                } else if (explicitHost) {
                    toast.warning(`No models found on ${isCustom ? 'Custom API' : 'Ollama'}: ${host}`)
                }
            } else if (explicitHost) {
                toast.error(`Failed to fetch models from ${host}`)
            }
        } catch (e) {
            if (e.name !== 'AbortError') {
                if (explicitHost) toast.error(`Connection error: ${e.message}`)
            }
        } finally {
            setLoadingModels(false)
        }
    }

    const startScan = async () => {
        setUploading(true)
        try {
            let res
            if (tab === 'upload' && files) {
                const fd = new FormData()
                for (let i = 0; i < files.length; i++) fd.append('files', files[i], files[i].webkitRelativePath || files[i].name)
                fd.append('config', JSON.stringify(config))
                res = await fetch('/api/scan/upload', { method: 'POST', body: fd })
            } else if (tab === 'git' && gitUrl.trim()) {
                res = await fetch('/api/scan/git', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: gitUrl.trim(), config }) })
            } else {
                toast.warning('Please provide a folder or Git URL')
                setUploading(false)
                return
            }
            if (res.ok) {
                navigate(`/scan/${(await res.json()).scan_id}`)
            } else {
                toast.error(`Scan failed to start: ${await res.text()}`)
            }
        } catch (e) {
            toast.error(`Error: ${e.message}`)
        } finally {
            setUploading(false)
        }
    }

    const modelSelect = (field) => availableModels.length > 0
        ? <select className="input" value={config[field]} onChange={e => setCfg({ [field]: e.target.value })} style={{ appearance: 'auto' }}>
            {availableModels.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        : <input className="input" type="text" value={config[field]} onChange={e => setCfg({ [field]: e.target.value })} placeholder="e.g. qwen2.5-coder:7b" />

    return (
        <div className="animate-fade-in">
            <div className="page-header">
                <h1>New Security Scan</h1>
                <p>Upload a project folder or provide a Git repository URL to start scanning</p>
            </div>

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
                            onDragOver={e => { e.preventDefault(); setDragover(true) }}
                            onDragLeave={() => setDragover(false)}
                            onDrop={e => { e.preventDefault(); setDragover(false); if (e.dataTransfer.items?.length) setFiles(e.dataTransfer.files) }}
                            onClick={() => document.getElementById('file-input').click()}
                        >
                            <input id="file-input" type="file" webkitdirectory="true" directory="true" multiple style={{ display: 'none' }} onChange={e => setFiles(e.target.files)} />
                            <div className="upload-zone-icon">
                                <Upload size={48} style={{ opacity: 0.4, color: 'var(--accent-primary)' }} />
                            </div>
                            <h3>{files ? `${files.length} files selected` : 'Drop your project folder here'}</h3>
                            <p>{files ? 'Click to change selection' : 'or click to browse files'}</p>
                        </div>
                    ) : (
                        <div className="card" style={{ padding: '32px' }}>
                            <FormField label="Repository URL" hint="Supports GitHub, GitLab, and Bitbucket public repositories. Cloned to a temporary directory for scanning.">
                                <input className="input" type="text" placeholder="https://github.com/user/repo.git" value={gitUrl} onChange={e => setGitUrl(e.target.value)} />
                            </FormField>
                        </div>
                    )}
                </div>

                {/* Right: Scan Config */}
                <div className="card">
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '8px' }}>Scan Configuration</h3>
                    <p className="form-hint" style={{ marginBottom: '20px' }}>
                        Pattern matching, AST analysis, taint analysis, and secret detection run automatically on every scan.
                    </p>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <OptionToggleRow
                            icon={<Shield size={18} />}
                            title="Deep Scan"
                            description={config.enableEnsemble ? 'Automatically included in Ensemble Audit' : 'Dependency vulnerabilities, Semgrep, supply chain, container scanning, Threat Intel'}
                            checked={config.enableDeepScan}
                            onChange={() => setCfg({ enableDeepScan: !config.enableDeepScan })}
                        />
                        <OptionToggleRow
                            icon={<Brain size={18} />}
                            title="AI-Powered"
                            description={config.enableEnsemble ? 'Automatically included in Ensemble Audit' : 'AI discovery, validation & auto-consolidation (requires Ollama)'}
                            checked={config.enableAI}
                            onChange={() => setCfg({ enableAI: !config.enableAI })}
                        />
                        <OptionToggleRow
                            icon={<Layers size={18} />}
                            title={<>Ensemble Audit <span className="badge badge-accent" style={{ marginLeft: '8px' }}>ADVANCED</span></>}
                            description="3-phase pipeline: Static scan → AI scan → Judge LLM merge. Designed for thorough, long-running audits."
                            checked={config.enableEnsemble}
                            onChange={() => setCfg({
                                enableEnsemble: !config.enableEnsemble,
                                enableDeepScan: !config.enableEnsemble ? true : config.enableDeepScan,
                                enableAI: !config.enableEnsemble ? true : config.enableAI,
                            })}
                        />
                    </div>

                    {/* AI Host Box */}
                    <div className="ai-host-box">
                        <div className="ai-host-box-header">
                            <label className="ai-host-label">
                                <Globe size={16} /> {config.aiProvider === 'openai' ? 'Custom API Configured' : 'Ollama Host API'}
                            </label>
                            {loadingModels && <span className="animate-spin" style={{ fontSize: '0.75rem', color: '#6366f1' }}>⏳</span>}
                        </div>
                        <div style={{ display: 'flex', gap: '10px' }}>
                            <input
                                className="input"
                                type="text"
                                value={config.aiProvider === 'openai' ? config.customApiUrl : config.ollamaHost}
                                onChange={e => { if (config.aiProvider !== 'openai') setCfg({ ollamaHost: e.target.value }) }}
                                disabled={config.aiProvider === 'openai'}
                                placeholder="localhost:11434 or 192.168.1.100:11434"
                                style={{ flex: 1, opacity: config.aiProvider === 'openai' ? 0.7 : 1 }}
                            />
                            <button type="button" className="btn btn-primary"
                                onClick={() => fetchModels(config.aiProvider === 'openai' ? config.customApiUrl : config.ollamaHost)}
                                disabled={loadingModels}
                                style={{ padding: '0 20px', height: '42px', whiteSpace: 'nowrap', minWidth: '150px' }}>
                                <Play size={14} fill="currentColor" /> REFRESH MODELS
                            </button>
                        </div>
                        <p className="form-hint">
                            {config.aiProvider === 'openai' ? 'Using the Custom API configured in Settings.' : "Enter your Ollama host and click Refresh to load available models."}
                        </p>
                    </div>

                    {/* AI Model selects */}
                    {(config.enableAI || config.enableEnsemble) && (
                        <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px', animation: 'fadeIn 0.3s ease' }}>
                            <FormField label="Discovery & Validation Model">{modelSelect('aiModel')}</FormField>
                            <FormField label="Final Consolidation Model (Larger LLM)">{modelSelect('consolidationModel')}</FormField>
                            {config.enableEnsemble && (
                                <div style={{ padding: '16px', borderRadius: '12px', background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.12)' }}>
                                    <label className="form-label" style={{ color: 'var(--accent-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <Layers size={14} /> Judge Model Configuration
                                    </label>
                                    <p className="form-hint" style={{ marginBottom: '12px' }}>The Judge LLM merges independent scan reports into a single consolidated finding.</p>
                                    {modelSelect('judgeModel')}
                                </div>
                            )}
                        </div>
                    )}

                    {/* ML FP Reduction */}
                    {(config.enableAI || config.enableEnsemble) && (
                        <div style={{ animation: 'fadeIn 0.3s ease' }}>
                            <OptionToggleRow
                                icon={<Sparkles size={18} />}
                                title="ML False Positive Reduction"
                                description="Filter likely false positives using historical similarity analysis"
                                checked={config.enableMLFPReduction}
                                onChange={() => setCfg({ enableMLFPReduction: !config.enableMLFPReduction })}
                            />
                        </div>
                    )}

                    {/* Custom Rules */}
                    <div style={{ padding: '12px 16px', borderRadius: '8px', background: 'var(--bg-secondary)', marginTop: '8px' }}>
                        <FormField label={<><FolderOpen size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} />Custom Rules Directory</>} hint="Leave empty to use the built-in rules directory">
                            <input className="input" type="text" value={config.customRulesDir} onChange={e => setCfg({ customRulesDir: e.target.value })} placeholder="rules (default)" />
                        </FormField>
                    </div>

                    {/* Collapsible advanced sections */}
                    <CollapsibleSection title="CI Policy Gates" icon={<AlertTriangle size={15} />} open={policyOpen} onToggle={() => setPolicyOpen(o => !o)}>
                        <FormField label="Fail On Severity" hint="Fail the scan if any finding meets or exceeds this severity">
                            <select className="input" value={config.policyFailOn} onChange={e => setCfg({ policyFailOn: e.target.value })} style={{ appearance: 'auto' }}>
                                <option value="">None (no gate)</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                        </FormField>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                            {[['maxCritical','Max Critical'],['maxHigh','Max High'],['maxMedium','Max Medium'],['maxTotal','Max Total']].map(([key, lbl]) => (
                                <FormField key={key} label={lbl}>
                                    <input className="input" type="number" min="-1"
                                        value={config[key] === -1 ? '' : config[key]} placeholder="No limit"
                                        onChange={e => setCfg({ [key]: e.target.value === '' ? -1 : parseInt(e.target.value) || -1 })} />
                                </FormField>
                            ))}
                        </div>
                    </CollapsibleSection>

                    <CollapsibleSection title="PR / MR Decoration" icon={<GitPullRequest size={15} />} open={prOpen} onToggle={() => setPrOpen(o => !o)}>
                        <FormField label="Provider">
                            <div style={{ display: 'flex', gap: '8px' }}>
                                {['', 'github', 'gitlab'].map(p => (
                                    <button key={p} type="button" onClick={() => setCfg({ prProvider: p })} style={{
                                        padding: '6px 14px', borderRadius: '6px', fontSize: '0.8rem', fontWeight: 600,
                                        border: '1px solid var(--border-primary)', cursor: 'pointer',
                                        background: config.prProvider === p ? 'var(--accent-primary)' : 'var(--bg-secondary)',
                                        color: config.prProvider === p ? '#fff' : 'var(--text-secondary)',
                                    }}>
                                        {p === '' ? 'None' : p === 'github' ? 'GitHub' : 'GitLab'}
                                    </button>
                                ))}
                            </div>
                        </FormField>
                        {config.prProvider !== '' && (
                            <>
                                <FormField label="Token"><input className="input" type="password" value={config.prToken} onChange={e => setCfg({ prToken: e.target.value })} placeholder="ghp_... or glpat-..." /></FormField>
                                <FormField label="Repository (owner/repo)"><input className="input" type="text" value={config.prRepo} onChange={e => setCfg({ prRepo: e.target.value })} placeholder="myorg/myrepo" /></FormField>
                                {config.prProvider === 'github' && <FormField label="PR Number"><input className="input" type="number" min="1" value={config.prNumber || ''} onChange={e => setCfg({ prNumber: parseInt(e.target.value) || 0 })} placeholder="42" /></FormField>}
                                {config.prProvider === 'gitlab' && <FormField label="MR IID"><input className="input" type="number" min="1" value={config.mrIid || ''} onChange={e => setCfg({ mrIid: parseInt(e.target.value) || 0 })} placeholder="12" /></FormField>}
                            </>
                        )}
                    </CollapsibleSection>

                    <CollapsibleSection title="Notifications" icon={<Bell size={15} />} open={notifOpen} onToggle={() => setNotifOpen(o => !o)}>
                        <FormField label="Webhook URLs" hint="Comma-separated list. A JSON payload is POSTed on scan completion.">
                            <textarea className="input" rows={3} value={config.webhookUrls} onChange={e => setCfg({ webhookUrls: e.target.value })} placeholder="https://hooks.slack.com/..., https://discord.com/api/webhooks/..." style={{ resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }} />
                        </FormField>
                        <p className="form-hint">CycloneDX SBOM (<code>sbom.cdx.json</code>) is generated automatically for every scan.</p>
                    </CollapsibleSection>

                    {tab === 'git' && (
                        <CollapsibleSection title="Incremental Scan" icon={<GitMerge size={15} />} open={incrOpen} onToggle={() => setIncrOpen(o => !o)}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <input type="checkbox" className="checkbox-custom" checked={config.incrementalScan} onChange={() => setCfg({ incrementalScan: !config.incrementalScan })} />
                                <div>
                                    <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>Scan only changed files (git diff)</div>
                                    <p className="form-hint" style={{ marginTop: '2px' }}>Restricts analysis to files changed relative to the base branch</p>
                                </div>
                            </div>
                            {config.incrementalScan && (
                                <FormField label="Base Branch" hint="The branch to diff against when computing changed files">
                                    <input className="input" type="text" value={config.baseBranch} onChange={e => setCfg({ baseBranch: e.target.value })} placeholder="main" />
                                </FormField>
                            )}
                        </CollapsibleSection>
                    )}

                    <div className="always-on-box">
                        <div className="always-on-header"><Lock size={12} /> Always Active</div>
                        Pattern matching • AST analysis • Taint/data flow • Secret detection • Reachability analysis
                    </div>
                </div>
            </div>

            <div style={{ marginTop: '32px', textAlign: 'center' }}>
                <button className="btn btn-primary btn-lg" onClick={startScan} disabled={uploading || (tab === 'upload' && !files) || (tab === 'git' && !gitUrl.trim())}>
                    {uploading
                        ? <><span className="animate-spin" style={{ display: 'inline-block' }}>⏳</span> Starting Scan...</>
                        : <><Play size={20} /> Start Security Scan</>}
                </button>
            </div>
        </div>
    )
}
