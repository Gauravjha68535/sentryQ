import React, { useState, useEffect } from 'react'
import { ChevronDown, ChevronRight, Plus, Play, Save, FileCode, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'

export default function RuleBuilder() {
    const [ruleFiles, setRuleFiles] = useState([])
    const [selectedFile, setSelectedFile] = useState(null)
    const [rules, setRules] = useState([])
    const [expandedRule, setExpandedRule] = useState(null)
    const [loading, setLoading] = useState(true)

    // New rule form
    const [showForm, setShowForm] = useState(false)
    const [newRule, setNewRule] = useState({
        id: '', languages: [''], severity: 'medium',
        patterns: [{ regex: '' }],
        description: '', remediation: '', cwe: '', owasp: ''
    })

    // Test pane
    const [testPattern, setTestPattern] = useState('')
    const [testCode, setTestCode] = useState('')
    const [testResult, setTestResult] = useState(null)
    const [testing, setTesting] = useState(false)

    useEffect(() => { fetchRuleFiles() }, [])

    const fetchRuleFiles = async () => {
        try {
            const res = await fetch('/api/rules')
            if (res.ok) setRuleFiles(await res.json())
        } catch (e) { console.error(e) }
        finally { setLoading(false) }
    }

    const fetchRulesForFile = async (filename) => {
        setSelectedFile(filename)
        setExpandedRule(null)
        try {
            const res = await fetch(`/api/rules/${filename}`)
            if (res.ok) setRules(await res.json())
        } catch (e) { console.error(e) }
    }

    const handleTest = async () => {
        if (!testPattern) return
        setTesting(true)
        try {
            const res = await fetch('/api/rules/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pattern: testPattern, code: testCode })
            })
            if (res.ok) setTestResult(await res.json())
        } catch (e) { console.error(e) }
        finally { setTesting(false) }
    }

    const handleSaveRule = async () => {
        if (!selectedFile || !newRule.id) return
        const rule = { ...newRule, languages: newRule.languages.filter(l => l.trim()) }
        try {
            const res = await fetch(`/api/rules/${selectedFile}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(rule)
            })
            if (res.ok) {
                setShowForm(false)
                setNewRule({ id: '', languages: [''], severity: 'medium', patterns: [{ regex: '' }], description: '', remediation: '', cwe: '', owasp: '' })
                fetchRulesForFile(selectedFile)
            }
        } catch (e) { console.error(e) }
    }

    const sevColor = (s) => {
        switch (s) {
            case 'critical': return 'var(--severity-critical)'
            case 'high': return 'var(--severity-high)'
            case 'medium': return 'var(--severity-medium)'
            case 'low': return 'var(--severity-low)'
            default: return 'var(--text-muted)'
        }
    }

    if (loading) return <div style={{ textAlign: 'center', padding: '80px', color: 'var(--text-muted)' }}>Loading rules...</div>

    return (
        <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
            <div style={{ marginBottom: '32px' }}>
                <h1 style={{ fontSize: '1.6rem', fontWeight: 800, marginBottom: '8px' }}>Rule Builder</h1>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>Create, browse, and test security scanning rules</p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '24px' }}>
                {/* Left - File List */}
                <div className="card" style={{ padding: '16px', maxHeight: 'calc(100vh - 200px)', overflowY: 'auto' }}>
                    <h3 style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', marginBottom: '12px', fontWeight: 700 }}>
                        Rule Files ({ruleFiles.length})
                    </h3>
                    {ruleFiles.map(f => (
                        <button key={f.filename}
                            onClick={() => fetchRulesForFile(f.filename)}
                            style={{
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%',
                                padding: '10px 12px', borderRadius: '8px', border: 'none', cursor: 'pointer', marginBottom: '4px',
                                background: selectedFile === f.filename ? 'rgba(99, 102, 241, 0.15)' : 'transparent',
                                color: selectedFile === f.filename ? 'var(--text-accent)' : 'var(--text-secondary)',
                                fontWeight: selectedFile === f.filename ? 700 : 500, fontSize: '0.82rem',
                                transition: 'all 0.15s', textAlign: 'left'
                            }}>
                            <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <FileCode size={14} />
                                {f.filename.replace('.yaml', '')}
                            </span>
                            <span style={{ fontSize: '0.7rem', background: 'var(--bg-elevated)', padding: '2px 8px', borderRadius: '10px', fontWeight: 700 }}>{f.rule_count}</span>
                        </button>
                    ))}
                </div>

                {/* Right - Rules + Test */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    {/* Rules List */}
                    {selectedFile ? (
                        <div className="card" style={{ padding: '20px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                                <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>{selectedFile} <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({rules.length} rules)</span></h3>
                                <button className="btn btn-primary btn-sm" onClick={() => setShowForm(!showForm)} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <Plus size={14} /> New Rule
                                </button>
                            </div>
                            {/* New Rule Form */}
                            {showForm && (
                                <div style={{ background: 'var(--bg-elevated)', borderRadius: '12px', padding: '20px', marginBottom: '16px', border: '1px solid var(--border-primary)' }}>
                                    <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '12px' }}>Create New Rule</h4>
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '10px' }}>
                                        <input className="input" placeholder="Rule ID (e.g. custom-sqli-1)" value={newRule.id} onChange={e => setNewRule({ ...newRule, id: e.target.value })} />
                                        <select className="input" value={newRule.severity} onChange={e => setNewRule({ ...newRule, severity: e.target.value })}>
                                            <option value="critical">Critical</option>
                                            <option value="high">High</option>
                                            <option value="medium">Medium</option>
                                            <option value="low">Low</option>
                                            <option value="info">Info</option>
                                        </select>
                                    </div>
                                    <input className="input" placeholder="Regex pattern" value={newRule.patterns[0].regex} onChange={e => setNewRule({ ...newRule, patterns: [{ regex: e.target.value }] })} style={{ marginBottom: '10px' }} />
                                    <input className="input" placeholder="Language (e.g. go, java, python)" value={newRule.languages[0]} onChange={e => setNewRule({ ...newRule, languages: [e.target.value] })} style={{ marginBottom: '10px' }} />
                                    <textarea className="input" placeholder="Description" rows={2} value={newRule.description} onChange={e => setNewRule({ ...newRule, description: e.target.value })} style={{ marginBottom: '10px', resize: 'vertical' }} />
                                    <textarea className="input" placeholder="Remediation" rows={2} value={newRule.remediation} onChange={e => setNewRule({ ...newRule, remediation: e.target.value })} style={{ marginBottom: '10px', resize: 'vertical' }} />
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '12px' }}>
                                        <input className="input" placeholder="CWE (e.g. CWE-89)" value={newRule.cwe} onChange={e => setNewRule({ ...newRule, cwe: e.target.value })} />
                                        <input className="input" placeholder="OWASP (e.g. A03:2021)" value={newRule.owasp} onChange={e => setNewRule({ ...newRule, owasp: e.target.value })} />
                                    </div>
                                    <div style={{ display: 'flex', gap: '8px' }}>
                                        <button className="btn btn-primary btn-sm" onClick={handleSaveRule} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <Save size={14} /> Save Rule
                                        </button>
                                        <button className="btn btn-secondary btn-sm" onClick={() => setShowForm(false)}>Cancel</button>
                                    </div>
                                </div>
                            )}
                            {/* Existing Rules */}
                            <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                                {rules.map((rule, i) => (
                                    <div key={rule.id || i} style={{ borderBottom: '1px solid var(--border-primary)', padding: '10px 0' }}>
                                        <div onClick={() => setExpandedRule(expandedRule === i ? null : i)}
                                            style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                                            {expandedRule === i ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                                            <span style={{ fontWeight: 600, fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>{rule.id}</span>
                                            <span style={{ color: sevColor(rule.severity), fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', background: `${sevColor(rule.severity)}15`, padding: '2px 8px', borderRadius: '10px' }}>{rule.severity}</span>
                                            <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem', flex: 1 }}>{rule.description}</span>
                                        </div>
                                        {expandedRule === i && (
                                            <div style={{ paddingLeft: '28px', marginTop: '8px', fontSize: '0.8rem' }}>
                                                <div style={{ color: 'var(--text-muted)', marginBottom: '4px' }}><strong>Pattern:</strong> <code style={{ background: 'var(--bg-elevated)', padding: '2px 6px', borderRadius: '4px', fontSize: '0.75rem' }}>{rule.patterns?.[0]?.regex}</code></div>
                                                <div style={{ color: 'var(--text-muted)', marginBottom: '4px' }}><strong>CWE:</strong> {rule.cwe || 'N/A'} | <strong>OWASP:</strong> {rule.owasp || 'N/A'}</div>
                                                {rule.remediation && <div style={{ color: 'var(--text-muted)' }}><strong>Fix:</strong> {rule.remediation}</div>}
                                                <button className="btn btn-sm" style={{ marginTop: '8px', fontSize: '0.72rem' }}
                                                    onClick={(e) => { e.stopPropagation(); setTestPattern(rule.patterns?.[0]?.regex || '') }}>
                                                    <Play size={12} /> Use in Test Pane
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <div className="card" style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
                            <FileCode size={48} style={{ marginBottom: '16px', opacity: 0.3 }} />
                            <p style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '8px' }}>Select a rule file</p>
                            <p style={{ fontSize: '0.85rem' }}>Choose a YAML rule file from the left to browse and edit rules</p>
                        </div>
                    )}

                    {/* Test Pane */}
                    <div className="card" style={{ padding: '20px' }}>
                        <h3 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Play size={16} /> Live Pattern Tester
                        </h3>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                            <div>
                                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px', display: 'block', fontWeight: 600 }}>Regex Pattern</label>
                                <input className="input" placeholder="e.g. exec\.Command\s*\(" value={testPattern} onChange={e => setTestPattern(e.target.value)} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }} />
                            </div>
                            <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                                <button className="btn btn-primary btn-sm" onClick={handleTest} disabled={testing || !testPattern}
                                    style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <Play size={14} /> {testing ? 'Testing...' : 'Test Pattern'}
                                </button>
                            </div>
                        </div>
                        <div style={{ marginTop: '12px' }}>
                            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px', display: 'block', fontWeight: 600 }}>Sample Code</label>
                            <textarea className="input" rows={8} placeholder="Paste sample code here to test your regex pattern against..." value={testCode} onChange={e => setTestCode(e.target.value)}
                                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', lineHeight: '1.6', resize: 'vertical' }} />
                        </div>
                        {/* Results */}
                        {testResult && (
                            <div style={{ marginTop: '12px', padding: '12px', borderRadius: '8px', background: 'var(--bg-elevated)', border: '1px solid var(--border-primary)' }}>
                                {!testResult.valid ? (
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--severity-critical)' }}>
                                        <XCircle size={16} /> <strong>Invalid regex:</strong> {testResult.error}
                                    </div>
                                ) : testResult.matches.length === 0 ? (
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)' }}>
                                        <AlertTriangle size={16} /> No matches found
                                    </div>
                                ) : (
                                    <div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--success)', marginBottom: '8px' }}>
                                            <CheckCircle size={16} /> <strong>{testResult.matches.length} match(es) found</strong>
                                        </div>
                                        {testResult.matches.map((m, i) => (
                                            <div key={i} style={{ padding: '6px 10px', background: 'rgba(34, 197, 94, 0.05)', borderLeft: '3px solid var(--success)', marginBottom: '4px', borderRadius: '0 6px 6px 0', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                                                <span style={{ color: 'var(--text-muted)', marginRight: '8px' }}>L{m.line}:</span>
                                                {m.content}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    )
}
