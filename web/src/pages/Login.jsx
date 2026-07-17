import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, LogIn } from 'lucide-react'

export default function Login({ onLogin }) {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')
    const [loading, setLoading] = useState(false)
    const navigate = useNavigate()

    const handleLogin = async (e) => {
        e.preventDefault()
        if (!username || !password) { setError('Username and password are required'); return }
        setError('')
        setLoading(true)
        try {
            let res
            try {
                res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password }),
                })
            } catch {
                setError('Cannot reach the server. Make sure SentryQ is running.')
                setLoading(false)
                return
            }
            if (!res.ok) {
                const body = await res.json().catch(() => ({}))
                throw new Error(body.error || 'Invalid credentials')
            }
            const data = await res.json()
            if (data.token) localStorage.setItem('sentryq_token', data.token)
            if (onLogin) onLogin()
            navigate('/')
        } catch (e) {
            setError(e.message || 'Login failed')
        } finally {
            setLoading(false)
        }
    }

    return (
        <div style={{
            minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'var(--bg-primary)', padding: '24px'
        }}>
            <div style={{
                width: '100%', maxWidth: '400px',
                background: 'var(--bg-card)', borderRadius: '16px',
                border: '1px solid var(--border-primary)', padding: '40px',
                boxShadow: '0 20px 60px rgba(0,0,0,0.4)'
            }}>
                <div style={{ textAlign: 'center', marginBottom: '32px' }}>
                    <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '12px' }}>
                        <Shield size={40} style={{ color: 'var(--accent-primary)' }} />
                    </div>
                    <h1 style={{ fontSize: '1.5rem', fontWeight: 800, margin: 0 }}>SentryQ</h1>
                    <p style={{ color: 'var(--text-muted)', marginTop: '4px', fontSize: '0.85rem' }}>Security Scanner — Sign In</p>
                </div>

                <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                            Username
                        </label>
                        <input
                            className="input"
                            type="text"
                            value={username}
                            onChange={e => setUsername(e.target.value)}
                            placeholder="admin"
                            autoComplete="username"
                            autoFocus
                        />
                    </div>
                    <div>
                        <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', display: 'block' }}>
                            Password
                        </label>
                        <input
                            className="input"
                            type="password"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            placeholder="••••••••"
                            autoComplete="current-password"
                        />
                    </div>
                    {error && (
                        <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '8px', padding: '10px 14px', color: '#ef4444', fontSize: '0.82rem' }}>
                            {error}
                        </div>
                    )}
                    <button
                        type="submit"
                        className="btn btn-primary"
                        disabled={loading}
                        style={{ width: '100%', justifyContent: 'center', padding: '12px', fontSize: '0.95rem', fontWeight: 700 }}
                    >
                        {loading
                            ? <><span className="animate-spin" style={{ display: 'inline-block' }}>⏳</span> Signing In…</>
                            : <><LogIn size={18} /> Sign In</>}
                    </button>
                </form>
            </div>
        </div>
    )
}
