import { useState, useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Settings, Shield, PlusCircle, Code, Menu, X, GitCompare, FileCheck, Sun, Moon } from 'lucide-react'

export default function Sidebar({ isOpen, onToggle }) {
    const [isLightMode, setIsLightMode] = useState(
        () => document.documentElement.getAttribute('data-theme') === 'light'
    )
    const [version, setVersion] = useState(null)

    useEffect(() => {
        fetch('/api/system/status')
            .then(r => r.ok ? r.json() : null)
            .then(d => { if (d?.version) setVersion(d.version) })
            .catch(() => {})
    }, [])

    const toggleTheme = () => {
        const next = isLightMode ? 'dark' : 'light'
        setIsLightMode(!isLightMode)
        document.documentElement.setAttribute('data-theme', next)
        localStorage.setItem('theme', next)
    }

    const links = [
        {
            section: 'Main', items: [
                { to: '/', icon: <LayoutDashboard />, label: 'Dashboard' },
                { to: '/scan/new', icon: <PlusCircle />, label: 'New Scan' },
                { to: '/compare', icon: <GitCompare />, label: 'Compare Scans' },
            ]
        },
        {
            section: 'Manage', items: [
                { to: '/compliance', icon: <FileCheck />, label: 'Compliance' },
                { to: '/rules', icon: <Code />, label: 'Rule Builder' },
                { to: '/settings', icon: <Settings />, label: 'Settings' },
            ]
        },
    ]

    return (
        <>
            {!isOpen && (
                <button
                    className="mobile-hamburger"
                    onClick={onToggle}
                    aria-label="Open menu"
                >
                    <Menu size={20} />
                </button>
            )}

            {isOpen && (
                <div className="sidebar-overlay" onClick={onToggle} />
            )}

            <aside className={`sidebar ${isOpen ? '' : 'sidebar-collapsed'}`}>
                <div className="sidebar-header">
                    <button className="sidebar-toggle-inline" onClick={onToggle} aria-label="Toggle sidebar">
                        {isOpen ? <X size={20} /> : <Menu size={20} />}
                    </button>
                    <div className="sidebar-logo-content">
                        <Shield size={20} color="var(--accent-primary)" />
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                            <h1 style={{ fontSize: '1rem', margin: 0, fontWeight: 700, lineHeight: 1 }}>SentryQ</h1>
                            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Security Scanner</span>
                        </div>
                    </div>
                </div>

                <nav className="sidebar-nav">
                    {links.map(section => (
                        <div key={section.section} className="sidebar-section">
                            <div className="sidebar-section-label">{section.section}</div>
                            {section.items.map(link => (
                                <NavLink
                                    key={link.to}
                                    to={link.to}
                                    end={link.to === '/'}
                                    className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
                                    title={!isOpen ? link.label : ''}
                                    onClick={() => {
                                        if (window.innerWidth <= 1024) onToggle()
                                    }}
                                >
                                    {link.icon}
                                    <span>{link.label}</span>
                                </NavLink>
                            ))}
                        </div>
                    ))}
                </nav>

                <div className="sidebar-version-box" style={{ padding: '16px 12px', borderTop: '1px solid var(--border-primary)', marginTop: 'auto' }}>
                    {/* Theme toggle — always visible as an icon button */}
                    <button
                        onClick={toggleTheme}
                        aria-label="Toggle theme"
                        title={isLightMode ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
                        style={{
                            background: 'transparent', border: '1px solid var(--border-primary)',
                            borderRadius: 'var(--radius-md)', color: 'var(--text-secondary)',
                            cursor: 'pointer', padding: '6px', display: 'flex',
                            alignItems: 'center', justifyContent: 'center',
                            width: '100%', marginBottom: '8px',
                            transition: 'background var(--transition-fast)',
                        }}
                        onMouseEnter={e => e.currentTarget.style.background = 'var(--glass-hover)'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                        {isLightMode ? <Moon size={16} /> : <Sun size={16} />}
                        {isOpen && (
                            <span style={{ marginLeft: '8px', fontSize: '0.8rem', fontWeight: 500 }}>
                                {isLightMode ? 'Dark Mode' : 'Light Mode'}
                            </span>
                        )}
                    </button>

                    {isOpen ? (
                        <div className="sidebar-version" style={{ padding: '10px 12px', borderRadius: 'var(--radius-md)', background: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '2px' }}>Version</div>
                            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                                {version ? `v${version}` : 'SentryQ'}
                            </div>
                        </div>
                    ) : (
                        <div style={{ fontSize: '0.65rem', textAlign: 'center', color: 'var(--text-muted)', width: '100%' }}>
                            {version ? `v${version}` : '—'}
                        </div>
                    )}
                </div>
            </aside>
        </>
    )
}
