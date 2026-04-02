import React from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { LayoutDashboard, ScanSearch, Settings, Shield, PlusCircle, History, Code, Menu, X } from 'lucide-react'

export default function Sidebar({ isOpen, onToggle }) {
    const location = useLocation()

    const links = [
        {
            section: 'Main', items: [
                { to: '/', icon: <LayoutDashboard />, label: 'Dashboard' },
                { to: '/scan/new', icon: <PlusCircle />, label: 'New Scan' },
            ]
        },
        {
            section: 'Manage', items: [
                { to: '/rules', icon: <Code />, label: 'Rule Builder' },
                { to: '/settings', icon: <Settings />, label: 'Settings' },
            ]
        },
    ]

    return (
        <>
            {/* Floating button for mobile only, when closed */}
            {!isOpen && (
                <button 
                    className="mobile-hamburger" 
                    onClick={onToggle}
                    aria-label="Open menu"
                >
                    <Menu size={20} />
                </button>
            )}

            {/* Overlay for mobile when sidebar is open */}
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
                                        // Close sidebar on mobile after navigation
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
                    {isOpen ? (
                        <div className="sidebar-version" style={{ padding: '12px', borderRadius: 'var(--radius-md)', background: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>Version</div>
                            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>v2.0.0 — SentryQ</div>
                        </div>
                    ) : (
                        <div style={{ fontSize: '0.65rem', textAlign: 'center', color: 'var(--text-muted)', width: '100%', wordBreak: 'keep-all', whiteSpace: 'nowrap', display: 'block' }}>
                            v2.0
                        </div>
                    )}
                </div>
            </aside>
        </>
    )
}
