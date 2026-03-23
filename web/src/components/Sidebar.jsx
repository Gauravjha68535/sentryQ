import React from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { LayoutDashboard, ScanSearch, Settings, Shield, PlusCircle, History, Code } from 'lucide-react'

export default function Sidebar() {
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
        <aside className="sidebar">
            <div className="sidebar-logo">
                <div className="sidebar-logo-icon">
                    <Shield size={20} color="white" />
                </div>
                <div>
                    <h1>JD Scanner</h1>
                    <span>AI Security Scanner</span>
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
                            >
                                {link.icon}
                                <span>{link.label}</span>
                            </NavLink>
                        ))}
                    </div>
                ))}
            </nav>
            <div style={{ padding: '16px 12px', borderTop: '1px solid var(--border-primary)' }}>
                <div style={{ padding: '12px', borderRadius: 'var(--radius-md)', background: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>Version</div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>v2.0.0 — Web UI</div>
                </div>
            </div>
        </aside>
    )
}
