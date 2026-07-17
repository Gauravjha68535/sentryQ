import React, { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, useNavigate, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import PageTransition from './components/PageTransition'
import { ToastProvider } from './components/Toast'
import { ConfirmProvider } from './components/ConfirmModal'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanProgress from './pages/ScanProgress'
import ReportViewer from './pages/ReportViewer'
import Settings from './pages/Settings'
import RuleBuilder from './pages/RuleBuilder'
import ScanDiff from './pages/ScanDiff'
import CompliancePage from './pages/CompliancePage'
import Login from './pages/Login'
import './index.css'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }
  static getDerivedStateFromError(error) { return { hasError: true, error } }
  componentDidCatch(error, info) { console.error('[SentryQ] Uncaught React error:', error, info) }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '40px', color: 'var(--text-primary, #fff)', textAlign: 'center' }}>
          <h2 style={{ color: '#ef4444' }}>Something went wrong</h2>
          <p style={{ color: 'var(--text-muted, #aaa)', marginBottom: '16px' }}>{this.state.error?.message || 'An unexpected error occurred.'}</p>
          <button style={{ padding: '8px 20px', borderRadius: '6px', cursor: 'pointer' }} onClick={() => this.setState({ hasError: false, error: null })}>Try again</button>
        </div>
      )
    }
    return this.props.children
  }
}

// Patches global fetch to inject stored auth token and redirect to /login on 401.
function useAuthInterceptor(setNeedsLogin) {
  const navigate = useNavigate()
  useEffect(() => {
    const origFetch = window.fetch.bind(window)
    window.fetch = async (...args) => {
      const token = localStorage.getItem('sentryq_token')
      if (token) {
        const opts = args[1] && typeof args[1] === 'object' ? args[1] : {}
        args[1] = { ...opts, headers: { ...(opts.headers || {}), 'Authorization': `Bearer ${token}` } }
      }
      const res = await origFetch(...args)
      if (res.status === 401 && typeof args[0] === 'string' && args[0].startsWith('/api/')) {
        localStorage.removeItem('sentryq_token')
        setNeedsLogin(true)
        navigate('/login')
      }
      return res
    }
    return () => { window.fetch = origFetch }
  }, [navigate, setNeedsLogin])
}

// Checks auth once at startup: probes /api/scans.
// Returns: 'loading' | 'ok' | 'login'
function useAuthStatus() {
  const [status, setStatus] = useState('loading')
  useEffect(() => {
    const token = localStorage.getItem('sentryq_token')
    // Try the probe with whatever token we have (may be empty)
    const headers = token ? { 'Authorization': `Bearer ${token}` } : {}
    fetch('/api/scans', { headers })
      .then(res => {
        if (res.status === 401) {
          localStorage.removeItem('sentryq_token')
          setStatus('login')
        } else {
          setStatus('ok')
        }
      })
      .catch(() => setStatus('ok')) // network error → let the app try (server might be starting)
  }, [])
  return status
}

function AuthInterceptorSetup({ setNeedsLogin }) {
  useAuthInterceptor(setNeedsLogin)
  return null
}

function AppLayout({ sidebarOpen, setSidebarOpen, setNeedsLogin, needsLogin }) {
  return (
    <>
      <AuthInterceptorSetup setNeedsLogin={setNeedsLogin} />
      <Routes>
        <Route path="/login" element={<Login onLogin={() => setNeedsLogin(false)} />} />
        <Route path="*" element={
          needsLogin
            ? <Navigate to="/login" replace />
            : (
              <div className="app-layout">
                <Sidebar isOpen={sidebarOpen} onToggle={() => setSidebarOpen(prev => !prev)} />
                <main className={`main-content ${sidebarOpen ? '' : 'main-content-expanded'}`}>
                  <ErrorBoundary>
                    <Routes>
                      <Route path="/"               element={<PageTransition><Dashboard /></PageTransition>} />
                      <Route path="/scan/new"        element={<PageTransition><NewScan /></PageTransition>} />
                      <Route path="/scan/:id"        element={<PageTransition><ScanProgress /></PageTransition>} />
                      <Route path="/scan/:id/report" element={<PageTransition><ReportViewer /></PageTransition>} />
                      <Route path="/rules"           element={<PageTransition><RuleBuilder /></PageTransition>} />
                      <Route path="/settings"        element={<PageTransition><Settings /></PageTransition>} />
                      <Route path="/compare"         element={<PageTransition><ScanDiff /></PageTransition>} />
                      <Route path="/compliance"      element={<PageTransition><CompliancePage /></PageTransition>} />
                      <Route path="/compliance/:id"  element={<PageTransition><CompliancePage /></PageTransition>} />
                    </Routes>
                  </ErrorBoundary>
                </main>
              </div>
            )
        } />
      </Routes>
    </>
  )
}

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [needsLogin, setNeedsLogin] = useState(false)
  const authStatus = useAuthStatus()

  // Restore saved theme
  useEffect(() => {
    const saved = localStorage.getItem('theme')
    if (saved) document.documentElement.setAttribute('data-theme', saved)
  }, [])

  if (authStatus === 'loading') {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-primary)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <div style={{ width: '36px', height: '36px', background: 'var(--accent-gradient)', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '20px', boxShadow: 'var(--shadow-glow)' }}>🔒</div>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Starting SentryQ...</div>
        </div>
      </div>
    )
  }

  if (authStatus === 'login' && !needsLogin) {
    setNeedsLogin(true)
  }

  return (
    <BrowserRouter>
      <ToastProvider>
        <ConfirmProvider>
          <AppLayout
            sidebarOpen={sidebarOpen}
            setSidebarOpen={setSidebarOpen}
            setNeedsLogin={setNeedsLogin}
            needsLogin={needsLogin || authStatus === 'login'}
          />
        </ConfirmProvider>
      </ToastProvider>
    </BrowserRouter>
  )
}
