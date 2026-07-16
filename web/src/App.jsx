import React, { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import PageTransition from './components/PageTransition'
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

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, info) {
    console.error('[SentryQ] Uncaught React error:', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '40px', color: 'var(--text-primary, #fff)', textAlign: 'center' }}>
          <h2 style={{ color: '#ef4444' }}>Something went wrong</h2>
          <p style={{ color: 'var(--text-muted, #aaa)', marginBottom: '16px' }}>
            {this.state.error?.message || 'An unexpected error occurred.'}
          </p>
          <button
            style={{ padding: '8px 20px', borderRadius: '6px', cursor: 'pointer' }}
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// Auth interceptor: patches global fetch to redirect to /login on 401.
// Only active when SENTRYQ_MULTI_USER=1 (detected by the server returning 401).
function useAuthInterceptor() {
  const navigate = useNavigate()
  useEffect(() => {
    const origFetch = window.fetch.bind(window)
    window.fetch = async (...args) => {
      // Inject stored token as Authorization header if present
      const token = localStorage.getItem('sentryq_token')
      if (token && args[1] && typeof args[1] === 'object') {
        args[1].headers = { ...(args[1].headers || {}), 'Authorization': `Bearer ${token}` }
      } else if (token && !args[1]) {
        args[1] = { headers: { 'Authorization': `Bearer ${token}` } }
      }
      const res = await origFetch(...args)
      // Only redirect to /login for API calls returning 401 (multi-user mode)
      if (res.status === 401 && typeof args[0] === 'string' && args[0].startsWith('/api/')) {
        localStorage.removeItem('sentryq_token')
        navigate('/login')
      }
      return res
    }
    return () => { window.fetch = origFetch }
  }, [navigate])
}

function AuthInterceptorSetup() {
  useAuthInterceptor()
  return null
}

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true)

  return (
    <BrowserRouter>
      <AuthInterceptorSetup />
      <Routes>
        {/* Standalone login page — no sidebar */}
        <Route path="/login" element={<Login />} />

        {/* All other routes share the sidebar layout */}
        <Route path="*" element={
          <div className="app-layout">
            <Sidebar isOpen={sidebarOpen} onToggle={() => setSidebarOpen(prev => !prev)} />
            <main className={`main-content ${sidebarOpen ? '' : 'main-content-expanded'}`}>
              <ErrorBoundary>
                <Routes>
                  <Route path="/" element={<PageTransition><Dashboard /></PageTransition>} />
                  <Route path="/scan/new" element={<PageTransition><NewScan /></PageTransition>} />
                  <Route path="/scan/:id" element={<PageTransition><ScanProgress /></PageTransition>} />
                  <Route path="/scan/:id/report" element={<PageTransition><ReportViewer /></PageTransition>} />
                  <Route path="/rules" element={<PageTransition><RuleBuilder /></PageTransition>} />
                  <Route path="/settings" element={<PageTransition><Settings /></PageTransition>} />
                  <Route path="/compare" element={<PageTransition><ScanDiff /></PageTransition>} />
                  <Route path="/compliance" element={<PageTransition><CompliancePage /></PageTransition>} />
                  <Route path="/compliance/:id" element={<PageTransition><CompliancePage /></PageTransition>} />
                </Routes>
              </ErrorBoundary>
            </main>
          </div>
        } />
      </Routes>
    </BrowserRouter>
  )
}
