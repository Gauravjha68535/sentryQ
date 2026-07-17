import React, { useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
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
          <p style={{ color: 'var(--text-muted, #aaa)', marginBottom: '16px' }}>{this.state.error?.message}</p>
          <button style={{ padding: '8px 20px', borderRadius: '6px', cursor: 'pointer' }}
            onClick={() => this.setState({ hasError: false, error: null })}>Try again</button>
        </div>
      )
    }
    return this.props.children
  }
}

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true)

  // Restore saved theme on mount
  React.useEffect(() => {
    const saved = localStorage.getItem('theme')
    if (saved) document.documentElement.setAttribute('data-theme', saved)
  }, [])

  return (
    <BrowserRouter>
      <ToastProvider>
        <ConfirmProvider>
          <div className="app-layout">
            <Sidebar isOpen={sidebarOpen} onToggle={() => setSidebarOpen(p => !p)} />
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
        </ConfirmProvider>
      </ToastProvider>
    </BrowserRouter>
  )
}
