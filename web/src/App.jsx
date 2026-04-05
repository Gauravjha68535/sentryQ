import React, { useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import PageTransition from './components/PageTransition'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanProgress from './pages/ScanProgress'
import ReportViewer from './pages/ReportViewer'
import Settings from './pages/Settings'
import RuleBuilder from './pages/RuleBuilder'
import { AnimatePresence } from 'framer-motion'
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

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true)

  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar isOpen={sidebarOpen} onToggle={() => setSidebarOpen(prev => !prev)} />
        <main className={`main-content ${sidebarOpen ? '' : 'main-content-expanded'}`}>
          <AnimatePresence mode="wait">
            <ErrorBoundary>
              <Routes>
                <Route path="/" element={<PageTransition><Dashboard /></PageTransition>} />
                <Route path="/scan/new" element={<PageTransition><NewScan /></PageTransition>} />
                <Route path="/scan/:id" element={<PageTransition><ScanProgress /></PageTransition>} />
                <Route path="/scan/:id/report" element={<PageTransition><ReportViewer /></PageTransition>} />
                <Route path="/rules" element={<PageTransition><RuleBuilder /></PageTransition>} />
                <Route path="/settings" element={<PageTransition><Settings /></PageTransition>} />
              </Routes>
            </ErrorBoundary>
          </AnimatePresence>
        </main>
      </div>
    </BrowserRouter>
  )
}
