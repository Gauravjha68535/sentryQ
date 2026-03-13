import React from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanProgress from './pages/ScanProgress'
import ReportViewer from './pages/ReportViewer'
import Settings from './pages/Settings'
import './index.css'

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan/new" element={<NewScan />} />
            <Route path="/scan/:id" element={<ScanProgress />} />
            <Route path="/scan/:id/report" element={<ReportViewer />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
