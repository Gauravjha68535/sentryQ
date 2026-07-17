import { createContext, useContext, useState, useCallback } from 'react'
import { CheckCircle, XCircle, Info, AlertTriangle, X } from 'lucide-react'

const ToastContext = createContext(null)

let idCounter = 0

export function ToastProvider({ children }) {
    const [toasts, setToasts] = useState([])

    const dismiss = useCallback((id) => {
        setToasts(prev => prev.filter(t => t.id !== id))
    }, [])

    const toast = useCallback((message, type = 'info', duration = 3500) => {
        const id = ++idCounter
        setToasts(prev => [...prev, { id, message, type }])
        setTimeout(() => dismiss(id), duration)
        return id
    }, [dismiss])

    toast.success = (msg, d) => toast(msg, 'success', d)
    toast.error   = (msg, d) => toast(msg, 'error', d ?? 5000)
    toast.warning = (msg, d) => toast(msg, 'warning', d)
    toast.info    = (msg, d) => toast(msg, 'info', d)

    const icons = {
        success: <CheckCircle size={16} />,
        error:   <XCircle size={16} />,
        warning: <AlertTriangle size={16} />,
        info:    <Info size={16} />,
    }

    return (
        <ToastContext.Provider value={toast}>
            {children}
            <div className="toast-container">
                {toasts.map(t => (
                    <div key={t.id} className={`toast toast-${t.type}`}>
                        {icons[t.type]}
                        <span>{t.message}</span>
                        <button className="toast-close" onClick={() => dismiss(t.id)}>
                            <X size={14} />
                        </button>
                    </div>
                ))}
            </div>
        </ToastContext.Provider>
    )
}

export function useToast() {
    const ctx = useContext(ToastContext)
    if (!ctx) throw new Error('useToast must be used inside ToastProvider')
    return ctx
}
