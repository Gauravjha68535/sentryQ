import { createContext, useContext, useState, useCallback } from 'react'
import { AlertTriangle } from 'lucide-react'

const ConfirmContext = createContext(null)

export function ConfirmProvider({ children }) {
    const [state, setState] = useState(null)

    const confirm = useCallback((message, title = 'Confirm') => {
        return new Promise((resolve) => {
            setState({ message, title, resolve })
        })
    }, [])

    const handle = (result) => {
        state?.resolve(result)
        setState(null)
    }

    return (
        <ConfirmContext.Provider value={confirm}>
            {children}
            {state && (
                <div className="modal-overlay" onClick={() => handle(false)}>
                    <div className="modal-box" onClick={e => e.stopPropagation()}>
                        <div className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <AlertTriangle size={18} style={{ color: 'var(--severity-high)' }} />
                            {state.title}
                        </div>
                        <p className="modal-message">{state.message}</p>
                        <div className="modal-actions">
                            <button className="btn btn-secondary" onClick={() => handle(false)}>Cancel</button>
                            <button className="btn btn-danger" onClick={() => handle(true)}>Confirm</button>
                        </div>
                    </div>
                </div>
            )}
        </ConfirmContext.Provider>
    )
}

export function useConfirm() {
    const ctx = useContext(ConfirmContext)
    if (!ctx) throw new Error('useConfirm must be used inside ConfirmProvider')
    return ctx
}
