import { ChevronDown } from 'lucide-react'

export default function CollapsibleSection({ title, icon, open, onToggle, children }) {
    return (
        <div className="collapsible">
            <button type="button" className="collapsible-trigger" onClick={onToggle}>
                <span className="collapsible-trigger-label">
                    {icon}
                    {title}
                </span>
                <ChevronDown
                    size={16}
                    style={{ transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}
                />
            </button>
            {open && <div className="collapsible-body">{children}</div>}
        </div>
    )
}
