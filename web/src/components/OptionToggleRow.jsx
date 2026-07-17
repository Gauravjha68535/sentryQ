export default function OptionToggleRow({ icon, title, description, checked, onChange }) {
    return (
        <div className="option-row">
            <div className="option-info">
                <div className={`option-icon${checked ? ' on' : ''}`}>{icon}</div>
                <div>
                    <div className="option-title">{title}</div>
                    <div className="option-desc">{description}</div>
                </div>
            </div>
            <input type="checkbox" className="checkbox-custom" checked={checked} onChange={onChange} />
        </div>
    )
}
