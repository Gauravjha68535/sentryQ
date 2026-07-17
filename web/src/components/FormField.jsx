export default function FormField({ label, hint, children, style }) {
    return (
        <div style={style}>
            {label && <label className="form-label">{label}</label>}
            {children}
            {hint && <p className="form-hint">{hint}</p>}
        </div>
    )
}
