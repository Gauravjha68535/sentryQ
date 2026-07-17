export default function StatCard({ label, value, color, onClick }) {
    return (
        <div className="stat-card" style={onClick ? { cursor: 'pointer' } : {}} onClick={onClick}>
            <div className="stat-card-label">{label}</div>
            <div className="stat-card-value" style={color ? { color } : {}}>{value}</div>
        </div>
    )
}
