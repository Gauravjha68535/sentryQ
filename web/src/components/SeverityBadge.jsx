import React from 'react'

const classes = {
    critical: 'severity-badge severity-critical',
    high: 'severity-badge severity-high',
    medium: 'severity-badge severity-medium',
    low: 'severity-badge severity-low',
    info: 'severity-badge severity-info',
}

export default function SeverityBadge({ severity }) {
    return (
        <span className={classes[severity] || 'severity-badge severity-info'}>
            {severity}
        </span>
    )
}
