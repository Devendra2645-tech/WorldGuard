import React from 'react';

export default function RiskOverview({
  riskLevel = 'Low',
  totalFindings = 0,
  severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
  verifiedFixesCount = 0,
  testsRun = 7,
}) {
  const critical = severityCounts.Critical || 0;
  const high = severityCounts.High || 0;
  const medium = severityCounts.Medium || 0;
  const low = severityCounts.Low || 0;
  const info = severityCounts.Info || 0;

  const total = critical + high + medium + low + info;
  const criticalPct = total > 0 ? (critical / total) * 100 : 0;
  const highPct = total > 0 ? (high / total) * 100 : 0;
  const mediumPct = total > 0 ? (medium / total) * 100 : 0;
  const lowPct = total > 0 ? (low / total) * 100 : 0;
  const infoPct = total > 0 ? (info / total) * 100 : 0;

  const getRiskBadgeClass = (level) => {
    switch (level?.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      case 'low':
        return 'badge-low';
      case 'info':
      case 'verified':
      case 'secure':
        return 'badge-verified';
      default:
        return 'badge-low';
    }
  };

  return (
    <div className="panel-card">
      <div className="panel-header">
        <div className="panel-title-group">
          <span className="panel-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2">
              <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
            </svg>
            Risk Analysis & Posture Overview
          </span>
        </div>
        <span className={`card-badge ${getRiskBadgeClass(riskLevel)}`} style={{ fontSize: '0.8rem', padding: '4px 10px' }}>
          Overall Risk: {riskLevel.toUpperCase()}
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
          <div className="detail-item">
            <span className="detail-label">Overall Severity</span>
            <span className="detail-value" style={{ color: riskLevel === 'Critical' ? 'var(--sev-critical)' : riskLevel === 'High' ? 'var(--sev-high)' : 'var(--status-verified)' }}>
              {riskLevel}
            </span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Active / Total Findings</span>
            <span className="detail-value">{totalFindings} findings</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Deterministic Tests</span>
            <span className="detail-value">{testsRun} executed</span>
          </div>
        </div>

        {/* Severity Distribution Visual Bar */}
        <div className="dist-bar-wrapper">
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
            <span>Severity Distribution</span>
            <span>{total > 0 ? `${total} Evaluated Findings` : 'No active vulnerabilities'}</span>
          </div>
          <div className="dist-bar">
            {total === 0 ? (
              <div style={{ width: '100%', height: '100%', background: 'var(--status-verified)' }} title="All clean" />
            ) : (
              <>
                {criticalPct > 0 && <div className="dist-segment" style={{ width: `${criticalPct}%`, background: 'var(--sev-critical)' }} title={`Critical: ${critical}`} />}
                {highPct > 0 && <div className="dist-segment" style={{ width: `${highPct}%`, background: 'var(--sev-high)' }} title={`High: ${high}`} />}
                {mediumPct > 0 && <div className="dist-segment" style={{ width: `${mediumPct}%`, background: 'var(--sev-med)' }} title={`Medium: ${medium}`} />}
                {lowPct > 0 && <div className="dist-segment" style={{ width: `${lowPct}%`, background: 'var(--sev-low)' }} title={`Low: ${low}`} />}
                {infoPct > 0 && <div className="dist-segment" style={{ width: `${infoPct}%`, background: 'var(--text-muted)' }} title={`Info: ${info}`} />}
              </>
            )}
          </div>
          <div className="dist-legend">
            <div className="legend-item">
              <span className="legend-dot" style={{ background: 'var(--sev-critical)' }} />
              <span>Critical ({critical})</span>
            </div>
            <div className="legend-item">
              <span className="legend-dot" style={{ background: 'var(--sev-high)' }} />
              <span>High ({high})</span>
            </div>
            <div className="legend-item">
              <span className="legend-dot" style={{ background: 'var(--sev-med)' }} />
              <span>Medium ({medium})</span>
            </div>
            <div className="legend-item">
              <span className="legend-dot" style={{ background: 'var(--sev-low)' }} />
              <span>Low ({low})</span>
            </div>
            <div className="legend-item">
              <span className="legend-dot" style={{ background: 'var(--status-verified)' }} />
              <span>Verified Fixed ({verifiedFixesCount})</span>
            </div>
          </div>
        </div>

        <div style={{ background: 'var(--bg-subtle)', padding: '12px 14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          <strong style={{ color: 'var(--text-primary)' }}>Risk Model Note:</strong> Severity ratings are derived from deterministic WorldGuard assessment rules using confidentiality, integrity, availability, and exploitability factors. No numerical CVSS score is assigned.
        </div>
      </div>
    </div>
  );
}
