import React from 'react';

export default function SummaryCards({
  totalFindings = 0,
  severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
  verifiedFixesCount = 0,
}) {
  const cards = [
    {
      label: 'Total Findings',
      value: totalFindings,
      badge: totalFindings === 0 ? 'Clear' : 'Active',
      badgeClass: totalFindings === 0 ? 'badge-verified' : 'badge-high',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      ),
    },
    {
      label: 'Critical',
      value: severityCounts.Critical || 0,
      badge: 'P0',
      badgeClass: 'badge-critical',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polygon points="12 2 2 22 22 22 12 2" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      ),
    },
    {
      label: 'High Severity',
      value: severityCounts.High || 0,
      badge: 'P1',
      badgeClass: 'badge-high',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      ),
    },
    {
      label: 'Medium Severity',
      value: severityCounts.Medium || 0,
      badge: 'P2',
      badgeClass: 'badge-medium',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="12" x2="12" y2="16" />
          <line x1="12" y1="8" x2="12.01" y2="8" />
        </svg>
      ),
    },
    {
      label: 'Low Severity',
      value: severityCounts.Low || 0,
      badge: 'P3',
      badgeClass: 'badge-low',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 16v-4" />
          <path d="M12 8h.01" />
        </svg>
      ),
    },
    {
      label: 'Verified Fixes',
      value: verifiedFixesCount,
      badge: verifiedFixesCount > 0 ? 'Retested' : 'None',
      badgeClass: 'badge-verified',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
          <polyline points="22 4 12 14.01 9 11.01" />
        </svg>
      ),
    },
  ];

  return (
    <div className="summary-grid">
      {cards.map((card, idx) => (
        <div key={idx} className="summary-card">
          <div className="card-top">
            <span className="card-label">{card.label}</span>
            <span className={`card-badge ${card.badgeClass}`}>{card.badge}</span>
          </div>
          <div className="card-value">{card.value}</div>
        </div>
      ))}
    </div>
  );
}
