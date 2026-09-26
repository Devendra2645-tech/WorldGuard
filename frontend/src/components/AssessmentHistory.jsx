import React from 'react';

export default function AssessmentHistory({
  scans = [],
  selectedScanId = null,
  onSelectScan,
  isLoadingHistory = false,
  onExportJson,
  onExportPdf,
}) {
  const getRiskBadge = (risk) => {
    switch (risk?.toLowerCase()) {
      case 'critical':
        return <span className="card-badge badge-critical">CRITICAL</span>;
      case 'high':
        return <span className="card-badge badge-high">HIGH</span>;
      case 'medium':
        return <span className="card-badge badge-medium">MEDIUM</span>;
      case 'low':
        return <span className="card-badge badge-low">LOW</span>;
      case 'info':
      case 'verified':
        return <span className="card-badge badge-verified">VERIFIED</span>;
      default:
        return <span className="card-badge badge-low">{risk || 'LOW'}</span>;
    }
  };

  return (
    <div className="history-section">
      <div className="panel-header">
        <div className="panel-title-group">
          <span className="panel-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            Assessment & Verification History
          </span>
          <span className="card-badge badge-low">{scans.length} Records</span>
        </div>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          Persisted SQLite Audit Log
        </div>
      </div>

      {isLoadingHistory ? (
        <div className="empty-state">
          <span className="spinner" style={{ width: '28px', height: '28px' }} />
          <div style={{ fontSize: '0.85rem' }}>Loading assessment records from backend database...</div>
        </div>
      ) : scans.length === 0 ? (
        <div className="empty-state">
          <svg className="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
          </svg>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>No historical scans found</div>
          <div style={{ fontSize: '0.8rem' }}>Run a security assessment or verify remediation to populate the audit log.</div>
        </div>
      ) : (
        <div className="table-responsive">
          <table className="findings-table">
            <thead>
              <tr>
                <th>Record ID</th>
                <th>Target / Operation</th>
                <th>Assessment Timestamp</th>
                <th>Risk Posture</th>
                <th>Findings</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const isSelected = selectedScanId === scan.id;
                const formattedDate = scan.scanned_at
                  ? new Date(scan.scanned_at).toLocaleString()
                  : 'N/A';

                return (
                  <tr key={scan.id} className={isSelected ? 'finding-row-selected' : ''}>
                    <td>
                      <span className="font-mono" style={{ color: 'var(--color-primary)', fontWeight: 600 }}>
                        #{scan.id}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {scan.target}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        {formattedDate}
                      </span>
                    </td>
                    <td>{getRiskBadge(scan.risk_level)}</td>
                    <td>
                      <span style={{ fontWeight: 600 }}>{scan.total_findings}</span>
                    </td>
                    <td>
                      <span className="card-badge badge-verified" style={{ fontSize: '0.7rem' }}>
                        {scan.status || 'COMPLETED'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                        <button
                          type="button"
                          className="btn-table-action"
                          onClick={() => onSelectScan(scan.id)}
                        >
                          Load
                        </button>
                        <button
                          type="button"
                          className="btn-table-action"
                          title={`Export JSON report for record #${scan.id}`}
                          onClick={() => onExportJson && onExportJson(scan.id)}
                          style={{ padding: '4px 8px', fontSize: '0.72rem' }}
                        >
                          JSON
                        </button>
                        <button
                          type="button"
                          className="btn-table-action"
                          title={`Download PDF report for record #${scan.id}`}
                          onClick={() => onExportPdf && onExportPdf(scan.id)}
                          style={{
                            padding: '4px 8px',
                            fontSize: '0.72rem',
                            color: 'var(--color-primary)',
                            borderColor: 'var(--color-primary-border)',
                          }}
                        >
                          PDF
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
