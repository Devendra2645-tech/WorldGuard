import React from 'react';

export default function RemediationModal({
  isOpen,
  onClose,
  onConfirmRemediation,
  isRemediating,
  findingId = 'WG-AC-004',
}) {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={isRemediating ? undefined : onClose}>
      <div className="modal-content" style={{ maxWidth: '580px' }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '32px', height: '32px', borderRadius: '6px', background: 'var(--status-verified-bg)', border: '1px solid var(--status-verified-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--status-verified)' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            </div>
            <div>
              <h3 style={{ fontSize: '1.05rem', color: 'var(--text-primary)', fontWeight: 800 }}>
                Confirm Remediation & Automatic Retest
              </h3>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                Target: http://127.0.0.1:8001 (Authorized Demo Target)
              </div>
            </div>
          </div>
          {!isRemediating && (
            <button type="button" className="btn-secondary" onClick={onClose} style={{ padding: '4px 10px' }}>
              ×
            </button>
          )}
        </div>

        <div className="modal-body" style={{ gap: '16px' }}>
          <div style={{ background: 'var(--bg-subtle)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span className="detail-label">Target Finding:</span>
              <span className="font-mono" style={{ color: 'var(--color-primary)', fontWeight: 700 }}>{findingId}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span className="detail-label">Vulnerability Class:</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '0.82rem' }}>Broken Access Control (CWE-862)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span className="detail-label">Target Route:</span>
              <span className="font-mono" style={{ color: 'var(--text-primary)', fontSize: '0.82rem' }}>GET /api/admin</span>
            </div>
          </div>

          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            <strong style={{ color: 'var(--text-primary)' }}>Verification Workflow:</strong>
            <ol style={{ paddingLeft: '20px', marginTop: '6px', display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <li><strong>Precondition Verification:</strong> Confirm endpoint currently returns HTTP 200 to Normal User.</li>
              <li><strong>Apply Demo Fix:</strong> Send configuration update to toggle server-side role validation.</li>
              <li><strong>Automatic Retest:</strong> Issue request as Normal User to verify HTTP 403 Forbidden is returned.</li>
              <li><strong>Admin Regression Check:</strong> Re-test Admin role to confirm legitimate access remains HTTP 200 OK.</li>
              <li><strong>Evidence Logging:</strong> Capture sanitized before/after audit trace to SQLite.</li>
            </ol>
          </div>

          {isRemediating && (
            <div style={{ background: 'var(--color-primary-subtle)', border: '1px solid var(--color-primary-border)', padding: '14px', borderRadius: '6px', display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span className="spinner" />
              <div style={{ fontSize: '0.85rem', color: 'var(--color-primary)', fontWeight: 600 }}>
                Applying fix and executing multi-step verification retest...
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button
            type="button"
            className="btn-secondary"
            onClick={onClose}
            disabled={isRemediating}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn-primary"
            style={{ background: 'var(--status-verified)', borderColor: 'var(--status-verified)' }}
            onClick={onConfirmRemediation}
            disabled={isRemediating}
          >
            {isRemediating ? 'Verifying...' : 'Execute & Retest'}
          </button>
        </div>
      </div>
    </div>
  );
}
