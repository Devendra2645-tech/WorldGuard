import React from 'react';

export default function BeforeAfterVerification({
  remediationRecord = null,
  isRemediating = false,
  onOpenRemediationModal,
  hasVulnerableFinding = false,
}) {
  const isVerified = remediationRecord?.verification_status === 'verified';

  return (
    <div className="panel-card" style={{ border: isVerified ? '1px solid var(--status-verified-border)' : '1px solid var(--border-subtle)' }}>
      <div className="panel-header">
        <div className="panel-title-group">
          <span className="panel-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--status-verified)" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
            Automated Remediation & Retest Verification
          </span>
          <span className="cwe-tag">WG-AC-004 (CWE-862)</span>
        </div>

        <div>
          {isVerified ? (
            <span className="card-badge badge-verified" style={{ fontSize: '0.8rem', padding: '4px 10px' }}>
              ✓ Remediated & Verified
            </span>
          ) : hasVulnerableFinding ? (
            <button
              type="button"
              className="btn-primary"
              style={{ background: 'var(--status-verified)', borderColor: 'var(--status-verified)', padding: '6px 14px', fontSize: '0.8rem' }}
              onClick={onOpenRemediationModal}
              disabled={isRemediating}
              title="Apply demo authorization fix and verify via automatic retest"
            >
              {isRemediating ? (
                <>
                  <span className="spinner" />
                  <span>Verifying Fix...</span>
                </>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  <span>Verify Remediation</span>
                </>
              )}
            </button>
          ) : (
            <span className="card-badge badge-low" style={{ fontSize: '0.78rem' }}>
              Standing By
            </span>
          )}
        </div>
      </div>

      <div className="workflow-stepper">
        {/* Step 1: BEFORE */}
        <div className="step-card before-vuln">
          <div className="step-info">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="step-tag badge-critical">1. Before Remediation</span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Baseline Access Test</span>
            </div>
            <div className="step-target-line">
              <span>Normal User</span>
              <span style={{ color: 'var(--text-muted)' }}>→</span>
              <span style={{ color: 'var(--color-primary)' }}>GET /api/admin</span>
            </div>
            <div className="step-details-line">
              Administrative telemetry accessible by unprivileged user without role restriction.
            </div>
          </div>
          <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
            <span className="card-badge badge-critical" style={{ fontFamily: 'var(--font-mono)' }}>
              HTTP 200 OK
            </span>
            <span style={{ fontSize: '0.7rem', color: 'var(--sev-critical)', fontWeight: '700' }}>VULNERABLE</span>
          </div>
        </div>

        {/* Stepper Connector 1 */}
        <div className="flow-connector">
          <span>↓</span>
          <span>Controlled Fix Applied: POST /api/admin/mode (vulnerable_mode: false)</span>
          <span>↓</span>
        </div>

        {/* Step 2: AFTER RETEST */}
        <div className={`step-card ${isVerified ? 'after-verified' : 'action-applied'}`}>
          <div className="step-info">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className={`step-tag ${isVerified ? 'badge-verified' : 'badge-low'}`}>
                2. Automatic Retest
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Role Enforcement Validation</span>
            </div>
            <div className="step-target-line">
              <span>Normal User</span>
              <span style={{ color: 'var(--text-muted)' }}>→</span>
              <span style={{ color: 'var(--color-primary)' }}>GET /api/admin</span>
            </div>
            <div className="step-details-line">
              Server-side RBAC dependency verifies role == &apos;Admin&apos; and rejects unprivileged access.
            </div>
          </div>
          <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
            <span className={`card-badge ${isVerified ? 'badge-verified' : 'badge-low'}`} style={{ fontFamily: 'var(--font-mono)' }}>
              {isVerified ? 'HTTP 403 Forbidden' : 'Expected: HTTP 403'}
            </span>
            <span style={{ fontSize: '0.7rem', color: isVerified ? 'var(--status-verified)' : 'var(--text-muted)', fontWeight: '700' }}>
              {isVerified ? 'FIX VERIFIED' : 'PENDING RETEST'}
            </span>
          </div>
        </div>

        {/* Step 3: ADMIN REGRESSION CHECK */}
        <div className={`step-card ${isVerified ? 'after-verified' : 'action-applied'}`} style={{ background: isVerified ? 'var(--status-verified-bg)' : undefined }}>
          <div className="step-info">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className={`step-tag ${isVerified ? 'badge-verified' : 'badge-low'}`}>
                3. Regression Verification
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Legitimate User Access Integrity</span>
            </div>
            <div className="step-target-line">
              <span>Admin</span>
              <span style={{ color: 'var(--text-muted)' }}>→</span>
              <span style={{ color: 'var(--color-primary)' }}>GET /api/admin</span>
            </div>
            <div className="step-details-line">
              Confirms legitimate administrative operators retain full unrestricted access.
            </div>
          </div>
          <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
            <span className={`card-badge ${isVerified ? 'badge-verified' : 'badge-low'}`} style={{ fontFamily: 'var(--font-mono)' }}>
              {isVerified ? 'HTTP 200 OK' : 'Expected: HTTP 200'}
            </span>
            <span style={{ fontSize: '0.7rem', color: isVerified ? 'var(--status-verified)' : 'var(--text-muted)', fontWeight: '700' }}>
              {isVerified ? 'REGRESSION CHECK PASSED' : 'PENDING CHECK'}
            </span>
          </div>
        </div>
      </div>

      {remediationRecord && (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', background: 'var(--bg-subtle)', padding: '10px 14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>
            Verification Audit ID: <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>#{remediationRecord.verification_id}</strong>
          </span>
          <span>
            Retested: <strong style={{ color: 'var(--text-primary)' }}>{new Date(remediationRecord.verified_at).toLocaleTimeString()}</strong>
          </span>
        </div>
      )}
    </div>
  );
}
