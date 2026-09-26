import React from 'react';

export default function Header({
  isBackendOnline,
  isAssessing,
  onRunAssessment,
  targetUrl = 'http://127.0.0.1:8001',
  activeAssessmentId = null,
  onExportJson,
  onExportPdf,
}) {
  return (
    <header className="header-wrapper">
      <div className="header-inner">
        <div className="brand-section">
          <div className="brand-icon" title="WorldGuard Security Engine">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <div>
            <div className="brand-title">
              WorldGuard
              <span className="brand-badge">SIH 2026</span>
            </div>
            <div className="brand-subtitle">
              Defensive Security Assessment Platform & Remediation Verifier
            </div>
          </div>
        </div>

        <div className="header-status-group">
          <div className="target-badge" title="Authorized Target Environment">
            <span className="target-label">Target:</span>
            <span className="target-value">{targetUrl}</span>
          </div>

          <div
            className={`backend-indicator ${isBackendOnline ? 'backend-online' : 'backend-offline'}`}
            title={isBackendOnline ? 'Connected to WorldGuard FastAPI backend (port 8000)' : 'Disconnected from backend'}
          >
            <span className={`status-dot ${isBackendOnline ? 'pulse' : ''}`} />
            <span>{isBackendOnline ? 'API Online' : 'API Offline'}</span>
          </div>

          {activeAssessmentId && (
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                type="button"
                className="btn-secondary"
                onClick={onExportJson}
                title="Export structured JSON security audit report"
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                <span>JSON Report</span>
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={onExportPdf}
                title="Download SIH defense-ready PDF security audit report"
                style={{ borderColor: 'var(--color-primary-border)', color: 'var(--color-primary)' }}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                  <polyline points="10 9 9 9 8 9" />
                </svg>
                <span>PDF Report</span>
              </button>
            </div>
          )}

          <button
            type="button"
            className="btn-primary"
            onClick={onRunAssessment}
            disabled={isAssessing || !isBackendOnline}
            title="Execute non-destructive security assessment against authorized demo target"
          >
            {isAssessing ? (
              <>
                <span className="spinner" />
                <span>Running Assessment...</span>
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
                <span>Run Demo Assessment</span>
              </>
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
