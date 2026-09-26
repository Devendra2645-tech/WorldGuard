import React, { useState } from 'react';

export default function AISecurityBrief({
  aiSummary,
  isLoading,
  onGenerateSummary,
  hasActiveAssessment = false,
}) {
  const [activeTab, setActiveTab] = useState('executive'); // 'executive' | 'analyst'
  const [isCollapsed, setIsCollapsed] = useState(false);

  const isFallback = aiSummary?.generated_by === 'deterministic_fallback';

  return (
    <div className="panel-card">
      <div className="panel-header">
        <div className="panel-title-group" style={{ flexWrap: 'wrap', gap: '8px' }}>
          <span className="panel-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2.2">
              <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 15h-2v-6h2zm0-8h-2V7h2z" />
            </svg>
            WorldGuard AI Security Brief
          </span>
          <span className="card-badge badge-medium" style={{ fontSize: '0.68rem', fontWeight: 700 }}>
            AI-GENERATED ADVISORY — NON-AUTHORITATIVE
          </span>
          {aiSummary && (
            <span className={`card-badge ${isFallback ? 'badge-low' : 'badge-verified'}`} style={{ fontSize: '0.68rem' }}>
              {isFallback ? 'Engine: Deterministic Fallback' : 'Engine: AI Assisted'}
            </span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {hasActiveAssessment && (
            <button
              type="button"
              className="btn-secondary"
              onClick={onGenerateSummary}
              disabled={isLoading}
              style={{ padding: '5px 12px', fontSize: '0.78rem' }}
              title="Synthesize AI security brief from deterministic assessment results"
            >
              {isLoading ? (
                <>
                  <span className="spinner" style={{ width: '12px', height: '12px' }} />
                  <span>Generating Brief...</span>
                </>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="23 4 23 10 17 10" />
                    <polyline points="1 20 1 14 7 14" />
                    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
                  </svg>
                  <span>{aiSummary ? 'Refresh Brief' : 'Generate AI Brief'}</span>
                </>
              )}
            </button>
          )}

          <button
            type="button"
            className="btn-secondary"
            onClick={() => setIsCollapsed(!isCollapsed)}
            style={{ padding: '4px 8px', fontSize: '0.8rem' }}
            title={isCollapsed ? 'Expand panel' : 'Collapse panel'}
          >
            {isCollapsed ? '▼ Expand' : '▲ Collapse'}
          </button>
        </div>
      </div>

      {!isCollapsed && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginTop: '6px' }}>
          {!aiSummary && !isLoading ? (
            <div style={{ background: 'var(--bg-subtle)', padding: '16px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                Deterministic assessment results are ready. Click <strong>Generate AI Brief</strong> to synthesize an executive posture overview and technical analyst digest.
              </div>
              <button
                type="button"
                className="btn-primary"
                onClick={onGenerateSummary}
                style={{ padding: '6px 14px', fontSize: '0.8rem' }}
              >
                Synthesize AI Security Brief
              </button>
            </div>
          ) : (
            <>
              {/* Tab Navigation */}
              <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                <button
                  type="button"
                  onClick={() => setActiveTab('executive')}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '5px',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    color: activeTab === 'executive' ? 'var(--color-primary)' : 'var(--text-secondary)',
                    background: activeTab === 'executive' ? 'var(--color-primary-subtle)' : 'transparent',
                    border: activeTab === 'executive' ? '1px solid var(--color-primary-border)' : '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                  }}
                >
                  Executive Brief
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('analyst')}
                  style={{
                    padding: '6px 14px',
                    borderRadius: '5px',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    color: activeTab === 'analyst' ? 'var(--color-primary)' : 'var(--text-secondary)',
                    background: activeTab === 'analyst' ? 'var(--color-primary-subtle)' : 'transparent',
                    border: activeTab === 'analyst' ? '1px solid var(--color-primary-border)' : '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                  }}
                >
                  Analyst Technical Digest
                </button>
              </div>

              {/* Tab Content */}
              <div style={{ background: 'var(--bg-subtle)', padding: '16px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: 1.6 }}>
                {activeTab === 'executive' ? (
                  <div>
                    <div style={{ fontWeight: 700, color: 'var(--color-primary)', marginBottom: '6px', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Executive Posture Summary
                    </div>
                    <div style={{ color: 'var(--text-secondary)' }}>
                      {aiSummary?.executive_summary}
                    </div>
                  </div>
                ) : (
                  <div>
                    <div style={{ fontWeight: 700, color: 'var(--color-primary)', marginBottom: '6px', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Security Engineering & Analyst Digest
                    </div>
                    <div style={{ color: 'var(--text-secondary)' }}>
                      {aiSummary?.analyst_summary}
                    </div>
                  </div>
                )}
              </div>

              {/* Key Risks & Recommended Actions Split Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
                {/* Key Risks */}
                <div style={{ background: 'var(--bg-subtle)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <span className="detail-section-title" style={{ color: 'var(--sev-high)' }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <polygon points="12 2 2 22 22 22 12 2" />
                    </svg>
                    Prioritized Risk Indicators
                  </span>
                  <ul style={{ paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {aiSummary?.key_risks?.map((risk, idx) => (
                      <li key={idx}>{risk}</li>
                    )) || <li>No active risks identified.</li>}
                  </ul>
                </div>

                {/* Recommended Actions */}
                <div style={{ background: 'var(--bg-subtle)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <span className="detail-section-title" style={{ color: 'var(--status-verified)' }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    Recommended Remediation Checklist
                  </span>
                  <ol style={{ paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {aiSummary?.recommended_actions?.map((action, idx) => (
                      <li key={idx}>{action}</li>
                    )) || <li>Maintain regular defensive scans.</li>}
                  </ol>
                </div>
              </div>

              {/* Notice */}
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>
                  <strong>Note:</strong> AI analysis interprets deterministic findings only. It does not fabricate vulnerabilities or numerical CVSS scores.
                </span>
                {isFallback && (
                  <span style={{ color: 'var(--text-muted)' }}>
                    AI provider unavailable — showing deterministic WorldGuard advisory.
                  </span>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
