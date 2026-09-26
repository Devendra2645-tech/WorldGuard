import React, { useState, useEffect } from 'react';
import { fetchFindingAIAnalysis } from '../api/worldguardApi';

export default function FindingDetails({
  finding,
  evidenceList = [],
  remediationRecord = null,
  onClose,
  onOpenRemediationModal,
  isRemediating = false,
}) {
  if (!finding) return null;

  const [aiAnalysis, setAiAnalysis] = useState(finding.ai_analysis || null);
  const [isLoadingAI, setIsLoadingAI] = useState(false);
  const [aiError, setAiError] = useState(null);

  useEffect(() => {
    setAiAnalysis(finding.ai_analysis || null);
    setAiError(null);
  }, [finding]);

  const handleFetchAI = async () => {
    setIsLoadingAI(true);
    setAiError(null);
    try {
      const result = await fetchFindingAIAnalysis(finding.id || finding.evidence_id || 'WG-AC-004');
      setAiAnalysis(result);
    } catch (err) {
      setAiError(err.message || 'Failed to generate AI analysis.');
    } finally {
      setIsLoadingAI(false);
    }
  };


  // Find corresponding evidence record if available
  const matchingEvidence = evidenceList.find(
    (e) => e.evidence_id === finding.evidence_id
  );

  const getSeverityBadgeClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      case 'low':
        return 'badge-low';
      default:
        return 'badge-low';
    }
  };

  const isVerified =
    finding.verification_status === 'verified' ||
    (finding.evidence_id === 'WG-AC-004' && remediationRecord?.verification_status === 'verified');

  const getReproductionSteps = () => {
    if (Array.isArray(finding.steps_to_reproduce) && finding.steps_to_reproduce.length > 0) {
      return finding.steps_to_reproduce;
    }
    const evId = finding.evidence_id || 'WG-AC-004';
    if (evId === 'WG-AC-004') {
      return [
        'Authenticate using the synthetic Normal User account.',
        'Obtain the temporary demo authentication token.',
        'Request GET /api/admin using that authenticated Normal User.',
        'Observe the HTTP response.',
        'Compare the observed response with the expected HTTP 403 requirement.'
      ];
    } else if (evId === 'WG-AUTH-004') {
      return [
        'Send GET / without authentication.',
        'Inspect the JSON response.',
        'Check for credential-like fields.',
        'Confirm whether usernames/passwords or authentication secrets are exposed.',
        'Record only sanitized evidence.'
      ];
    } else if (evId === 'WG-SEC-001') {
      return [
        'Send GET /.',
        'Inspect the HTTP response headers.',
        'Check for Content-Security-Policy.',
        'Check for X-Frame-Options.',
        'Check for X-Content-Type-Options.',
        'Record missing headers as sanitized evidence.'
      ];
    } else if (evId === 'WG-API-001') {
      return [
        'Send GET /openapi.json without authentication.',
        'Observe the HTTP response.',
        'Confirm whether the schema is publicly accessible.',
        'Record only sanitized metadata about the exposed endpoint.'
      ];
    }
    return ['Send request to target endpoint.', 'Observe response against security baseline.'];
  };

  const getPocCurlCommand = () => {
    const evId = finding.evidence_id || 'WG-AC-004';
    if (evId === 'WG-AC-004') {
      return `curl -s -X GET http://127.0.0.1:8001/api/admin \\\n  -H "Authorization: Bearer [REDACTED]" \\\n  -H "Accept: application/json"`;
    } else if (evId === 'WG-AUTH-004') {
      return `curl -s -X GET http://127.0.0.1:8001/ \\\n  -H "Accept: application/json"`;
    } else if (evId === 'WG-SEC-001') {
      return `curl -s -I http://127.0.0.1:8001/`;
    } else if (evId === 'WG-API-001') {
      const ep = finding.endpoint || '/openapi.json';
      return `curl -s -X GET http://127.0.0.1:8001${ep.startsWith('/') ? ep : '/' + ep}`;
    }
    const ep = finding.endpoint || '/';
    return `curl -s -X ${finding.method || 'GET'} http://127.0.0.1:8001${ep.startsWith('/') ? ep : '/' + ep}`;
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="modal-header">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="font-mono" style={{ color: 'var(--color-primary)', fontWeight: 700 }}>
                {finding.evidence_id || 'WG-AC-004'}
              </span>
              <span className={`card-badge ${getSeverityBadgeClass(finding.severity)}`}>
                {finding.severity?.toUpperCase() || 'HIGH'}
              </span>
              {isVerified ? (
                <span className="card-badge badge-verified">✓ REMEDIATED & VERIFIED</span>
              ) : (
                <span className="card-badge badge-critical">ACTIVE VULNERABILITY</span>
              )}
            </div>
            <h2 style={{ fontSize: '1.15rem', color: 'var(--text-primary)', fontWeight: 800 }}>
              {finding.title}
            </h2>
          </div>
          <button
            type="button"
            className="btn-secondary"
            onClick={onClose}
            style={{ padding: '4px 10px', fontSize: '1.1rem', lineHeight: '1' }}
          >
            ×
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body">
          {/* SECTION 1: WHAT HAPPENED */}
          <div className="detail-section">
            <span className="detail-section-title">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              What Happened
            </span>
            <div style={{ background: 'var(--bg-subtle)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {finding.description}
            </div>
          </div>

          {/* SECTION 2: SAFE PROOF-OF-CONCEPT & REPRODUCTION */}
          <div className="detail-section">
            <span className="detail-section-title" style={{ color: 'var(--color-primary)' }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="16 18 22 12 16 6" />
                <polyline points="8 6 2 12 8 18" />
              </svg>
              Safe Proof-of-Concept &amp; Reproduction
            </span>

            <div className="detail-grid">
              <div className="detail-item">
                <span className="detail-label">Affected Component</span>
                <span className="detail-value" style={{ color: 'var(--color-primary)', fontWeight: 600 }}>
                  {finding.affected_component || (
                    finding.evidence_id === 'WG-AC-004' ? 'Admin Access Guard' :
                    finding.evidence_id === 'WG-AUTH-004' ? 'Public Landing Controller' :
                    finding.evidence_id === 'WG-SEC-001' ? 'Security Headers Middleware' :
                    finding.evidence_id === 'WG-API-001' ? 'OpenAPI Documentation Route' : 'Application Endpoint'
                  )}
                </span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Target &amp; Method</span>
                <span className="detail-value font-mono">
                  {finding.method || 'GET'} {finding.endpoint || '/'}
                </span>
              </div>
            </div>

            {/* Steps to Reproduce */}
            <div style={{ background: 'var(--bg-subtle)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', marginBottom: '8px', letterSpacing: '0.05em' }}>
                Safe Reproduction Steps (Non-Destructive Local Probe):
              </div>
              <ol style={{ margin: 0, paddingLeft: '20px', fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.6, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {getReproductionSteps().map((step, idx) => (
                  <li key={idx}>{step}</li>
                ))}
              </ol>
            </div>

            {/* Safe Test Command Code Block */}
            <div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', marginBottom: '6px', letterSpacing: '0.05em' }}>
                Safe Local curl Execution (Zero Secrets Disclosed):
              </div>
              <pre style={{ margin: 0, padding: '12px 14px', background: '#0f172a', borderRadius: '6px', border: '1px solid #1e293b', color: '#38bdf8', fontSize: '0.78rem', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
                {getPocCurlCommand()}
              </pre>
            </div>

            {/* Expected vs Observed Behavior Comparison */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
              <div style={{ background: 'var(--status-verified-bg)', border: '1px solid var(--status-verified-border)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ color: 'var(--status-verified-text)', fontWeight: 700, fontSize: '0.75rem', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span>✓ EXPECTED BEHAVIOR</span>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {finding.expected_behavior || (
                    finding.evidence_id === 'WG-AC-004' ? 'Authenticated users without the Admin role must receive HTTP 403 Forbidden when requesting the administrative endpoint.' :
                    finding.evidence_id === 'WG-AUTH-004' ? 'The unauthenticated root endpoint may return public welcome metadata, but must not expose usernames, passwords, credentials, authentication secrets, or other sensitive authentication material.' :
                    finding.evidence_id === 'WG-SEC-001' ? 'HTTP responses should include appropriate browser security headers such as Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options.' :
                    finding.evidence_id === 'WG-API-001' ? 'Production API documentation and schema endpoints should be disabled or protected from unauthenticated access.' :
                    'Expected secure behavior according to defensive policy.'
                  )}
                </div>
              </div>

              <div style={{ background: 'var(--sev-critical-bg)', border: '1px solid var(--sev-critical-border)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ color: 'var(--sev-critical-text)', fontWeight: 700, fontSize: '0.75rem', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span>⚠ OBSERVED BEHAVIOR</span>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {finding.observed_behavior || (
                    finding.evidence_id === 'WG-AC-004' ? 'A Normal User received HTTP 200 OK from the administrative endpoint while vulnerable mode was enabled.' :
                    finding.evidence_id === 'WG-AUTH-004' ? 'The unauthenticated root endpoint returned a demo_credentials field containing credential-like account information.' :
                    finding.evidence_id === 'WG-SEC-001' ? 'The inspected response did not contain the required defensive security headers.' :
                    finding.evidence_id === 'WG-API-001' ? 'The OpenAPI schema endpoint was accessible without authentication and returned HTTP 200 OK.' :
                    'Observed security gap during defensive assessment.'
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* SECTION 3: EVIDENCE */}
          <div className="detail-section">
            <span className="detail-section-title">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
              </svg>
              Deterministic Assessment Evidence
            </span>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="detail-label">Evidence ID</span>
                <span className="detail-value font-mono">{finding.evidence_id || 'WG-AC-004'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Tested Role</span>
                <span className="detail-value">{finding.tested_role || finding.affected_role || 'Normal User'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Endpoint & Method</span>
                <span className="detail-value font-mono">
                  {finding.method || 'GET'} {finding.endpoint || '/api/admin'}
                </span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Status Comparison</span>
                <span className="detail-value" style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <span style={{ color: 'var(--status-verified)' }}>
                    Expected: {matchingEvidence?.expected_status || (finding.evidence_id === 'WG-AC-004' ? '403' : '200')}
                  </span>
                  <span style={{ color: 'var(--text-muted)' }}>|</span>
                  <span style={{ color: isVerified ? 'var(--status-verified)' : 'var(--sev-critical)' }}>
                    Observed: {matchingEvidence?.observed_status || (isVerified ? '403' : '200')}
                  </span>
                </span>
              </div>
            </div>

            {matchingEvidence && (
              <div className="evidence-box">
                <div style={{ color: 'var(--text-muted)', marginBottom: '6px', fontSize: '0.75rem' }}>
                  Sanitized Request Audit (Secrets / Credentials Redacted):
                </div>
                {matchingEvidence.request_info?.headers?.Authorization && (
                  <div>Authorization: <span className="redacted-tag">[REDACTED]</span></div>
                )}
                <div>Method: {matchingEvidence.method} {matchingEvidence.endpoint}</div>
                <div>Observed Response Code: HTTP {matchingEvidence.observed_status}</div>
                {matchingEvidence.response_excerpt && (
                  <div style={{ marginTop: '6px', color: 'var(--text-muted)' }}>
                    Response Payload: {typeof matchingEvidence.response_excerpt === 'string' ? matchingEvidence.response_excerpt : JSON.stringify(matchingEvidence.response_excerpt)}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* SECTION 3: RISK ANALYSIS */}
          <div className="detail-section">
            <span className="detail-section-title">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="12 2 2 22 22 22 12 2" />
              </svg>
              Risk Analysis & CVSS Metrics
            </span>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="detail-label">Severity Level</span>
                <span className="detail-value" style={{ color: 'var(--sev-high)' }}>{finding.severity || 'High'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Severity Method</span>
                <span className="detail-value">{finding.severity_method || 'WorldGuard prototype rule'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Exploitability</span>
                <span className="detail-value" style={{ color: 'var(--sev-high)' }}>{finding.exploitability || 'High'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Confidentiality Impact</span>
                <span className="detail-value" style={{ color: 'var(--sev-high)' }}>{finding.confidentiality_impact || 'High'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Integrity Impact</span>
                <span className="detail-value" style={{ color: 'var(--sev-high)' }}>{finding.integrity_impact || 'High'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Availability Impact</span>
                <span className="detail-value" style={{ color: 'var(--sev-low)' }}>{finding.availability_impact || 'Low'}</span>
              </div>
            </div>
          </div>

          {/* SECTION 4: BUSINESS IMPACT */}
          <div className="detail-section">
            <span className="detail-section-title">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="2" y="7" width="20" height="14" rx="2" ry="2" />
                <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
              </svg>
              Operational & Business Impact
            </span>
            <div className="detail-grid">
              <div className="detail-item">
                <span className="detail-label">Affected Role</span>
                <span className="detail-value">{finding.affected_role || 'Normal User'}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Remediation Priority</span>
                <span className="detail-value" style={{ color: 'var(--sev-high)' }}>{finding.remediation_priority || 'High'}</span>
              </div>
            </div>
            <div className="detail-item">
              <span className="detail-label">Data Sensitivity</span>
              <span className="detail-value" style={{ fontSize: '0.85rem' }}>
                {finding.data_sensitivity || 'Administrative system telemetry and restricted functionality'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Business Consequence</span>
              <span className="detail-value" style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-secondary)' }}>
                {finding.business_impact ||
                  'An authenticated user without administrative privileges may access restricted administrative functionality, creating a risk of unauthorized information access and unauthorized administrative actions.'}
              </span>
            </div>
          </div>

          {/* SECTION 6: REMEDIATION & VERIFICATION */}
          <div className="detail-section">
            <span className="detail-section-title">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Remediation Guidance &amp; Verification Status
            </span>
            <div style={{ background: 'var(--bg-subtle)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              <strong style={{ color: 'var(--text-primary)' }}>Recommended Action:</strong>{' '}
              {finding.remediation || (
                finding.evidence_id === 'WG-AC-004' ? 'Implement server-side role validation requiring current_user[\'role\'] == \'Admin\' before processing requests on /api/admin.' :
                finding.evidence_id === 'WG-AUTH-004' ? 'Remove hardcoded credentials and demo account material from public API responses. Store secrets securely and enforce strict access controls.' :
                finding.evidence_id === 'WG-SEC-001' ? 'Configure HTTP middleware to inject Content-Security-Policy, X-Frame-Options (DENY/SAMEORIGIN), and X-Content-Type-Options (nosniff) headers on all responses.' :
                finding.evidence_id === 'WG-API-001' ? 'Restrict access to OpenAPI specification and Swagger UI documentation in production environments using authentication guards or disabling documentation endpoints.' :
                'Remediate vulnerability according to standard security practices.'
              )}
            </div>

            {finding.evidence_id === 'WG-AC-004' ? (
              <div className="detail-grid">
                <div className="detail-item">
                  <span className="detail-label">Pre-Remediation Status</span>
                  <span className="detail-value font-mono" style={{ color: 'var(--sev-critical)' }}>
                    {remediationRecord ? `HTTP ${remediationRecord.pre_remediation_status}` : 'HTTP 200 OK (Vulnerable)'}
                  </span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Post-Remediation Retest</span>
                  <span className="detail-value font-mono" style={{ color: isVerified ? 'var(--status-verified)' : 'var(--sev-med)' }}>
                    {isVerified ? 'HTTP 403 Forbidden' : 'Pending Verification'}
                  </span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Verification Status</span>
                  <span className="detail-value">
                    {isVerified ? (
                      <span style={{ color: 'var(--status-verified)' }}>✓ Verified Fixed</span>
                    ) : (
                      <span style={{ color: 'var(--sev-critical)' }}>Unverified / Vulnerable</span>
                    )}
                  </span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Admin Regression Check</span>
                  <span className="detail-value">
                    {isVerified ? (
                      <span style={{ color: 'var(--status-verified)' }}>Passed (HTTP 200 OK)</span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>Pending Retest</span>
                    )}
                  </span>
                </div>
              </div>
            ) : (
              <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px 14px', color: 'var(--text-secondary)', fontSize: '0.82rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                <span>Remediation verification not yet implemented for this finding.</span>
                <span className="card-badge badge-high">
                  OPEN / UNREMEDIATED
                </span>
              </div>
            )}
          </div>

          {/* SECTION 6: AI ANALYSIS & ADVISORY */}
          <div className="detail-section" style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
              <span className="detail-section-title" style={{ color: 'var(--color-primary)' }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 15h-2v-6h2zm0-8h-2V7h2z" />
                </svg>
                AI Analysis & Prioritization Advisory
              </span>
              <span className="card-badge badge-medium" style={{ fontSize: '0.68rem', fontWeight: 700 }}>
                AI-GENERATED ADVISORY — NON-AUTHORITATIVE
              </span>
            </div>

            {!aiAnalysis && !isLoadingAI ? (
              <div style={{ background: 'var(--bg-subtle)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Synthesize plain-language explanation, operational impact narrative, and developer guidance for this finding.
                </span>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={handleFetchAI}
                  style={{ padding: '6px 12px', fontSize: '0.8rem', borderColor: 'var(--color-primary-border)', color: 'var(--color-primary)' }}
                >
                  Generate AI Advisory
                </button>
              </div>
            ) : isLoadingAI ? (
              <div style={{ background: 'var(--bg-subtle)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '0.82rem', color: 'var(--color-primary)' }}>
                <span className="spinner" style={{ width: '14px', height: '14px' }} />
                <span>Synthesizing structured advisory analysis...</span>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {aiAnalysis?.generated_by === 'deterministic_fallback' && (
                  <div style={{ background: 'var(--bg-inset)', padding: '8px 12px', borderRadius: '5px', border: '1px solid var(--border-subtle)', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    AI provider unavailable — showing deterministic WorldGuard advisory.
                  </div>
                )}

                <div className="detail-item">
                  <span className="detail-label">Vulnerability Mechanism</span>
                  <span className="detail-value" style={{ fontSize: '0.84rem', fontWeight: 400, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {aiAnalysis?.explanation}
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Contextual Business Risk</span>
                  <span className="detail-value" style={{ fontSize: '0.84rem', fontWeight: 400, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {aiAnalysis?.business_impact}
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Prioritization Rationale</span>
                  <span className="detail-value" style={{ fontSize: '0.84rem', fontWeight: 400, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {aiAnalysis?.prioritization_rationale}
                  </span>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Advisory Developer Remediation</span>
                  <pre style={{ margin: '4px 0 0', padding: '10px', background: 'var(--bg-inset)', borderRadius: '4px', border: '1px solid var(--border-subtle)', fontSize: '0.78rem', color: 'var(--text-primary)', whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
                    {aiAnalysis?.remediation_guidance}
                  </pre>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Validation & Retest Procedure</span>
                  <pre style={{ margin: '4px 0 0', padding: '10px', background: 'var(--bg-inset)', borderRadius: '4px', border: '1px solid var(--border-subtle)', fontSize: '0.78rem', color: 'var(--status-verified-text)', whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
                    {aiAnalysis?.verification_procedure}
                  </pre>
                </div>
              </div>
            )}
            {aiError && (
              <div style={{ color: 'var(--sev-critical)', fontSize: '0.78rem' }}>{aiError}</div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="modal-footer">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close
          </button>
          {finding.evidence_id === 'WG-AC-004' && !isVerified && (
            <button
              type="button"
              className="btn-primary"
              style={{ background: '#059669', borderColor: '#10b981' }}
              onClick={() => {
                onClose();
                onOpenRemediationModal();
              }}
              disabled={isRemediating}
            >
              Verify Remediation Now
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
