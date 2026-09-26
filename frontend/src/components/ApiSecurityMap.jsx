import React, { useState, useMemo } from 'react';

/**
 * 13 Known Authorized Demo Target Routes for fallback/reference.
 */
const DEFAULT_DEMO_ROUTES = [
  {
    endpoint: '/',
    method: 'GET',
    authentication: 'Public',
    required_role: 'None',
    data_modifying: false,
    security_status: 'FINDING',
    observed_status: 200,
    expected_status: 200,
    finding_id: 'WG-AUTH-004, WG-SEC-001',
    finding_ids: ['WG-AUTH-004', 'WG-SEC-001'],
    severity: 'High',
    affected_component: 'Public Landing Controller, Security Headers Middleware',
    security_note: 'Unauthenticated root landing endpoint exposes synthetic credentials in JSON (WG-AUTH-004) and lacks protective HTTP security headers (WG-SEC-001).',
  },
  {
    endpoint: '/health',
    method: 'GET',
    authentication: 'Public',
    required_role: 'None',
    data_modifying: false,
    security_status: 'PUBLIC',
    observed_status: 200,
    expected_status: 200,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: null,
    security_note: 'Intentionally unauthenticated health check probe.',
  },
  {
    endpoint: '/api/auth/login',
    method: 'POST',
    authentication: 'Public',
    required_role: 'None',
    data_modifying: true,
    security_status: 'PASS',
    observed_status: 200,
    expected_status: 200,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: null,
    security_note: 'Authentication verified: Valid demo login succeeds (HTTP 200); invalid credentials rejected with HTTP 401 Unauthorized.',
  },
  {
    endpoint: '/api/auth/me',
    method: 'GET',
    authentication: 'Required',
    required_role: 'Any Authenticated Role',
    data_modifying: false,
    security_status: 'PASS',
    observed_status: 200,
    expected_status: 200,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: null,
    security_note: 'Session authentication verified: Valid Bearer token accesses user profile (HTTP 200 OK); missing and invalid tokens rejected with HTTP 401 Unauthorized.',
  },
  {
    endpoint: '/api/users',
    method: 'GET',
    authentication: 'Required',
    required_role: 'Admin, Analyst',
    data_modifying: false,
    security_status: 'NOT_ASSESSED',
    observed_status: null,
    expected_status: null,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: null,
    security_note: 'Not evaluated in automated assessment suite (requires Admin or Analyst role in code).',
  },
  {
    endpoint: '/api/reports',
    method: 'GET',
    authentication: 'Required',
    required_role: 'Any Authenticated Role',
    data_modifying: false,
    security_status: 'PASS',
    observed_status: 200,
    expected_status: 200,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: null,
    security_note: 'Read authorization verified: Authenticated Normal User successfully lists telemetry reports (HTTP 200 OK).',
  },
  {
    endpoint: '/api/reports',
    method: 'POST',
    authentication: 'Required',
    required_role: 'Admin, Analyst, Operator',
    data_modifying: true,
    security_status: 'PASS',
    observed_status: 403,
    expected_status: 403,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: null,
    security_note: 'Write authorization verified: Unprivileged Normal User rejected with HTTP 403 Forbidden.',
  },
  {
    endpoint: '/api/analytics',
    method: 'GET',
    authentication: 'Required',
    required_role: 'Admin, Analyst',
    data_modifying: false,
    security_status: 'NOT_ASSESSED',
    observed_status: null,
    expected_status: null,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: null,
    security_note: 'Not evaluated in automated assessment suite (requires Admin or Analyst role in code).',
  },
  {
    endpoint: '/api/admin',
    method: 'GET',
    authentication: 'Required',
    required_role: 'Admin',
    data_modifying: false,
    security_status: 'FINDING',
    observed_status: 200,
    expected_status: 403,
    finding_id: 'WG-AC-004',
    finding_ids: ['WG-AC-004'],
    severity: 'High',
    affected_component: 'Admin Access Guard',
    security_note: 'Broken Access Control (CWE-862): Normal User received HTTP 200 OK instead of expected HTTP 403 Forbidden while vulnerable mode was active.',
  },
  {
    endpoint: '/api/admin/mode',
    method: 'GET',
    authentication: 'Public',
    required_role: 'None',
    data_modifying: false,
    security_status: 'PUBLIC',
    observed_status: 200,
    expected_status: 200,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: null,
    security_note: 'Benchmark control route: Inspects demo vulnerability mode (vulnerable vs fixed).',
  },
  {
    endpoint: '/api/admin/mode',
    method: 'POST',
    authentication: 'Public',
    required_role: 'None',
    data_modifying: true,
    security_status: 'PUBLIC',
    observed_status: 200,
    expected_status: 200,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: null,
    security_note: 'Benchmark control route: Toggles demo vulnerability state for before/after demonstration.',
  },
  {
    endpoint: '/openapi.json',
    method: 'GET',
    authentication: 'Public',
    required_role: 'None',
    data_modifying: false,
    security_status: 'FINDING',
    observed_status: 200,
    expected_status: 401,
    finding_id: 'WG-API-001',
    finding_ids: ['WG-API-001'],
    severity: 'Info',
    affected_component: 'OpenAPI Documentation Route',
    security_note: 'Interactive OpenAPI specification schema is publicly accessible without authentication, exposing endpoint definitions and internal parameter models.',
  },
  {
    endpoint: '/docs',
    method: 'GET',
    authentication: 'Public',
    required_role: 'None',
    data_modifying: false,
    security_status: 'PUBLIC',
    observed_status: 200,
    expected_status: 401,
    finding_id: null,
    finding_ids: [],
    severity: null,
    affected_component: 'OpenAPI Documentation Route',
    security_note: 'Public interactive Swagger UI documentation interface (associated with API schema exposure).',
  },
];

export default function ApiSecurityMap({
  apiSecurityMap = null,
  findings = [],
  onSelectFinding = null,
  remediationRecord = null,
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Compute resolved route map
  const routes = useMemo(() => {
    let baseList = Array.isArray(apiSecurityMap) && apiSecurityMap.length > 0
      ? apiSecurityMap
      : DEFAULT_DEMO_ROUTES;

    // Check if remediation is verified for WG-AC-004
    const isAcRemediated =
      remediationRecord?.verification_status === 'verified' ||
      findings.some((f) => f.evidence_id === 'WG-AC-004' && f.verification_status === 'verified');

    return baseList.map((item) => {
      // If /api/admin is remediated, dynamically update its status
      if (item.endpoint === '/api/admin' && item.method === 'GET') {
        if (isAcRemediated) {
          return {
            ...item,
            security_status: 'VERIFIED',
            observed_status: 403,
            security_note: 'Remediation verified: Normal User received HTTP 403 Forbidden; Admin regression check passed (HTTP 200 OK).',
          };
        }
      }
      return item;
    });
  }, [apiSecurityMap, remediationRecord, findings]);

  // Status counts for filter pills
  const statusCounts = useMemo(() => {
    const counts = { ALL: routes.length, FINDING: 0, VERIFIED: 0, PASS: 0, PUBLIC: 0, NOT_ASSESSED: 0 };
    routes.forEach((r) => {
      const s = r.security_status || 'NOT_ASSESSED';
      if (counts[s] !== undefined) {
        counts[s] += 1;
      }
    });
    return counts;
  }, [routes]);

  // Filter routes based on search and selected filter
  const filteredRoutes = useMemo(() => {
    return routes.filter((r) => {
      const matchesStatus =
        statusFilter === 'ALL' ||
        (r.security_status || '').toUpperCase() === statusFilter.toUpperCase();

      const term = searchTerm.toLowerCase().trim();
      if (!term) return matchesStatus;

      const fIds = Array.isArray(r.finding_ids) ? r.finding_ids.join(' ') : (r.finding_id || '');
      const matchesSearch =
        (r.endpoint || '').toLowerCase().includes(term) ||
        (r.method || '').toLowerCase().includes(term) ||
        (r.required_role || '').toLowerCase().includes(term) ||
        (r.authentication || '').toLowerCase().includes(term) ||
        (r.security_status || '').toLowerCase().includes(term) ||
        (r.security_note || '').toLowerCase().includes(term) ||
        fIds.toLowerCase().includes(term);

      return matchesStatus && matchesSearch;
    });
  }, [routes, statusFilter, searchTerm]);

  // Find and open finding modal
  const handleFindingClick = (fid) => {
    if (!onSelectFinding) return;
    const cleanId = fid.trim();
    // Look up in active findings list
    const matched = findings.find(
      (f) => f.evidence_id === cleanId || f.finding_id === cleanId
    );
    if (matched) {
      onSelectFinding(matched);
    } else {
      // Synthesize basic finding details if not directly in findings array
      onSelectFinding({
        evidence_id: cleanId,
        title: cleanId === 'WG-AC-004'
          ? 'Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)'
          : cleanId === 'WG-AUTH-004'
          ? 'Public Credential Exposure on Unauthenticated Root Endpoint'
          : cleanId === 'WG-SEC-001'
          ? 'Missing Security Headers'
          : cleanId === 'WG-API-001'
          ? 'Public OpenAPI Specification & Swagger UI Exposure'
          : `Security Finding ${cleanId}`,
        severity: cleanId === 'WG-API-001' ? 'Info' : cleanId === 'WG-SEC-001' ? 'Medium' : 'High',
        endpoint: cleanId === 'WG-AC-004' ? '/api/admin' : cleanId === 'WG-API-001' ? '/openapi.json' : '/',
        method: 'GET',
        verification_status: cleanId === 'WG-AC-004' && (remediationRecord?.verification_status === 'verified') ? 'verified' : 'unverified',
      });
    }
  };

  const getStatusBadge = (status) => {
    switch (status?.toUpperCase()) {
      case 'FINDING':
        return <span className="card-badge badge-critical" style={{ letterSpacing: '0.05em' }}>● FINDING</span>;
      case 'VERIFIED':
        return <span className="card-badge badge-verified" style={{ letterSpacing: '0.05em' }}>✓ VERIFIED</span>;
      case 'PASS':
        return <span className="card-badge badge-verified" style={{ letterSpacing: '0.05em' }}>✓ PASS</span>;
      case 'PUBLIC':
        return <span className="card-badge badge-low" style={{ letterSpacing: '0.05em' }}>PUBLIC</span>;
      case 'NOT_ASSESSED':
      default:
        return (
          <span
            className="card-badge"
            style={{
              backgroundColor: 'var(--bg-inset)',
              borderColor: 'var(--border-subtle)',
              color: 'var(--text-muted)',
              letterSpacing: '0.05em',
            }}
          >
            NOT ASSESSED
          </span>
        );
    }
  };

  return (
    <div className="findings-section" style={{ marginTop: '4px' }}>
      {/* Header and Title */}
      <div className="panel-header" style={{ flexWrap: 'wrap', gap: '12px' }}>
        <div className="panel-title-group">
          <span className="panel-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2">
              <polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6" />
              <line x1="8" y1="2" x2="8" y2="18" />
              <line x1="16" y1="6" x2="16" y2="22" />
            </svg>
            API Attack Surface & Security Map
          </span>
          <span className="card-badge badge-low">{routes.length} Target Routes</span>
        </div>

        {/* Controls: Search and Status Filters */}
        <div className="table-controls" style={{ flexWrap: 'wrap' }}>
          <input
            type="text"
            className="search-input"
            placeholder="Search routes, methods, roles, notes..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ minWidth: '220px' }}
          />
          <select
            className="filter-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="ALL">All Statuses ({statusCounts.ALL})</option>
            <option value="FINDING">Findings ({statusCounts.FINDING})</option>
            <option value="VERIFIED">Verified ({statusCounts.VERIFIED})</option>
            <option value="PASS">Passed ({statusCounts.PASS})</option>
            <option value="PUBLIC">Public ({statusCounts.PUBLIC})</option>
            <option value="NOT_ASSESSED">Not Assessed ({statusCounts.NOT_ASSESSED})</option>
          </select>
        </div>
      </div>

      {/* Quick Filter Pill Buttons */}
      <div
        style={{
          display: 'flex',
          gap: '8px',
          flexWrap: 'wrap',
          alignItems: 'center',
          padding: '0 4px',
        }}
      >
        <button
          type="button"
          onClick={() => setStatusFilter('ALL')}
          style={{
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: 600,
            background: statusFilter === 'ALL' ? 'var(--color-primary-subtle)' : 'var(--bg-card)',
            border: `1px solid ${statusFilter === 'ALL' ? 'var(--color-primary-border)' : 'var(--border-subtle)'}`,
            color: statusFilter === 'ALL' ? 'var(--color-primary)' : 'var(--text-secondary)',
            cursor: 'pointer',
          }}
        >
          ALL ({statusCounts.ALL})
        </button>
        <button
          type="button"
          onClick={() => setStatusFilter('FINDING')}
          style={{
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: 600,
            background: statusFilter === 'FINDING' ? 'var(--sev-critical-bg)' : 'var(--bg-card)',
            border: `1px solid ${statusFilter === 'FINDING' ? 'var(--sev-critical-border)' : 'var(--border-subtle)'}`,
            color: statusFilter === 'FINDING' ? 'var(--sev-critical-text)' : 'var(--text-secondary)',
            cursor: 'pointer',
          }}
        >
          FINDINGS ({statusCounts.FINDING})
        </button>
        <button
          type="button"
          onClick={() => setStatusFilter('VERIFIED')}
          style={{
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: 600,
            background: statusFilter === 'VERIFIED' ? 'var(--status-verified-bg)' : 'var(--bg-card)',
            border: `1px solid ${statusFilter === 'VERIFIED' ? 'var(--status-verified-border)' : 'var(--border-subtle)'}`,
            color: statusFilter === 'VERIFIED' ? 'var(--status-verified-text)' : 'var(--text-secondary)',
            cursor: 'pointer',
          }}
        >
          VERIFIED ({statusCounts.VERIFIED})
        </button>
        <button
          type="button"
          onClick={() => setStatusFilter('PASS')}
          style={{
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: 600,
            background: statusFilter === 'PASS' ? 'var(--status-verified-bg)' : 'var(--bg-card)',
            border: `1px solid ${statusFilter === 'PASS' ? 'var(--status-verified-border)' : 'var(--border-subtle)'}`,
            color: statusFilter === 'PASS' ? 'var(--status-verified-text)' : 'var(--text-secondary)',
            cursor: 'pointer',
          }}
        >
          PASS ({statusCounts.PASS})
        </button>
        <button
          type="button"
          onClick={() => setStatusFilter('PUBLIC')}
          style={{
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: 600,
            background: statusFilter === 'PUBLIC' ? 'var(--sev-low-bg)' : 'var(--bg-card)',
            border: `1px solid ${statusFilter === 'PUBLIC' ? 'var(--sev-low-border)' : 'var(--border-subtle)'}`,
            color: statusFilter === 'PUBLIC' ? 'var(--sev-low-text)' : 'var(--text-secondary)',
            cursor: 'pointer',
          }}
        >
          PUBLIC ({statusCounts.PUBLIC})
        </button>
        <button
          type="button"
          onClick={() => setStatusFilter('NOT_ASSESSED')}
          style={{
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '0.75rem',
            fontWeight: 600,
            background: statusFilter === 'NOT_ASSESSED' ? 'var(--bg-inset)' : 'var(--bg-card)',
            border: `1px solid ${statusFilter === 'NOT_ASSESSED' ? 'var(--border-strong)' : 'var(--border-subtle)'}`,
            color: statusFilter === 'NOT_ASSESSED' ? 'var(--text-primary)' : 'var(--text-secondary)',
            cursor: 'pointer',
          }}
        >
          NOT ASSESSED ({statusCounts.NOT_ASSESSED})
        </button>
      </div>

      {/* Table Content */}
      {filteredRoutes.length === 0 ? (
        <div className="empty-state">
          <svg className="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="12" cy="12" r="10" />
            <path d="M8 12h8" />
          </svg>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>No endpoints match your filter</div>
          <div style={{ fontSize: '0.8rem' }}>Adjust your search query or status filter to see target endpoints.</div>
        </div>
      ) : (
        <div className="table-responsive">
          <table className="findings-table">
            <thead>
              <tr>
                <th style={{ width: '85px' }}>Method</th>
                <th style={{ width: '180px' }}>Endpoint Path</th>
                <th style={{ width: '130px' }}>Authentication</th>
                <th style={{ width: '170px' }}>Required Role</th>
                <th style={{ width: '120px' }}>Telemetry</th>
                <th style={{ width: '130px' }}>Security Posture</th>
                <th style={{ width: '150px' }}>Linked Finding</th>
                <th>Security Analysis & Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredRoutes.map((route, idx) => {
                const fIds = Array.isArray(route.finding_ids) && route.finding_ids.length > 0
                  ? route.finding_ids
                  : route.finding_id
                  ? route.finding_id.split(',').map((s) => s.trim())
                  : [];

                const isMethodPost = route.method === 'POST';

                return (
                  <tr key={`${route.method}-${route.endpoint}-${idx}`}>
                    {/* Method */}
                    <td>
                      <span
                        className="font-mono"
                        style={{
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '4px',
                          background: isMethodPost ? 'var(--sev-high-bg)' : 'var(--sev-low-bg)',
                          color: isMethodPost ? 'var(--sev-high-text)' : 'var(--sev-low-text)',
                          border: `1px solid ${isMethodPost ? 'var(--sev-high-border)' : 'var(--sev-low-border)'}`,
                          display: 'inline-block',
                        }}
                      >
                        {route.method}
                      </span>
                    </td>

                    {/* Endpoint */}
                    <td>
                      <span
                        className="font-mono"
                        style={{
                          fontSize: '0.82rem',
                          fontWeight: 600,
                          color: 'var(--text-primary)',
                        }}
                      >
                        {route.endpoint}
                      </span>
                    </td>

                    {/* Authentication */}
                    <td>
                      <span
                        style={{
                          fontSize: '0.8rem',
                          fontWeight: 500,
                          color: route.authentication === 'Required' ? 'var(--color-primary)' : 'var(--text-secondary)',
                        }}
                      >
                        {route.authentication}
                      </span>
                    </td>

                    {/* Required Role */}
                    <td>
                      <span
                        className="cwe-tag"
                        style={{
                          color: route.required_role === 'None' ? 'var(--text-muted)' : 'var(--text-primary)',
                          fontSize: '0.75rem',
                        }}
                      >
                        {route.required_role}
                      </span>
                    </td>

                    {/* Telemetry (Observed / Expected) */}
                    <td>
                      {route.observed_status ? (
                        <div style={{ fontSize: '0.75rem', lineHeight: '1.4' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Obs: </span>
                          <span
                            className="font-mono"
                            style={{
                              color:
                                route.observed_status === route.expected_status
                                  ? 'var(--status-verified)'
                                  : route.security_status === 'FINDING'
                                  ? 'var(--sev-critical)'
                                  : 'var(--color-primary)',
                              fontWeight: 600,
                            }}
                          >
                            HTTP {route.observed_status}
                          </span>
                          {route.expected_status && route.observed_status !== route.expected_status && (
                            <div>
                              <span style={{ color: 'var(--text-muted)' }}>Exp: </span>
                              <span className="font-mono" style={{ color: 'var(--text-muted)' }}>
                                HTTP {route.expected_status}
                              </span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>

                    {/* Security Status */}
                    <td>{getStatusBadge(route.security_status)}</td>

                    {/* Linked Finding */}
                    <td>
                      {fIds.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          {fIds.map((fid) => (
                            <button
                              key={fid}
                              type="button"
                              onClick={() => handleFindingClick(fid)}
                              className="font-mono"
                              style={{
                                fontSize: '0.75rem',
                                fontWeight: 700,
                                padding: '2px 8px',
                                borderRadius: '4px',
                                background: route.security_status === 'VERIFIED'
                                  ? 'var(--status-verified-bg)'
                                  : 'var(--sev-critical-bg)',
                                color: route.security_status === 'VERIFIED'
                                  ? 'var(--status-verified-text)'
                                  : 'var(--sev-critical-text)',
                                border: `1px solid ${
                                  route.security_status === 'VERIFIED'
                                    ? 'var(--status-verified-border)'
                                    : 'var(--sev-critical-border)'
                                }`,
                                cursor: 'pointer',
                                textAlign: 'left',
                                display: 'inline-block',
                                width: 'fit-content',
                              }}
                              title="Click to view detailed reproduction and proof-of-concept"
                            >
                              🔍 {fid}
                            </button>
                          ))}
                        </div>
                      ) : (
                        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>

                    {/* Security Note */}
                    <td>
                      <div
                        style={{
                          fontSize: '0.78rem',
                          color: 'var(--text-secondary)',
                          lineHeight: '1.4',
                          maxWidth: '420px',
                        }}
                      >
                        {route.security_note}
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
