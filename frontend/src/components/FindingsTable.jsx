import React, { useState } from 'react';

export default function FindingsTable({
  findings = [],
  onSelectFinding,
  selectedFindingId = null,
  remediationRecord = null,
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      (f.title || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.evidence_id || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.cwe_id || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.endpoint || '').toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity =
      severityFilter === 'ALL' ||
      (f.severity || '').toUpperCase() === severityFilter.toUpperCase();

    return matchesSearch && matchesSeverity;
  });

  const getSeverityBadge = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <span className="card-badge badge-critical">CRITICAL</span>;
      case 'high':
        return <span className="card-badge badge-high">HIGH</span>;
      case 'medium':
        return <span className="card-badge badge-medium">MEDIUM</span>;
      case 'low':
        return <span className="card-badge badge-low">LOW</span>;
      default:
        return <span className="card-badge badge-low">{severity || 'INFO'}</span>;
    }
  };

  const getStatusBadge = (finding) => {
    // If WG-AC-004 and remediationRecord is verified, mark Verified
    if (finding.evidence_id === 'WG-AC-004' && remediationRecord?.verification_status === 'verified') {
      return <span className="card-badge badge-verified">✓ VERIFIED</span>;
    }
    if (finding.verification_status === 'verified') {
      return <span className="card-badge badge-verified">✓ VERIFIED</span>;
    }
    return <span className="card-badge badge-critical">VULNERABLE</span>;
  };

  return (
    <div className="findings-section">
      <div className="panel-header">
        <div className="panel-title-group">
          <span className="panel-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
              <polyline points="10 9 9 9 8 9" />
            </svg>
            Security Findings & Vulnerability Matrix
          </span>
          <span className="card-badge badge-low">{findings.length} Discovered</span>
        </div>

        <div className="table-controls">
          <input
            type="text"
            className="search-input"
            placeholder="Search by ID, title, CWE, or endpoint..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          <select
            className="filter-select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {filteredFindings.length === 0 ? (
        <div className="empty-state">
          <svg className="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="12" cy="12" r="10" />
            <path d="M8 12h8" />
          </svg>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>No security findings match your criteria</div>
          <div style={{ fontSize: '0.8rem' }}>Run a demo assessment to populate findings from the local target application.</div>
        </div>
      ) : (
        <div className="table-responsive">
          <table className="findings-table">
            <thead>
              <tr>
                <th>ID / Evidence</th>
                <th>Vulnerability Title</th>
                <th>Severity</th>
                <th>Category</th>
                <th>CWE / OWASP</th>
                <th>Affected Role</th>
                <th>Endpoint</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map((finding, idx) => {
                const isSelected = selectedFindingId === (finding.evidence_id || idx);
                const priorityClass =
                  (finding.remediation_priority || 'High').toLowerCase() === 'high'
                    ? 'badge-high'
                    : (finding.remediation_priority || '').toLowerCase() === 'medium'
                    ? 'badge-medium'
                    : 'badge-low';

                return (
                  <tr
                    key={finding.evidence_id || idx}
                    className={isSelected ? 'finding-row-selected' : ''}
                  >
                    <td>
                      <span className="font-mono" style={{ color: 'var(--color-primary)', fontWeight: 600 }}>
                        {finding.evidence_id || `WG-FIND-${idx + 1}`}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', maxWidth: '300px' }}>
                        {finding.title}
                      </div>
                    </td>
                    <td>{getSeverityBadge(finding.severity)}</td>
                    <td>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        {finding.category || 'Access Control'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                        {finding.cwe_id && <span className="cwe-tag">{finding.cwe_id}</span>}
                        {finding.owasp_category && (
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                            {finding.owasp_category}
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="cwe-tag" style={{ color: 'var(--text-primary)' }}>
                        {finding.affected_role || finding.tested_role || 'Normal User'}
                      </span>
                    </td>
                    <td>
                      <span className="font-mono" style={{ fontSize: '0.78rem', color: 'var(--text-primary)' }}>
                        {finding.method ? `${finding.method} ` : ''}
                        {finding.endpoint || '/api/admin'}
                      </span>
                    </td>
                    <td>
                      <span className={`card-badge ${priorityClass}`} style={{ fontSize: '0.7rem' }}>
                        {finding.remediation_priority || 'High'}
                      </span>
                    </td>
                    <td>{getStatusBadge(finding)}</td>
                    <td>
                      <button
                        type="button"
                        className="btn-table-action"
                        onClick={() => onSelectFinding(finding)}
                      >
                        Inspect Details
                      </button>
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
