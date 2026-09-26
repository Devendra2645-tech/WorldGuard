import React, { useState, useMemo } from 'react';

/**
 * EvidenceTimeline component
 * Renders a deterministic, chronological audit trail tracing the assessment lifecycle:
 * Execution -> Tests -> Evidence -> Findings -> Risk -> Remediation -> Retest -> Verification.
 * Strictly adheres to zero-credential-leakage and honest timestamp reporting.
 */
export default function EvidenceTimeline({
  timeline = [],
  finalState = 'AWAITING_REMEDIATION',
  onSelectFinding = null,
  isLoading = false,
}) {
  const [filterType, setFilterType] = useState('ALL');
  const [highOnly, setHighOnly] = useState(false);
  const [sortOrder, setSortOrder] = useState('asc'); // 'asc' = oldest first (narrative), 'desc' = newest first
  const [expandedEvents, setExpandedEvents] = useState({});

  // Toggle single event expansion
  const toggleExpand = (eventId) => {
    setExpandedEvents((prev) => ({
      ...prev,
      [eventId]: !prev[eventId],
    }));
  };

  // Expand / collapse all
  const toggleExpandAll = () => {
    if (Object.keys(expandedEvents).length === timeline.length) {
      setExpandedEvents({});
    } else {
      const all = {};
      timeline.forEach((e) => {
        all[e.event_id] = true;
      });
      setExpandedEvents(all);
    }
  };

  // Filtered & sorted timeline
  const processedTimeline = useMemo(() => {
    if (!Array.isArray(timeline)) return [];

    let filtered = timeline.filter((item) => {
      // Category filter
      if (filterType === 'FINDINGS') {
        if (item.event_type !== 'FINDING_DETECTED') return false;
      } else if (filterType === 'REMEDIATION') {
        if (!['REMEDIATION_STARTED', 'REMEDIATION_APPLIED', 'RETEST_EXECUTED', 'REGRESSION_CHECKED', 'VERIFICATION_COMPLETED'].includes(item.event_type)) {
          return false;
        }
      } else if (filterType === 'VERIFICATION') {
        if (!['RETEST_EXECUTED', 'REGRESSION_CHECKED', 'VERIFICATION_COMPLETED'].includes(item.event_type)) {
          return false;
        }
      }

      // Severity filter
      if (highOnly) {
        const sev = (item.severity || '').toLowerCase();
        if (sev !== 'high' && sev !== 'critical') return false;
      }

      return true;
    });

    if (sortOrder === 'desc') {
      return [...filtered].reverse();
    }
    return filtered;
  }, [timeline, filterType, highOnly, sortOrder]);

  // Counts for filter pills
  const counts = useMemo(() => {
    if (!Array.isArray(timeline)) return { all: 0, findings: 0, remediation: 0, verification: 0 };
    return {
      all: timeline.length,
      findings: timeline.filter((e) => e.event_type === 'FINDING_DETECTED').length,
      remediation: timeline.filter((e) => ['REMEDIATION_STARTED', 'REMEDIATION_APPLIED', 'RETEST_EXECUTED', 'REGRESSION_CHECKED', 'VERIFICATION_COMPLETED'].includes(e.event_type)).length,
      verification: timeline.filter((e) => ['RETEST_EXECUTED', 'REGRESSION_CHECKED', 'VERIFICATION_COMPLETED'].includes(e.event_type)).length,
    };
  }, [timeline]);

  // Status helper styles
  const getStatusBadge = (status) => {
    switch (status) {
      case 'PASS':
        return <span className="timeline-badge badge-pass">PASS</span>;
      case 'FAIL':
        return <span className="timeline-badge badge-fail">FAIL</span>;
      case 'VERIFIED':
        return <span className="timeline-badge badge-verified">VERIFIED</span>;
      case 'COMPLETED':
        return <span className="timeline-badge badge-completed">COMPLETED</span>;
      default:
        return <span className="timeline-badge badge-info">{status || 'INFO'}</span>;
    }
  };

  const getSeverityBadge = (severity) => {
    if (!severity) return null;
    const s = severity.toLowerCase();
    let badgeClass = 'badge-low';
    if (s === 'critical') badgeClass = 'badge-critical';
    else if (s === 'high') badgeClass = 'badge-high';
    else if (s === 'medium') badgeClass = 'badge-medium';
    else if (s === 'info') badgeClass = 'badge-info';

    return <span className={`card-badge ${badgeClass}`} style={{ fontSize: '0.72rem', padding: '2px 8px' }}>{severity}</span>;
  };

  const getNodeIcon = (eventType, status) => {
    if (eventType === 'ASSESSMENT_EXECUTION_STARTED') {
      return (
        <span className="node-icon node-start" title="Assessment Started">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor">
            <polygon points="5 3 19 12 5 21 5 3" />
          </svg>
        </span>
      );
    }
    if (status === 'FAIL' || eventType === 'FINDING_DETECTED') {
      return (
        <span className="node-icon node-fail" title="Vulnerability Finding Detected">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        </span>
      );
    }
    if (status === 'VERIFIED' || eventType === 'VERIFICATION_COMPLETED') {
      return (
        <span className="node-icon node-verified" title="Remediation Verified">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
            <polyline points="20 6 9 17 4 12" />
          </svg>
        </span>
      );
    }
    if (status === 'PASS') {
      return (
        <span className="node-icon node-pass" title="Check Passed">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <polyline points="20 6 9 17 4 12" />
          </svg>
        </span>
      );
    }
    return (
      <span className="node-icon node-info" title="Lifecycle Event">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor">
          <circle cx="12" cy="12" r="6" />
        </svg>
      </span>
    );
  };

  return (
    <div className="panel-card timeline-card" style={{ marginBottom: '24px' }}>
      {/* Panel Header */}
      <div className="panel-header" style={{ flexWrap: 'wrap', gap: '12px' }}>
        <div className="panel-title-group">
          <span className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--color-primary)" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            Evidence Timeline & Audit Trail
          </span>
          <span className="cwe-tag" style={{ background: 'var(--color-primary-subtle)', color: 'var(--color-primary)', borderColor: 'var(--color-primary-border)' }}>
            Deterministic Chronology ({processedTimeline.length} Events)
          </span>
        </div>

        {/* Final Security State Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: '500' }}>Final Security State:</span>
          {finalState === 'REMEDIATION_VERIFIED' ? (
            <span className="card-badge badge-verified" style={{ padding: '4px 12px', fontSize: '0.82rem', fontWeight: 'bold' }}>
              ✓ REMEDIATION VERIFIED
            </span>
          ) : finalState === 'REMEDIATION_FAILED' ? (
            <span className="card-badge badge-critical" style={{ padding: '4px 12px', fontSize: '0.82rem', fontWeight: 'bold' }}>
              ✗ REMEDIATION FAILED
            </span>
          ) : (
            <span className="card-badge badge-medium" style={{ padding: '4px 12px', fontSize: '0.82rem', fontWeight: 'bold' }}>
              ⏳ AWAITING REMEDIATION
            </span>
          )}
        </div>
      </div>

      {/* Filter and Control Bar */}
      <div className="timeline-filter-bar">
        <div className="timeline-filters">
          <button
            type="button"
            className={`btn-filter ${filterType === 'ALL' ? 'active' : ''}`}
            onClick={() => setFilterType('ALL')}
          >
            All Events ({counts.all})
          </button>
          <button
            type="button"
            className={`btn-filter ${filterType === 'FINDINGS' ? 'active' : ''}`}
            onClick={() => setFilterType('FINDINGS')}
          >
            Findings ({counts.findings})
          </button>
          <button
            type="button"
            className={`btn-filter ${filterType === 'REMEDIATION' ? 'active' : ''}`}
            onClick={() => setFilterType('REMEDIATION')}
          >
            Remediation ({counts.remediation})
          </button>
          <button
            type="button"
            className={`btn-filter ${filterType === 'VERIFICATION' ? 'active' : ''}`}
            onClick={() => setFilterType('VERIFICATION')}
          >
            Verification ({counts.verification})
          </button>
        </div>

        <div className="timeline-controls" style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={highOnly}
              onChange={(e) => setHighOnly(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            High / Critical Only
          </label>

          <button
            type="button"
            className="btn-text-action"
            onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
            title="Toggle chronological order"
          >
            {sortOrder === 'asc' ? 'Oldest First ↓' : 'Newest First ↑'}
          </button>

          <button
            type="button"
            className="btn-text-action"
            onClick={toggleExpandAll}
            title="Expand or collapse all event details"
          >
            {Object.keys(expandedEvents).length === processedTimeline.length && processedTimeline.length > 0
              ? 'Collapse All'
              : 'Expand All'}
          </button>
        </div>
      </div>

      {/* Timeline Stream Container */}
      <div className="timeline-container">
        {isLoading ? (
          <div style={{ textAlign: 'center', padding: '40px', color: '#94a3b8' }}>
            <span className="spinner" style={{ marginRight: '8px' }} />
            Loading assessment audit trail...
          </div>
        ) : processedTimeline.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: '#64748b' }}>
            No timeline events match the selected criteria.
          </div>
        ) : (
          <div className="timeline-track">
            {processedTimeline.map((item) => {
              const isExpanded = Boolean(expandedEvents[item.event_id]);
              const rawTs = item.timestamp || '';
              const timeDisplay = rawTs.length >= 19 ? rawTs.substring(11, 23) : rawTs;
              const dateDisplay = rawTs.length >= 10 ? rawTs.substring(0, 10) : '';

              return (
                <div key={item.event_id} className={`timeline-entry ${item.status === 'FAIL' ? 'entry-fail' : ''} ${item.status === 'VERIFIED' ? 'entry-verified' : ''}`}>
                  {/* Left Column: Timestamp */}
                  <div className="timeline-time-col">
                    <span className="time-primary">
                      {timeDisplay}
                      {!item.timestamp_exact && <span className="time-approx-star" title="Derived/linked timestamp; exact event start/analysis time is not separately persisted.">*</span>}
                    </span>
                    <span className="time-secondary">{dateDisplay}</span>
                    <span className="event-id-tag">{item.event_id}</span>
                  </div>

                  {/* Center Node Indicator */}
                  <div className="timeline-node-col">
                    {getNodeIcon(item.event_type, item.status)}
                    <div className="timeline-vertical-line" />
                  </div>

                  {/* Right Column: Event Content Card */}
                  <div className="timeline-content-card">
                    <div className="timeline-card-header" onClick={() => toggleExpand(item.event_id)}>
                      <div className="timeline-title-row">
                        <span className="event-type-badge">{item.event_type.replace(/_/g, ' ')}</span>
                        <h4 className="event-title">{item.title}</h4>
                        {getSeverityBadge(item.severity)}
                        {getStatusBadge(item.status)}
                      </div>

                      <div className="timeline-meta-tags">
                        {item.method && item.endpoint && (
                          <span className="meta-tag tag-endpoint">
                            <code>{item.method} {item.endpoint}</code>
                          </span>
                        )}
                        {item.role && (
                          <span className="meta-tag tag-role">
                            Role: <b>{item.role}</b>
                          </span>
                        )}
                        {item.evidence_id && (
                          <span className="meta-tag tag-id">
                            Ref: <code>{item.evidence_id}</code>
                          </span>
                        )}
                        {item.finding_id && onSelectFinding && (
                          <button
                            type="button"
                            className="meta-tag tag-finding-link"
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectFinding({ evidence_id: item.finding_id });
                            }}
                            title="Inspect detailed finding dossier & safe PoC"
                          >
                            Finding: <b>{item.finding_id}</b> ↗
                          </button>
                        )}
                        <span className="expand-indicator">
                          {isExpanded ? '▲' : '▼'}
                        </span>
                      </div>
                    </div>

                    {/* Summary Description */}
                    <p className="timeline-description">{item.description}</p>

                    {/* Expandable Details Drawer */}
                    {isExpanded && (
                      <div className="timeline-drawer">
                        <div className="drawer-grid">
                          {item.expected_status !== null && (
                            <div className="drawer-item">
                              <span className="drawer-label">Expected Status:</span>
                              <span className="drawer-value"><code>HTTP {item.expected_status}</code></span>
                            </div>
                          )}
                          {item.observed_status !== null && (
                            <div className="drawer-item">
                              <span className="drawer-label">Observed Status:</span>
                              <span className={`drawer-value ${item.observed_status === item.expected_status ? 'text-success' : 'text-danger'}`}>
                                <code>HTTP {item.observed_status}</code>
                              </span>
                            </div>
                          )}
                          <div className="drawer-item">
                            <span className="drawer-label">Lifecycle Phase:</span>
                            <span className="drawer-value">{item.phase || 'Security Assessment'}</span>
                          </div>
                          <div className="drawer-item">
                            <span className="drawer-label">Timestamp Source:</span>
                            <span className="drawer-value">
                              <code>{item.timestamp_source}</code>
                              {item.timestamp_exact ? ' (Exact)' : ' (Derived / Linked)'}
                            </span>
                          </div>
                        </div>

                        {item.finding_id && onSelectFinding && (
                          <div style={{ marginTop: '10px', textAlign: 'right' }}>
                            <button
                              type="button"
                              className="btn-text-link"
                              onClick={() => onSelectFinding({ evidence_id: item.finding_id })}
                            >
                              Open Finding Details & Reproduction Steps →
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer Timestamp Disclaimer */}
      <div style={{ padding: '8px 16px', background: 'var(--bg-subtle)', borderTop: '1px solid var(--border-subtle)', borderRadius: '0 0 8px 8px', fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
        <span>
          <i>* Denotes derived/linked timestamp (e.g. linked evidence or final test execution); exact event start/analysis time is not separately persisted.</i>
        </span>
        <span>
          Zero secrets, tokens, or raw Authorization headers exposed in audit log.
        </span>
      </div>
    </div>
  );
}
