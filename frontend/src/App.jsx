import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import SummaryCards from './components/SummaryCards';
import RiskOverview from './components/RiskOverview';
import BeforeAfterVerification from './components/BeforeAfterVerification';
import AISecurityBrief from './components/AISecurityBrief';
import FindingsTable from './components/FindingsTable';
import FindingDetails from './components/FindingDetails';
import ApiSecurityMap from './components/ApiSecurityMap';
import EvidenceTimeline from './components/EvidenceTimeline';
import RemediationModal from './components/RemediationModal';
import AssessmentHistory from './components/AssessmentHistory';
import {
  checkBackendHealth,
  fetchAssessmentHistory,
  fetchAssessmentDetails,
  fetchAssessmentAISummary,
  fetchAssessmentTimeline,
  triggerDemoAssessment,
  applyRemediationVerification,
  downloadReportFile,
} from './api/worldguardApi';

export default function App() {
  const [isBackendOnline, setIsBackendOnline] = useState(false);
  const [isAssessing, setIsAssessing] = useState(false);
  const [isRemediating, setIsRemediating] = useState(false);
  const [isRemediationModalOpen, setIsRemediationModalOpen] = useState(false);

  const [activeAssessment, setActiveAssessment] = useState(null);
  const [aiSummary, setAiSummary] = useState(null);
  const [isLoadingAISummary, setIsLoadingAISummary] = useState(false);
  const [remediationRecord, setRemediationRecord] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [scansHistory, setScansHistory] = useState([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [notification, setNotification] = useState(null);

  const [timeline, setTimeline] = useState([]);
  const [timelineFinalState, setTimelineFinalState] = useState('AWAITING_REMEDIATION');
  const [isLoadingTimeline, setIsLoadingTimeline] = useState(false);

  // Clear notification helper
  const showNotification = useCallback((type, text) => {
    setNotification({ type, text });
    setTimeout(() => {
      setNotification((prev) => (prev?.text === text ? null : prev));
    }, 6000);
  }, []);

  // Sync timeline when activeAssessment or remediationRecord changes
  useEffect(() => {
    if (activeAssessment?.timeline && activeAssessment.timeline.length > 0) {
      setTimeline(activeAssessment.timeline);
      setTimelineFinalState(
        activeAssessment.final_state ||
        (remediationRecord?.verification_status === 'verified' ? 'REMEDIATION_VERIFIED' : 'AWAITING_REMEDIATION')
      );
    } else {
      const aId = activeAssessment?.id || activeAssessment?.assessment_id;
      if (aId) {
        setIsLoadingTimeline(true);
        fetchAssessmentTimeline(aId)
          .then((res) => {
            setTimeline(res.timeline || []);
            setTimelineFinalState(res.final_state || 'AWAITING_REMEDIATION');
          })
          .catch((err) => {
            console.warn('Failed to load timeline:', err);
          })
          .finally(() => {
            setIsLoadingTimeline(false);
          });
      } else {
        setTimeline([]);
        setTimelineFinalState('AWAITING_REMEDIATION');
      }
    }
  }, [activeAssessment, remediationRecord]);

  // Poll / check health
  const checkHealth = useCallback(async () => {
    try {
      await checkBackendHealth();
      setIsBackendOnline(true);
    } catch {
      setIsBackendOnline(false);
    }
  }, []);

  // Fetch scan history
  const loadHistory = useCallback(async () => {
    setIsLoadingHistory(true);
    try {
      const history = await fetchAssessmentHistory(50);
      setScansHistory(Array.isArray(history) ? history : []);
    } catch (err) {
      console.warn('Failed to load scan history:', err);
    } finally {
      setIsLoadingHistory(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    checkHealth();
    loadHistory();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, [checkHealth, loadHistory]);

  // Load a specific historical assessment record
  const handleSelectScan = async (scanId) => {
    try {
      const data = await fetchAssessmentDetails(scanId);
      setActiveAssessment(data);

      // Check if this record is a remediation verification
      const raw = data.raw_results || {};
      if (raw.record_type === 'remediation_verification' && raw.remediation_result) {
        setRemediationRecord(raw.remediation_result);
      } else {
        // If it's a standard demo assessment, check if any finding was verified
        const hasVerifiedFinding = data.findings?.some((f) => f.verification_status === 'verified');
        if (!hasVerifiedFinding) {
          setRemediationRecord(null);
        }
      }

      // Check for persisted AI summary
      if (raw.ai_summary) {
        setAiSummary(raw.ai_summary);
      } else if (data.ai_summary) {
        setAiSummary(data.ai_summary);
      } else {
        setAiSummary(null);
      }

      showNotification('info', `Loaded assessment record #${scanId} for target ${data.target}`);
    } catch (err) {
      showNotification('error', `Failed to load record #${scanId}: ${err.message}`);
    }
  };

  // Run the authorized demo assessment (POST /assessment/demo)
  const handleRunAssessment = async () => {
    setIsAssessing(true);
    setNotification(null);
    try {
      const result = await triggerDemoAssessment('http://127.0.0.1:8001');
      setActiveAssessment(result);
      setAiSummary(result.ai_summary || null);

      // If the newly returned assessment has active findings (WG-AC-004), reset verified state
      const hasActiveVulnerability = result.findings?.some(
        (f) => f.evidence_id === 'WG-AC-004' && f.severity === 'High'
      );
      if (hasActiveVulnerability) {
        setRemediationRecord(null);
      }

      showNotification(
        'success',
        `Security assessment completed against http://127.0.0.1:8001. ${result.tests_run || 7} tests executed, ${result.findings?.length || 0} finding(s) discovered.`
      );
      loadHistory();
    } catch (err) {
      showNotification('error', `Assessment failed: ${err.message}`);
    } finally {
      setIsAssessing(false);
    }
  };

  // Generate or refresh AI assessment summary
  const handleGenerateAISummary = async () => {
    const assessmentId = activeAssessment?.id || activeAssessment?.assessment_id;
    if (!assessmentId) {
      showNotification('error', 'No active assessment record selected.');
      return;
    }
    setIsLoadingAISummary(true);
    try {
      const summary = await fetchAssessmentAISummary(assessmentId);
      setAiSummary(summary);
      showNotification('success', 'AI security brief generated.');
    } catch (err) {
      showNotification('error', `Failed to generate AI summary: ${err.message}`);
    } finally {
      setIsLoadingAISummary(false);
    }
  };


  // Run the remediation verification workflow (POST /remediation/demo/apply)
  const handleConfirmRemediation = async () => {
    setIsRemediating(true);
    try {
      const currentAssessmentId = activeAssessment?.id || activeAssessment?.assessment_id || null;
      const result = await applyRemediationVerification('WG-AC-004', 'http://127.0.0.1:8001', currentAssessmentId);
      setRemediationRecord(result);
      setIsRemediationModalOpen(false);

      if (result.verification_status === 'verified') {
        showNotification(
          'success',
          'Remediation verified! Normal User received HTTP 403 Forbidden and Admin legitimate access confirmed intact (HTTP 200).'
        );

        // Update active assessment state to reflect verified finding
        if (activeAssessment) {
          const updatedFindings = (activeAssessment.findings || []).map((f) => {
            if (f.evidence_id === 'WG-AC-004') {
              return {
                ...f,
                verification_status: 'verified',
                observed_status: 403,
              };
            }
            return f;
          });

          setActiveAssessment({
            ...activeAssessment,
            findings: updatedFindings,
          });
        }
      } else if (result.verification_status === 'precondition_failed') {
        showNotification(
          'info',
          'Precondition note: Target was already secured (HTTP 403). No fix was applied.'
        );
      } else {
        showNotification('error', `Remediation verification failed: ${result.message}`);
      }

      if (currentAssessmentId) {
        try {
          const tRes = await fetchAssessmentTimeline(currentAssessmentId);
          if (tRes?.timeline) {
            setTimeline(tRes.timeline);
            setTimelineFinalState(tRes.final_state || 'REMEDIATION_VERIFIED');
          }
        } catch {
          // ignore
        }
      }

      loadHistory();
    } catch (err) {
      showNotification('error', `Remediation error: ${err.message}`);
    } finally {
      setIsRemediating(false);
    }
  };

  // Derived dashboard metrics
  const findings = activeAssessment?.findings || [];
  const evidenceList = activeAssessment?.evidence || [];
  const riskSummary = activeAssessment?.risk_summary || {
    risk_level: findings.length > 0 ? (remediationRecord?.verification_status === 'verified' ? 'Low' : 'High') : 'Low',
    total_findings: findings.length,
    severity_counts: { Critical: 0, High: findings.length, Medium: 0, Low: 0, Info: 0 },
  };

  const isVerified = remediationRecord?.verification_status === 'verified';
  const verifiedFixesCount = isVerified ? 1 : 0;
  const activeFindingsCount = isVerified ? Math.max(0, findings.length - 1) : findings.length;

  const adjustedSeverityCounts = {
    Critical: riskSummary.severity_counts?.Critical || 0,
    High: isVerified ? Math.max(0, (riskSummary.severity_counts?.High || 0) - 1) : riskSummary.severity_counts?.High || 0,
    Medium: riskSummary.severity_counts?.Medium || 0,
    Low: riskSummary.severity_counts?.Low || 0,
    Info: riskSummary.severity_counts?.Info || 0,
  };

  const adjustedRiskLevel =
    adjustedSeverityCounts.Critical > 0
      ? 'Critical'
      : adjustedSeverityCounts.High > 0
      ? 'High'
      : adjustedSeverityCounts.Medium > 0
      ? 'Medium'
      : adjustedSeverityCounts.Low > 0
      ? 'Low'
      : 'Low';

  const hasVulnerableFinding = findings.some(
    (f) => f.evidence_id === 'WG-AC-004' && !isVerified
  );

  const handleExportJson = (assessmentId) => {
    const id = assessmentId || activeAssessment?.id || activeAssessment?.assessment_id;
    if (!id) {
      showNotification('error', 'No assessment record selected to export.');
      return;
    }
    downloadReportFile(id, 'json');
    showNotification('info', `Exporting JSON security audit report for record #${id}...`);
  };

  const handleExportPdf = (assessmentId) => {
    const id = assessmentId || activeAssessment?.id || activeAssessment?.assessment_id;
    if (!id) {
      showNotification('error', 'No assessment record selected to export.');
      return;
    }
    downloadReportFile(id, 'pdf');
    showNotification('info', `Generating SIH defense-grade PDF audit report for record #${id}...`);
  };

  return (
    <div className="app-container">
      <Header
        isBackendOnline={isBackendOnline}
        isAssessing={isAssessing}
        onRunAssessment={handleRunAssessment}
        targetUrl="http://127.0.0.1:8001"
        activeAssessmentId={activeAssessment?.id || activeAssessment?.assessment_id}
        onExportJson={() => handleExportJson()}
        onExportPdf={() => handleExportPdf()}
      />

      <main className="dashboard-content">
        {/* Notification Banner */}
        {notification && (
          <div
            className={`notification-banner ${
              notification.type === 'success'
                ? 'banner-success'
                : notification.type === 'error'
                ? 'banner-error'
                : 'banner-info'
            }`}
          >
            <span>{notification.text}</span>
            <button
              type="button"
              onClick={() => setNotification(null)}
              style={{ color: 'inherit', fontWeight: 'bold' }}
            >
              ✕
            </button>
          </div>
        )}

        {/* Top Summary Cards */}
        <SummaryCards
          totalFindings={activeFindingsCount}
          severityCounts={adjustedSeverityCounts}
          verifiedFixesCount={verifiedFixesCount}
        />

        {/* Hero Section: Risk Overview + Before/After Verification Stepper */}
        <div className="hero-split-grid">
          <RiskOverview
            riskLevel={adjustedRiskLevel}
            totalFindings={activeFindingsCount}
            severityCounts={adjustedSeverityCounts}
            verifiedFixesCount={verifiedFixesCount}
            testsRun={activeAssessment?.tests_run || 12}
          />

          <BeforeAfterVerification
            remediationRecord={remediationRecord}
            isRemediating={isRemediating}
            onOpenRemediationModal={() => setIsRemediationModalOpen(true)}
            hasVulnerableFinding={hasVulnerableFinding}
          />
        </div>

        {/* WorldGuard AI Security Brief Panel */}
        <AISecurityBrief
          aiSummary={aiSummary}
          isLoading={isLoadingAISummary}
          onGenerateSummary={handleGenerateAISummary}
          hasActiveAssessment={Boolean(activeAssessment)}
        />

        {/* Security Findings Matrix */}
        <FindingsTable
          findings={findings}
          selectedFindingId={selectedFinding?.evidence_id}
          onSelectFinding={(f) => setSelectedFinding(f)}
          remediationRecord={remediationRecord}
        />

        {/* API Attack Surface & Security Map */}
        <ApiSecurityMap
          apiSecurityMap={activeAssessment?.api_security_map}
          findings={findings}
          onSelectFinding={(f) => setSelectedFinding(f)}
          remediationRecord={remediationRecord}
        />

        {/* Evidence Timeline & Audit Trail */}
        <EvidenceTimeline
          timeline={timeline}
          finalState={timelineFinalState}
          onSelectFinding={(f) => setSelectedFinding(f)}
          isLoading={isLoadingTimeline}
        />

        {/* Assessment & Retest History */}
        <AssessmentHistory
          scans={scansHistory}
          selectedScanId={activeAssessment?.id || activeAssessment?.assessment_id}
          onSelectScan={handleSelectScan}
          isLoadingHistory={isLoadingHistory}
          onExportJson={(id) => handleExportJson(id)}
          onExportPdf={(id) => handleExportPdf(id)}
        />
      </main>

      {/* Finding Details Modal */}
      {selectedFinding && (
        <FindingDetails
          finding={selectedFinding}
          evidenceList={evidenceList}
          remediationRecord={remediationRecord}
          onClose={() => setSelectedFinding(null)}
          onOpenRemediationModal={() => {
            setSelectedFinding(null);
            setIsRemediationModalOpen(true);
          }}
          isRemediating={isRemediating}
        />
      )}

      {/* Remediation Confirmation Dialog */}
      <RemediationModal
        isOpen={isRemediationModalOpen}
        onClose={() => setIsRemediationModalOpen(false)}
        onConfirmRemediation={handleConfirmRemediation}
        isRemediating={isRemediating}
        findingId="WG-AC-004"
      />
    </div>
  );
}
