/**
 * WorldGuard Security Assessment Platform - Frontend API Client
 * Connects to the defensive FastAPI backend (default: http://127.0.0.1:8000).
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
const DEFAULT_TIMEOUT_MS = 15000;

class ApiError extends Error {
  constructor(message, status = 0, detail = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Internal fetch wrapper with timeout, CORS, and standardized error handling.
 */
async function request(endpoint, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const url = `${API_BASE_URL}${endpoint}`;
  const config = {
    ...options,
    signal: controller.signal,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(options.headers || {}),
    },
  };

  try {
    const response = await fetch(url, config);
    clearTimeout(timer);

    let data;
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      data = await response.json();
    } else {
      const text = await response.text();
      data = { raw: text };
    }

    if (!response.ok) {
      const errorMsg = data?.detail || data?.message || `Request failed with HTTP status ${response.status}`;
      throw new ApiError(errorMsg, response.status, data);
    }

    return data;
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof ApiError) {
      throw err;
    }
    if (err.name === 'AbortError') {
      throw new ApiError(`Request timeout after ${timeoutMs / 1000}s while calling ${endpoint}`, 408);
    }
    throw new ApiError(
      `Unable to reach WorldGuard backend at ${API_BASE_URL}. Ensure the backend service is running on port 8000.`,
      0,
      { originalError: err.message }
    );
  }
}

/**
 * Checks API server health
 */
export async function checkBackendHealth() {
  return request('/health');
}

/**
 * Retrieves assessment and scan history from SQLite
 */
export async function fetchAssessmentHistory(limit = 50) {
  const safeLimit = Math.max(1, Math.min(limit, 100));
  return request(`/scans?limit=${safeLimit}`);
}

/**
 * Retrieves a single scan / assessment record by ID
 */
export async function fetchAssessmentDetails(assessmentId) {
  if (!assessmentId) {
    throw new ApiError('Assessment ID is required', 400);
  }
  // Try /assessment/{id} first; fall back to /scans/{id}
  try {
    return await request(`/assessment/${assessmentId}`);
  } catch (err) {
    if (err.status === 404 || err.status === 400) {
      return await request(`/scans/${assessmentId}`);
    }
    throw err;
  }
}

/**
 * Executes a controlled security assessment against the authorized local demo target
 * Security Boundary: strictly restricted to http://127.0.0.1:8001
 */
export async function triggerDemoAssessment(targetUrl = 'http://127.0.0.1:8001') {
  return request('/assessment/demo', {
    method: 'POST',
    body: JSON.stringify({ target_url: targetUrl }),
  });
}

/**
 * Executes the controlled remediation and verification workflow for a demo finding (e.g. WG-AC-004)
 */
export async function applyRemediationVerification(
  findingId = 'WG-AC-004',
  targetUrl = 'http://127.0.0.1:8001',
  assessmentId = null
) {
  const body = {
    finding_id: findingId,
    target_url: targetUrl,
  };
  if (assessmentId) {
    body.assessment_id = assessmentId;
  }
  return request('/remediation/demo/apply', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

/**
 * Retrieves a persisted remediation verification record by ID
 */
export async function fetchRemediationDetails(verificationId) {
  if (!verificationId) {
    throw new ApiError('Verification ID is required', 400);
  }
  return request(`/remediation/${verificationId}`);
}

/**
 * Generates or retrieves AI assessment summary (executive & technical)
 */
export async function fetchAssessmentAISummary(assessmentId) {
  if (!assessmentId) {
    throw new ApiError('Assessment ID is required', 400);
  }
  return request(`/assessment/${assessmentId}/ai-summary`, {
    method: 'POST',
  });
}

/**
 * Generates or retrieves structured AI finding analysis and advisory
 */
export async function fetchFindingAIAnalysis(findingId) {
  if (!findingId) {
    throw new ApiError('Finding identifier is required', 400);
  }
  return request(`/findings/${encodeURIComponent(findingId)}/ai-analysis`, {
    method: 'POST',
  });
}

export async function fetchAssessmentJsonReport(assessmentId) {
  if (!assessmentId) {
    throw new ApiError('Assessment ID is required', 400);
  }
  return request(`/reports/${assessmentId}/json`);
}

/**
 * Retrieves the API Security Map for an assessment or latest demo assessment
 */
export async function fetchApiSecurityMap(assessmentId = null) {
  if (!assessmentId) {
    return request('/assessment/demo/api-map');
  }
  return request(`/assessment/${assessmentId}/api-map`);
}

/**
 * Retrieves the Evidence Timeline / Audit Trail for a completed assessment record
 */
export async function fetchAssessmentTimeline(assessmentId) {
  if (!assessmentId) {
    throw new ApiError('Assessment ID is required', 400);
  }
  return request(`/assessment/${assessmentId}/timeline`);
}

/**
 * Initiates direct browser download for generated security reports (PDF / JSON)
 */
export function downloadReportFile(assessmentId, format = 'pdf') {
  if (!assessmentId) return;
  const url = `${API_BASE_URL}/reports/${assessmentId}/${format}`;
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', `worldguard_report_${assessmentId}.${format}`);
  link.target = '_blank';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

export { API_BASE_URL };

