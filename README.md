# World Monitor Security Assessment

**SIH 2026 Defensive Security Assessment Backend for the World Monitor Application**

---

## Overview

The **World Monitor Security Assessment** backend is an authorized, non-destructive security auditing tool designed to evaluate the defensive posture of web applications and services. It performs automated, passive security evaluations without intrusive testing, credential attacks, or service disruption.

---

## Features

- **Non-Destructive Scanning:** Passive inspection of externally reachable security attributes.
- **SSRF Protection:** Built-in validation rejecting loopback (`127.0.0.1`, `localhost`), link-local (`169.254.x.x`), private IP ranges (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`), and internal domain names to prevent the backend from being used as an SSRF proxy.
- **Security Headers Scanner:** Audits the presence and configuration of essential security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`).
- **TLS/HTTPS Inspector:** Evaluates HTTPS connectivity, socket handshakes, and negotiated TLS protocol versions.
- **API Surface Discovery:** Checks for publicly exposed OpenAPI and Swagger specifications (`openapi.json`, `swagger.json`).
- **Severity & Risk Engine:** Aggregates discovered findings and computes categorized risk summaries (`Critical`, `High`, `Medium`, `Low`, `Info`).
- **CORS Enabled:** Pre-configured for local frontend development environments.

---

## Project Structure

```
World-monitor-security/
├── backend/
│   ├── main.py                  # FastAPI application, CORS, input validation, and API routes
│   ├── ai/                      # AI Analysis & Prioritization (Phase 10 - Non-Authoritative Advisory)
│   │   ├── __init__.py          # Module exports
│   │   ├── models.py            # Pydantic schemas (FindingAIAnalysis, AssessmentAISummary)
│   │   ├── prompts.py           # Strictly sanitized prompt builders with secret stripping
│   │   └── service.py           # Provider-agnostic engine (httpx REST + deterministic fallback)
│   ├── analysis/
│   │   ├── risk.py              # Risk analysis, qualitative impact & business impact engine
│   │   └── severity.py          # Risk evaluation and severity calculation engine
│   ├── assessments/             # Controlled local security assessment engine (auth & RBAC)
│   │   ├── auth_tests.py        # Authentication integrity tests
│   │   ├── authorization_tests.py # RBAC & Broken Access Control (CWE-862) tests
│   │   ├── evidence.py          # Secret redaction & structured test evidence logging
│   │   └── runner.py            # Assessment orchestration & target boundary validation
│   ├── database/
│   │   ├── database.py          # SQLite database connection and persistence
│   │   └── models.py            # Pydantic data schemas
│   ├── remediation/             # Controlled remediation & automatic verification engine
│   │   ├── __init__.py          # Remediation exports
│   │   └── service.py           # Precondition verification, fix application, retest & persistence
│   └── scanners/
│       ├── headers.py           # HTTP security header verification
│       ├── tls.py               # TLS handshake and protocol analyzer
│       ├── api.py               # OpenAPI/Swagger specification detection
│       └── dependencies.py      # Dependency package parser (OSV advisory lookup)
├── demo_app/                    # Controlled Local Target Demo Application (SIH Benchmark)
│   ├── main.py                  # Demo application entrypoint (port 8001)
│   ├── auth.py                  # Demo authentication & RBAC dependencies
│   ├── database.py              # Demo SQLite DB & deterministic synthetic seeding
│   ├── models.py                # Demo API schemas
│   ├── routes/                  # Demo routes (auth, users, reports, analytics, admin)
│   └── README.md                # Demo application documentation
├── docs/                        # Project documentation and specifications
├── frontend/                    # Security Analyst Dashboard (Phase 9 & 10 - React/Vite)
│   ├── src/
│   │   ├── api/
│   │   │   └── worldguardApi.js # Standardized frontend API client & error handling
│   │   ├── components/
│   │   │   ├── Header.jsx       # Platform header, environment indicators & actions
│   │   │   ├── SummaryCards.jsx # Metrics cards (Total, Critical, High, Med, Low, Verified)
│   │   │   ├── RiskOverview.jsx # Severity distribution & deterministic risk posture
│   │   │   ├── BeforeAfterVerification.jsx # Before/after remediation & regression view
│   │   │   ├── AISecurityBrief.jsx # Phase 10: Executive & technical AI advisory brief
│   │   │   ├── FindingsTable.jsx # Vulnerability matrix with filters & search
│   │   │   ├── FindingDetails.jsx # Detailed audit modal with Section 6 AI Advisory
│   │   │   ├── RemediationModal.jsx # Verification confirmation dialog
│   │   │   └── AssessmentHistory.jsx # Historical audit log with drill-down
│   │   ├── App.jsx              # Main dashboard orchestration component
│   │   ├── index.css            # Dark-themed cybersecurity analyst styling
│   │   └── main.jsx             # React entrypoint
│   ├── package.json
│   └── vite.config.js

├── tests/                       # Unit and integration test suites
├── requirements.txt             # Python dependencies
└── README.md                    # Project documentation
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js v18+ & npm (for frontend dashboard)
- Virtual environment (`venv`)

### Installation

1. **Backend setup:**
   ```powershell
   cd D:\World-monitor-security
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. **Frontend setup:**
   ```powershell
   cd D:\World-monitor-security\frontend
   npm.cmd install
   ```

---

## Running the Complete System

To run the complete WorldGuard platform for an SIH 2026 demonstration, open three terminals:

### Terminal 1: Authorized Demo Application Target (Port 8001)
```powershell
cd D:\World-monitor-security
.\.venv\Scripts\python.exe -m uvicorn demo_app.main:app --host 127.0.0.1 --port 8001 --reload
```

### Terminal 2: WorldGuard Security Assessment Backend (Port 8000)
```powershell
cd D:\World-monitor-security
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive API docs available at:
- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **ReDoc:** `http://127.0.0.1:8000/redoc`

### Terminal 3: Security Analyst Dashboard Frontend (Port 5173)
```powershell
cd D:\World-monitor-security\frontend
npm.cmd run dev
```
Access the analyst dashboard in your browser at:
`http://localhost:5173` or `http://127.0.0.1:5173`

---

## API Endpoints

### 1. `GET /`
Returns the status message of the API.

### 2. `GET /health`
Returns the health status of the service:
```json
{
  "status": "healthy"
}
```

### 3. `POST /scan`
Performs a defensive security assessment against a validated public target URL.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Validation & Defensive Guardrails:**
- Scheme must be strictly `http://` or `https://`.
- `localhost` and internal domains (`.local`, `.internal`, `.lan`, etc.) are blocked.
- Private, loopback, and link-local IP addresses are blocked.

**Sample Response:**
```json
{
  "scan_id": 1,
  "target": "https://example.com",
  "risk_summary": {
    "risk_level": "Medium",
    "total_findings": 3,
    "severity_counts": {
      "Critical": 0,
      "High": 0,
      "Medium": 2,
      "Low": 1,
      "Info": 0
    }
  },
  "security_headers": { ... },
  "tls": { ... },
  "api": { ... }
}
```

### 4. `GET /scans`
Retrieves recent completed scan history.

**Query Parameters:**
- `limit` (optional, default 50, max 100): number of recent scans to return.

**Sample Response:**
```json
[
  {
    "id": 1,
    "target": "https://example.com",
    "scanned_at": "2026-09-24T13:20:00.000000+00:00",
    "risk_level": "Medium",
    "total_findings": 3,
    "severity_counts": {
      "Critical": 0,
      "High": 0,
      "Medium": 2,
      "Low": 1,
      "Info": 0
    },
    "status": "completed"
  }
]
```

### 5. `GET /scans/{scan_id}`
Retrieves a single complete scan record with all associated findings and raw scanner outputs.

**Path Parameters:**
- `scan_id`: Integer ID of the scan record.

### 6. `POST /assessment/demo`
Executes the controlled security assessment engine against the authorized local demo target (`http://127.0.0.1:8001`).

**Security Boundary:** Strictly restricted to `127.0.0.1:8001` (or `localhost:8001`). Rejects all external hosts.

**Request Body (optional):**
```json
{
  "target_url": "http://127.0.0.1:8001"
}
```

**Sample Vulnerable Result (Vulnerable Mode Active):**
```json
{
  "assessment_id": 2,
  "target": "http://127.0.0.1:8001",
  "status": "completed",
  "tests_run": 7,
  "risk_summary": {
    "risk_level": "High",
    "total_findings": 1,
    "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0}
  },
  "findings": [
    {
      "title": "Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)",
      "severity": "High",
      "category": "Authorization / Access Control",
      "description": "The administrative endpoint GET /api/admin allows unprivileged users ('Normal User') to view administrative control telemetry and system configurations without requiring the Admin role. Expected HTTP 403 Forbidden, but received HTTP 200 OK.",
      "severity_method": "WorldGuard prototype rule",
      "exploitability": "High",
      "confidentiality_impact": "High",
      "integrity_impact": "High",
      "availability_impact": "Low",
      "affected_role": "Normal User",
      "data_sensitivity": "Administrative system telemetry and restricted functionality",
      "business_impact": "An authenticated user without administrative privileges may access restricted administrative functionality, creating a risk of unauthorized information access and unauthorized administrative actions.",
      "remediation_priority": "High",
      "cwe_id": "CWE-862",
      "owasp_category": "A01:2021-Broken Access Control",
      "evidence_id": "WG-AC-004",
      "endpoint": "/api/admin",
      "method": "GET",
      "tested_role": "Normal User",
      "remediation": "Implement server-side role validation requiring current_user['role'] == 'Admin' before processing requests on /api/admin."
    }
  ],
  "evidence": [
    {
      "evidence_id": "WG-AC-004",
      "test_name": "Normal User Prohibited Access to Admin Control Panel",
      "test_role": "Normal User",
      "method": "GET",
      "endpoint": "/api/admin",
      "expected_status": 403,
      "observed_status": 200,
      "status_match": false,
      "timestamp": "2026-09-24T13:30:00.000000+00:00",
      "request_info": {
        "headers": {
          "Authorization": "[REDACTED]"
        },
        "body": null
      },
      "response_status": 200,
      "response_excerpt": "{'status': 'operational', 'system_name': 'World Monitor Core Node #01', 'vulnerability_active': True}"
    }
  ]
}
```

### 7. `GET /assessment/{assessment_id}`
Retrieves stored demo assessment results, including findings and secret-redacted evidence.

**Path Parameters:**
- `assessment_id`: Integer ID of the assessment record.

### 8. `POST /remediation/demo/apply`
Executes a controlled remediation and verification workflow for a demo finding (e.g., `WG-AC-004`).

**Security Boundary:** Strictly limited to the authorized local demo target (`http://127.0.0.1:8001` or `localhost:8001`). Non-demo targets are rejected.

**Workflow:**
1. **Precondition Verification:** Queries `GET /api/admin` with Normal User credentials to confirm the vulnerable state (`200 OK`).
2. **Apply Demo Fix:** Toggles server-side role validation on the demo app via `POST /api/admin/mode` (`vulnerable_mode: false`).
3. **Automatic Retest:** Re-queries `GET /api/admin` with Normal User credentials to verify access is now denied (`403 Forbidden`).
4. **Admin Regression Check:** Verifies legitimate access by Admin role remains intact (`200 OK`).
5. **Secret-Redacted Evidence Collection:** Logs structured before/after evidence with sensitive tokens and passwords sanitized to `[REDACTED]`.
6. **SQLite Persistence:** Stores the complete before/after verification record.

**Request Body (optional):**
```json
{
  "finding_id": "WG-AC-004",
  "target_url": "http://127.0.0.1:8001"
}
```

**Sample Verified Response:**
```json
{
  "finding_id": "WG-AC-004",
  "finding_title": "Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)",
  "target": "http://127.0.0.1:8001",
  "remediation_description": "Enforce server-side Admin role authorization on GET /api/admin.",
  "precondition_status": "vulnerable_confirmed",
  "pre_remediation_status": 200,
  "post_remediation_status": 403,
  "verification_status": "verified",
  "verified_at": "2026-09-24T14:00:00.000000+00:00",
  "tested_role": "Normal User",
  "endpoint": "/api/admin",
  "method": "GET",
  "expected_status": 403,
  "observed_status": 403,
  "admin_regression_status": "passed",
  "evidence": [
    {
      "evidence_id": "WG-REM-PRE-001",
      "test_name": "Pre-Remediation Vulnerability Verification",
      "test_role": "Normal User",
      "method": "GET",
      "endpoint": "/api/admin",
      "expected_status": 200,
      "observed_status": 200,
      "status_match": true,
      "request_info": { "headers": { "Authorization": "[REDACTED]" }, "body": null },
      "response_status": 200,
      "response_excerpt": "..."
    },
    {
      "evidence_id": "WG-REM-ACT-002",
      "test_name": "Apply Demo Server-Side Authorization Fix",
      "test_role": "System / Admin",
      "method": "POST",
      "endpoint": "/api/admin/mode",
      "expected_status": 200,
      "observed_status": 200,
      "status_match": true,
      "request_info": { "headers": { "Content-Type": "application/json" }, "body": { "vulnerable_mode": false } },
      "response_status": 200,
      "response_excerpt": "..."
    },
    {
      "evidence_id": "WG-REM-VER-003",
      "test_name": "Post-Remediation Verification Retest",
      "test_role": "Normal User",
      "method": "GET",
      "endpoint": "/api/admin",
      "expected_status": 403,
      "observed_status": 403,
      "status_match": true,
      "request_info": { "headers": { "Authorization": "[REDACTED]" }, "body": null },
      "response_status": 403,
      "response_excerpt": "..."
    },
    {
      "evidence_id": "WG-REM-REG-004",
      "test_name": "Admin Legitimate Access Regression Check",
      "test_role": "Admin",
      "method": "GET",
      "endpoint": "/api/admin",
      "expected_status": 200,
      "observed_status": 200,
      "status_match": true,
      "request_info": { "headers": { "Authorization": "[REDACTED]" }, "body": null },
      "response_status": 200,
      "response_excerpt": "..."
    }
  ],
  "message": "Remediation verified successfully: Normal User received HTTP 403 Forbidden and Admin access remains functional (HTTP 200).",
  "verification_id": 3
}
```

### 9. `GET /remediation/{verification_id}`
Retrieves a persisted remediation verification record from SQLite by ID, including before/after statuses and complete redacted evidence.

**Path Parameters:**
- `verification_id`: Integer ID of the remediation verification record.

---

## Phase 9: Security Analyst Dashboard

WorldGuard features a specialized, professional React/Vite dashboard designed for security analysts and SIH 2026 demonstrations:

- **Target & Health Indicators:** Live heartbeat connection to the FastAPI backend (`:8000`) and authorized target environment (`:8001`).
- **One-Click Assessment Trigger:** Triggers `POST /assessment/demo` to run deterministic authentication and RBAC evaluations.
- **Dynamic Summary Cards:** Real-time metrics for Total Findings, Critical, High, Medium, Low, and Verified Fixes derived from backend data.
- **Risk Posture & Severity Distribution:** Visual bar chart depicting finding distribution without arbitrary or fabricated scores.
- **Before / After Verification View:** High-visibility hero stepper mapping the exact lifecycle of `WG-AC-004`:
  1. *Before:* Normal User $\rightarrow$ `GET /api/admin` $\rightarrow$ `HTTP 200 OK (Vulnerable)`
  2. *Action:* Apply controlled server-side authorization check (`vulnerable_mode: false`)
  3. *After Retest:* Normal User $\rightarrow$ `GET /api/admin` $\rightarrow$ `HTTP 403 Forbidden (Verified)`
  4. *Regression Check:* Admin $\rightarrow$ `GET /api/admin` $\rightarrow$ `HTTP 200 OK (Passed)`
- **Finding Inspection Modal:** Complete drill-down view showing What Happened, Deterministic Evidence, CVSS-aligned Risk Analysis, Qualitative Business Impact, and Remediation Guidance with zero secret leakage.
- **Assessment History:** Searchable and inspectable audit log backed by SQLite persistence (`GET /scans`).

---

## Phase 10: AI Analysis & Prioritization (Advisory Layer)

WorldGuard incorporates an AI Analysis and Prioritization advisory layer designed to assist both executives and security analysts in interpreting findings, understanding business impact, and planning verification retests:

### Core Security & Architectural Principles
1. **Deterministic Assessment is the Source of Truth:** Automated assessment rules determine vulnerability existence and severity ratings. The AI cannot independently create, delete, or re-classify vulnerabilities.
2. **Strictly Non-Authoritative Advisory:** All AI-generated content is clearly branded with:
   `AI-GENERATED ADVISORY — NON-AUTHORITATIVE`
3. **No Fabricated CVSS Scores:** The advisory layer explains exploitability and impact factors using qualitative metrics without inventing numerical CVSS scores.
4. **Zero-Secret Sanitization:** Passwords, Bearer tokens, Authorization headers, API keys, cookies, and session tokens are strictly sanitized (`[REDACTED]`) before building prompts.
5. **Advisory Remediation Guidance:** Recommended remediation steps are advisory developer guidance only and are never executed automatically.
6. **Graceful Deterministic Fallback:** Operates 100% offline without requiring an API key. If the AI provider is disabled, unconfigured, or encounters network timeouts, the platform automatically returns deterministic expert rule synthesis without error.

### Environment Configuration
Configure the provider via environment variables:
```bash
# Default: Deterministic fallback (no external requests, 100% offline)
WORLDGUARD_AI_PROVIDER=none

# Optional: Google Gemini provider via httpx REST
WORLDGUARD_AI_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key_here
```

### Phase 10 API Endpoints
- `POST /assessment/{assessment_id}/ai-summary`: Synthesizes or retrieves executive and technical analyst summaries. Persisted in `scans.raw_results["ai_summary"]`.
- `POST /findings/{finding_id}/ai-analysis`: Synthesizes finding-level explanation, business risk, prioritization rationale, advisory remediation, and validation steps. Persisted in `findings.metadata["ai_analysis"]`.
- `POST /assessment/demo?include_ai=true`: Runs the assessment and generates the AI summary in a single coordinated request.

---

## Security & Ethics Policy

This tool is strictly intended for authorized, defensive security evaluations. It does not contain:
- Exploitation payloads
- Brute-force or denial-of-service mechanisms
- Credential stuffing or cracking tools
- Destructive testing routines
