from typing import Optional, Any
from backend.assessments.evidence import record_evidence


def run_authorization_assessment(
    client: Any,
    user_token: Optional[str] = None,
    admin_token: Optional[str] = None
) -> dict:
    """
    Executes controlled Role-Based Access Control (RBAC) tests against the local demo target.
    Focuses on detecting Broken Access Control (CWE-862) while validating legitimate RBAC policies.
    """
    evidence = []
    findings = []

    user_headers = {"Authorization": f"Bearer {user_token}"} if user_token else {}
    admin_headers = {"Authorization": f"Bearer {admin_token}"} if admin_token else {}

    # Test 1: WG-AC-001 - Admin Legitimate Access to Admin Endpoint
    # Expected: 200 OK
    resp_admin = client.get("/api/admin", headers=admin_headers)
    status_admin = resp_admin.status_code
    body_admin = resp_admin.json() if status_admin == 200 else resp_admin.text

    evidence.append(record_evidence(
        evidence_id="WG-AC-001",
        test_name="Admin Authorized Access to Admin Endpoint",
        test_role="Admin",
        method="GET",
        endpoint="/api/admin",
        expected_status=200,
        observed_status=status_admin,
        request_headers=admin_headers,
        request_body=None,
        response_body=body_admin
    ))

    if status_admin != 200:
        findings.append({
            "title": "RBAC Misconfiguration: Administrator Denied from Admin Endpoint",
            "severity": "Medium",
            "category": "Authorization / Access Control",
            "description": f"Admin role was denied access to GET /api/admin with HTTP {status_admin}. Expected 200 OK.",
            "severity_method": "WorldGuard prototype rule",
            "evidence_id": "WG-AC-001"
        })

    # Test 2: WG-AC-002 - Normal User Legitimate Access to Reports (Read)
    # Expected: 200 OK
    resp_reports = client.get("/api/reports", headers=user_headers)
    status_reports = resp_reports.status_code
    body_reports = resp_reports.json() if status_reports == 200 else resp_reports.text

    evidence.append(record_evidence(
        evidence_id="WG-AC-002",
        test_name="Normal User Permitted Read Access to Reports",
        test_role="Normal User",
        method="GET",
        endpoint="/api/reports",
        expected_status=200,
        observed_status=status_reports,
        request_headers=user_headers,
        request_body=None,
        response_body=body_reports
    ))

    if status_reports != 200:
        findings.append({
            "title": "RBAC Misconfiguration: Normal User Denied from Reading Reports",
            "severity": "Low",
            "category": "Authorization / Access Control",
            "description": f"Normal user was unable to list reports (HTTP {status_reports}). Expected 200 OK.",
            "severity_method": "WorldGuard prototype rule",
            "evidence_id": "WG-AC-002"
        })

    # Test 3: WG-AC-003 - Normal User Denied from Creating Reports (Write)
    # Expected: 403 Forbidden
    probe_report_body = {
        "title": "Unauthorized User Report Probe",
        "category": "Assessment",
        "summary": "Non-destructive authorization probe."
    }
    resp_create = client.post("/api/reports", json=probe_report_body, headers=user_headers)
    status_create = resp_create.status_code
    body_create = resp_create.json() if status_create in (200, 201, 403) else resp_create.text

    evidence.append(record_evidence(
        evidence_id="WG-AC-003",
        test_name="Normal User Denied Report Creation",
        test_role="Normal User",
        method="POST",
        endpoint="/api/reports",
        expected_status=403,
        observed_status=status_create,
        request_headers=user_headers,
        request_body=probe_report_body,
        response_body=body_create
    ))

    if status_create != 403:
        findings.append({
            "title": "Broken Access Control: Normal User Can Create Reports",
            "severity": "Medium",
            "category": "Authorization / Access Control",
            "description": (
                f"Normal user created a report via POST /api/reports with HTTP {status_create}. "
                "Report creation should be restricted to Operator, Analyst, or Admin roles."
            ),
            "severity_method": "WorldGuard prototype rule",
            "evidence_id": "WG-AC-003"
        })

    # Test 4: WG-AC-004 - Normal User Access to Restricted Admin Endpoint (PRIMARY DEMO)
    # Expected: 403 Forbidden
    resp_target = client.get("/api/admin", headers=user_headers)
    status_target = resp_target.status_code
    body_target = resp_target.json() if status_target in (200, 403) else resp_target.text

    evidence.append(record_evidence(
        evidence_id="WG-AC-004",
        test_name="Normal User Prohibited Access to Admin Control Panel",
        test_role="Normal User",
        method="GET",
        endpoint="/api/admin",
        expected_status=403,
        observed_status=status_target,
        request_headers=user_headers,
        request_body=None,
        response_body=body_target
    ))

    if status_target == 200:
        # VULNERABILITY DETECTED
        findings.append({
            "title": "Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)",
            "severity": "High",
            "category": "Authorization / Access Control",
            "description": (
                "The administrative endpoint GET /api/admin allows unprivileged users ('Normal User') "
                "to view administrative control telemetry and system configurations without requiring the Admin role. "
                "Expected HTTP 403 Forbidden, but received HTTP 200 OK."
            ),
            "severity_method": "WorldGuard prototype rule",
            "cwe_id": "CWE-862",
            "owasp_category": "A01:2021-Broken Access Control",
            "evidence_id": "WG-AC-004",
            "endpoint": "/api/admin",
            "method": "GET",
            "tested_role": "Normal User",
            "affected_component": "Admin Access Guard",
            "expected_behavior": "Authenticated users without the Admin role must receive HTTP 403 Forbidden when requesting the administrative endpoint.",
            "observed_behavior": "A Normal User received HTTP 200 OK from the administrative endpoint while vulnerable mode was enabled.",
            "steps_to_reproduce": [
                "Authenticate using the synthetic Normal User account.",
                "Obtain the temporary demo authentication token.",
                "Request GET /api/admin using that authenticated Normal User.",
                "Observe the HTTP response.",
                "Compare the observed response with the expected HTTP 403 requirement."
            ],
            "remediation": "Implement server-side role validation requiring current_user['role'] == 'Admin' before processing requests on /api/admin."
        })

    from backend.analysis.risk import enrich_finding_risk
    enriched_findings = [enrich_finding_risk(f) for f in findings]

    return {
        "findings": enriched_findings,
        "evidence": evidence
    }
