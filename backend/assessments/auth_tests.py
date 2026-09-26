from typing import Optional, Any
from backend.assessments.evidence import record_evidence


def run_auth_assessment(client: Any) -> dict:
    """
    Executes controlled authentication tests against the local demo target.
    Uses only synthetic demo credentials.
    """
    evidence = []
    findings = []
    user_token = None
    admin_token = None

    # Test 1: WG-AUTH-001 - Valid Normal User Login
    req_body_valid = {"username": "user_demo", "password": "demo_user_password"}
    resp_valid = client.post("/api/auth/login", json=req_body_valid)
    status_valid = resp_valid.status_code
    resp_data_valid = resp_valid.json() if status_valid == 200 else resp_valid.text

    evidence.append(record_evidence(
        evidence_id="WG-AUTH-001",
        test_name="Valid Normal User Login",
        test_role="Normal User",
        method="POST",
        endpoint="/api/auth/login",
        expected_status=200,
        observed_status=status_valid,
        request_headers={"Content-Type": "application/json"},
        request_body=req_body_valid,
        response_body=resp_data_valid
    ))

    if status_valid == 200 and isinstance(resp_data_valid, dict):
        user_token = resp_data_valid.get("token")
    else:
        findings.append({
            "title": "Authentication Assessment Failure: Valid Demo User Login Rejected",
            "severity": "Medium",
            "category": "Authentication",
            "description": f"Valid demo credentials for 'user_demo' were rejected with HTTP {status_valid}. Expected 200 OK.",
            "severity_method": "WorldGuard prototype rule",
            "evidence_id": "WG-AUTH-001"
        })

    # Test 2: WG-AUTH-002 - Invalid Credentials Login
    req_body_invalid = {"username": "user_demo", "password": "wrong_demo_password_9981"}
    resp_invalid = client.post("/api/auth/login", json=req_body_invalid)
    status_invalid = resp_invalid.status_code

    evidence.append(record_evidence(
        evidence_id="WG-AUTH-002",
        test_name="Invalid Credentials Rejection",
        test_role="Unauthenticated",
        method="POST",
        endpoint="/api/auth/login",
        expected_status=401,
        observed_status=status_invalid,
        request_headers={"Content-Type": "application/json"},
        request_body=req_body_invalid,
        response_body=resp_invalid.json() if status_invalid == 401 else resp_invalid.text
    ))

    if status_invalid != 401:
        findings.append({
            "title": "Authentication Bypass: Invalid Credentials Accepted",
            "severity": "Critical",
            "category": "Authentication",
            "description": f"Invalid credentials for 'user_demo' were accepted with HTTP {status_invalid}. Expected 401 Unauthorized.",
            "severity_method": "WorldGuard prototype rule",
            "evidence_id": "WG-AUTH-002"
        })

    # Test 3: WG-AUTH-003 - Authenticated Profile Query (/api/auth/me)
    if user_token:
        headers_me = {"Authorization": f"Bearer {user_token}"}
        resp_me = client.get("/api/auth/me", headers=headers_me)
        status_me = resp_me.status_code
        data_me = resp_me.json() if status_me == 200 else resp_me.text

        evidence.append(record_evidence(
            evidence_id="WG-AUTH-003",
            test_name="Authenticated Profile Query",
            test_role="Normal User",
            method="GET",
            endpoint="/api/auth/me",
            expected_status=200,
            observed_status=status_me,
            request_headers=headers_me,
            request_body=None,
            response_body=data_me
        ))

        if status_me != 200:
            findings.append({
                "title": "Session Authentication Failure: Profile Retrieval Failed",
                "severity": "Medium",
                "category": "Authentication",
                "description": f"Authenticated GET /api/auth/me failed with HTTP {status_me}. Expected 200 OK.",
                "severity_method": "WorldGuard prototype rule",
                "evidence_id": "WG-AUTH-003"
            })

    # Test 4: WG-AUTH-005 - Missing Authentication Token Enforcement (/api/auth/me)
    # Request protected endpoint without Authorization or X-Demo-Token headers
    resp_no_token = client.get("/api/auth/me")
    status_no_token = resp_no_token.status_code
    body_no_token = resp_no_token.json() if status_no_token in (200, 401, 403) else resp_no_token.text

    evidence.append(record_evidence(
        evidence_id="WG-AUTH-005",
        test_name="Missing Authentication Token Enforcement",
        test_role="Unauthenticated",
        method="GET",
        endpoint="/api/auth/me",
        expected_status=401,
        observed_status=status_no_token,
        request_headers={},
        request_body=None,
        response_body=body_no_token
    ))

    if status_no_token != 401:
        findings.append({
            "title": "Missing Authentication: Unauthenticated Access to Protected Profile Permitted",
            "severity": "High",
            "category": "Authentication",
            "cwe_id": "CWE-306",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "description": (
                f"The protected profile endpoint GET /api/auth/me accepted an unauthenticated request "
                f"without an Authorization header, returning HTTP {status_no_token}. Expected HTTP 401 Unauthorized."
            ),
            "severity_method": "WorldGuard prototype rule",
            "evidence_id": "WG-AUTH-005",
            "endpoint": "/api/auth/me",
            "method": "GET",
            "affected_component": "Demo Authentication Dependency",
            "expected_behavior": "Requests lacking authentication headers must be rejected with HTTP 401 Unauthorized.",
            "observed_behavior": f"Request without authentication header returned HTTP {status_no_token}.",
            "steps_to_reproduce": [
                "Send GET /api/auth/me without Authorization or X-Demo-Token headers.",
                "Inspect the HTTP response status code.",
                "Verify whether the server enforces mandatory authentication."
            ],
            "remediation": "Enforce mandatory authentication verification before processing requests to protected routes."
        })

    # Test 5: WG-AUTH-006 - Malformed / Invalid Authentication Token Rejection (/api/auth/me)
    # Request protected endpoint with an invalid synthetic token
    # To prevent credential / token leakage, do not persist the invalid token in evidence
    headers_invalid = {"Authorization": "Bearer invalid_demo_token_99999"}
    resp_invalid_token = client.get("/api/auth/me", headers=headers_invalid)
    status_invalid_token = resp_invalid_token.status_code
    body_invalid_token = resp_invalid_token.json() if status_invalid_token in (200, 401, 403) else resp_invalid_token.text

    evidence.append(record_evidence(
        evidence_id="WG-AUTH-006",
        test_name="Malformed / Invalid Token Rejection",
        test_role="Unauthenticated",
        method="GET",
        endpoint="/api/auth/me",
        expected_status=401,
        observed_status=status_invalid_token,
        request_headers={"Authorization": "Bearer [REDACTED]"},
        request_body=None,
        response_body=body_invalid_token
    ))

    if status_invalid_token != 401:
        findings.append({
            "title": "Authentication Bypass: Malformed or Invalid Token Accepted",
            "severity": "Critical",
            "category": "Authentication",
            "cwe_id": "CWE-287",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "description": (
                f"The protected endpoint GET /api/auth/me accepted an invalid bearer token, "
                f"returning HTTP {status_invalid_token}. Expected HTTP 401 Unauthorized."
            ),
            "severity_method": "WorldGuard prototype rule",
            "evidence_id": "WG-AUTH-006",
            "endpoint": "/api/auth/me",
            "method": "GET",
            "affected_component": "Demo Authentication Dependency",
            "expected_behavior": "Requests with forged, malformed, or invalid tokens must be rejected with HTTP 401 Unauthorized.",
            "observed_behavior": f"Request with invalid token returned HTTP {status_invalid_token}.",
            "steps_to_reproduce": [
                "Send GET /api/auth/me with an invalid Bearer token.",
                "Inspect the HTTP response status code.",
                "Verify whether the server validates the authenticity of the session token."
            ],
            "remediation": "Validate session tokens against the authoritative session store and reject invalid or unrecognized tokens."
        })

    # Acquire Admin token for authorization testing
    resp_admin = client.post("/api/auth/login", json={"username": "admin_demo", "password": "demo_admin_password"})
    if resp_admin.status_code == 200:
        admin_token = resp_admin.json().get("token")

    return {
        "findings": findings,
        "evidence": evidence,
        "user_token": user_token,
        "admin_token": admin_token
    }
