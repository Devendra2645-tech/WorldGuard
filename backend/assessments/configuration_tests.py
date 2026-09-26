from typing import Any
from backend.assessments.evidence import record_evidence


def run_security_headers_assessment(client: Any) -> dict:
    """
    Evaluates whether the local demo application emits essential defense-in-depth
    security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options).
    Aggregates missing headers into a single finding (WG-SEC-001).
    """
    evidence = []
    findings = []

    try:
        resp = client.get("/")
        status_code = resp.status_code
        headers = dict(resp.headers)
    except Exception:
        status_code = 500
        headers = {}

    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]
    missing_headers = [h for h in required_headers if h not in headers]

    evidence.append(record_evidence(
        evidence_id="WG-SEC-001",
        test_name="Security Headers Assessment",
        test_role="Anonymous / Public",
        method="GET",
        endpoint="/",
        expected_status=200,
        observed_status=status_code,
        request_headers={"Accept": "application/json"},
        request_body=None,
        response_body={
            "missing_headers": missing_headers,
            "required_headers": required_headers,
            "status": "missing_protective_headers" if missing_headers else "protective_headers_present"
        }
    ))

    if missing_headers:
        findings.append({
            "title": "Missing Security Headers",
            "severity": "Medium",
            "category": "Security Misconfiguration",
            "cwe_id": "CWE-693",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "evidence_id": "WG-SEC-001",
            "endpoint": "/",
            "method": "GET",
            "affected_component": "Security Headers Middleware",
            "expected_behavior": "HTTP responses should include appropriate browser security headers such as Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options.",
            "observed_behavior": "The inspected response did not contain the required defensive security headers.",
            "steps_to_reproduce": [
                "Send GET /.",
                "Inspect the HTTP response headers.",
                "Check for Content-Security-Policy.",
                "Check for X-Frame-Options.",
                "Check for X-Content-Type-Options.",
                "Record missing headers as sanitized evidence."
            ],
            "description": (
                f"The HTTP response does not provide required protective security headers: {', '.join(missing_headers)}. "
                "The absence of these headers diminishes defense-in-depth protections against clickjacking (CWE-1021), "
                "MIME-type sniffing, and cross-site execution attacks."
            ),
            "severity_method": "WorldGuard prototype rule",
            "remediation": "Configure HTTP middleware to inject Content-Security-Policy, X-Frame-Options (DENY/SAMEORIGIN), and X-Content-Type-Options (nosniff) headers on all responses."
        })

    return {
        "findings": findings,
        "evidence": evidence
    }


def run_api_docs_assessment(client: Any) -> dict:
    """
    Evaluates whether interactive API documentation or OpenAPI specification schemas
    are publicly accessible without authentication.
    Produces a single finding (WG-API-001).
    """
    evidence = []
    findings = []

    exposed_endpoint = None
    observed_status = 404

    # Check 1: /openapi.json
    try:
        resp_spec = client.get("/openapi.json")
        if resp_spec.status_code == 200:
            exposed_endpoint = "/openapi.json"
            observed_status = 200
    except Exception:
        pass

    # Check 2: /docs (if /openapi.json was not exposed)
    if not exposed_endpoint:
        try:
            resp_docs = client.get("/docs")
            if resp_docs.status_code == 200:
                exposed_endpoint = "/docs"
                observed_status = 200
        except Exception:
            pass

    if exposed_endpoint:
        evidence.append(record_evidence(
            evidence_id="WG-API-001",
            test_name="Public OpenAPI Specification & Swagger UI Exposure",
            test_role="Anonymous / Public",
            method="GET",
            endpoint=exposed_endpoint,
            expected_status=401,
            observed_status=observed_status,
            request_headers={"Accept": "application/json"},
            request_body=None,
            response_body={
                "exposed_endpoint": exposed_endpoint,
                "status_code": observed_status,
                "exposure_type": "Public Interactive API Documentation"
            }
        ))

        findings.append({
            "title": "Public OpenAPI Specification & Swagger UI Exposure",
            "severity": "Info",
            "category": "API Security Misconfiguration",
            "cwe_id": "CWE-200",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "evidence_id": "WG-API-001",
            "endpoint": exposed_endpoint,
            "method": "GET",
            "affected_component": "OpenAPI Documentation Route",
            "expected_behavior": "Production API documentation and schema endpoints should be disabled or protected from unauthenticated access.",
            "observed_behavior": "The OpenAPI schema endpoint was accessible without authentication and returned HTTP 200 OK.",
            "steps_to_reproduce": [
                "Send GET /openapi.json without authentication.",
                "Observe the HTTP response.",
                "Confirm whether the schema is publicly accessible.",
                "Record only sanitized metadata about the exposed endpoint."
            ],
            "description": (
                f"Interactive API documentation and OpenAPI specification schema are publicly accessible at {exposed_endpoint} "
                "without authentication. Unrestricted exposure of API schemas reveals endpoints, parameter definitions, and "
                "internal system architecture to unauthorized actors."
            ),
            "severity_method": "WorldGuard prototype rule",
            "remediation": "Restrict access to OpenAPI specification and Swagger UI documentation in production environments using authentication guards or disabling documentation endpoints."
        })
    else:
        evidence.append(record_evidence(
            evidence_id="WG-API-001",
            test_name="Public OpenAPI Specification & Swagger UI Exposure",
            test_role="Anonymous / Public",
            method="GET",
            endpoint="/openapi.json",
            expected_status=401,
            observed_status=observed_status,
            request_headers={"Accept": "application/json"},
            request_body=None,
            response_body={"status": "API documentation is not publicly exposed."}
        ))

    return {
        "findings": findings,
        "evidence": evidence
    }


def run_root_credential_exposure_assessment(client: Any) -> dict:
    """
    Evaluates whether unauthenticated root endpoints expose sensitive credential material.
    Guarantees that all evidence is 100% sanitized with no cleartext passwords stored.
    Produces WG-AUTH-004.
    """
    evidence = []
    findings = []

    try:
        resp = client.get("/")
        status_code = resp.status_code
        data = resp.json() if status_code == 200 else {}
    except Exception:
        status_code = 500
        data = {}

    has_credentials = False
    sanitized_credentials_sample = {}

    if isinstance(data, dict) and "demo_credentials" in data:
        has_credentials = True
        raw_creds = data.get("demo_credentials", {})
        if isinstance(raw_creds, dict):
            for role, cred in raw_creds.items():
                if isinstance(cred, dict):
                    sanitized_credentials_sample[role] = {
                        "username": cred.get("username", "[REDACTED]"),
                        "password": "[REDACTED]"
                    }
                else:
                    sanitized_credentials_sample[role] = "[REDACTED]"

    if has_credentials:
        evidence.append(record_evidence(
            evidence_id="WG-AUTH-004",
            test_name="Public Credential Exposure on Root Endpoint",
            test_role="Anonymous / Public",
            method="GET",
            endpoint="/",
            expected_status=200,
            observed_status=status_code,
            request_headers={"Accept": "application/json"},
            request_body=None,
            response_body={
                "demo_credentials": sanitized_credentials_sample
            }
        ))

        findings.append({
            "title": "Public Credential Exposure on Unauthenticated Root Endpoint",
            "severity": "High",
            "category": "Information Exposure / Credential Disclosure",
            "cwe_id": "CWE-200",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "evidence_id": "WG-AUTH-004",
            "endpoint": "/",
            "method": "GET",
            "affected_component": "Public Landing Controller",
            "expected_behavior": (
                "The unauthenticated root endpoint may return public welcome metadata, "
                "but must not expose usernames, passwords, credentials, authentication secrets, "
                "or other sensitive authentication material."
            ),
            "observed_behavior": (
                "The unauthenticated root endpoint returned a demo_credentials field "
                "containing credential-like account information."
            ),
            "steps_to_reproduce": [
                "Send GET / without authentication.",
                "Inspect the JSON response.",
                "Check for credential-like fields.",
                "Confirm whether usernames/passwords or authentication secrets are exposed.",
                "Record only sanitized evidence."
            ],
            "description": (
                "The unauthenticated root landing endpoint GET / publicly exposes synthetic account credentials "
                "(including administrative accounts) in cleartext JSON. Publicly exposing credential material allows "
                "unauthorized actors to immediately authenticate and perform privileged operations."
            ),
            "severity_method": "WorldGuard prototype rule",
            "remediation": "Remove hardcoded credentials and demo account material from public API responses. Store secrets securely and enforce strict access controls."
        })
    else:
        evidence.append(record_evidence(
            evidence_id="WG-AUTH-004",
            test_name="Public Credential Exposure on Root Endpoint",
            test_role="Anonymous / Public",
            method="GET",
            endpoint="/",
            expected_status=200,
            observed_status=status_code,
            request_headers={"Accept": "application/json"},
            request_body=None,
            response_body={"status": "No credentials exposed on root endpoint."}
        ))

    return {
        "findings": findings,
        "evidence": evidence
    }


def run_configuration_assessment(client: Any) -> dict:
    """
    Executes all configuration, API surface, and information exposure assessments.
    Combines WG-SEC-001, WG-API-001, and WG-AUTH-004 assessments.
    """
    headers_res = run_security_headers_assessment(client)
    api_res = run_api_docs_assessment(client)
    creds_res = run_root_credential_exposure_assessment(client)

    all_findings = headers_res["findings"] + api_res["findings"] + creds_res["findings"]
    all_evidence = headers_res["evidence"] + api_res["evidence"] + creds_res["evidence"]

    return {
        "findings": all_findings,
        "evidence": all_evidence
    }
