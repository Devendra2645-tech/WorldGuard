from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Optional
import datetime

from backend.scanners.headers import scan_security_headers
from backend.scanners.tls import scan_tls
from backend.scanners.api import scan_api
from backend.analysis.severity import calculate_summary
from backend.database import (
    init_db,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    get_finding_by_id,
    save_finding_ai_analysis,
    save_assessment_ai_summary
)
from backend.assessments import run_demo_assessment, validate_demo_target, reset_demo_target_mode
from backend.remediation import apply_demo_remediation, get_remediation_record
from backend.ai import generate_ai_finding_analysis, generate_ai_assessment_summary
from backend.reports import build_security_report_data, generate_pdf_report
from backend.analysis.api_map import build_api_security_map
from backend.analysis.timeline import build_evidence_timeline



app = FastAPI(
    title="World Monitor Security Assessment API",
    description="Backend API for security assessment of the World Monitor application",
    version="1.0.0"
)


@app.on_event("startup")
def startup_event():
    """Initializes the SQLite database tables upon application startup."""
    init_db()


# CORS configuration for local frontend development
origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"message": "World Monitor Security Assessment API is running"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
BLOCKED_INTERNAL_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".localdomain",
    ".home.arpa",
    ".corp",
    ".intranet",
    ".test",
    ".example",
    ".invalid",
)


def is_restricted_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """Check if an IP address belongs to loopback, private, link-local, or restricted ranges."""
    # Check if IPv6 has embedded IPv4 in NAT64 well-known prefix (RFC 6052)
    if isinstance(ip, ipaddress.IPv6Address) and ip in NAT64_PREFIX:
        embedded_ipv4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        return is_restricted_ip(embedded_ipv4)

    # Check IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_restricted_ip(ip.ipv4_mapped)

    if ip.is_loopback:
        return True, "loopback address"
    if ip.is_private:
        return True, "private network address"
    if ip.is_link_local:
        return True, "link-local address"
    if ip.is_multicast:
        return True, "multicast address"
    if ip.is_unspecified:
        return True, "unspecified address"
    if ip.is_reserved:
        return True, "reserved address"

    return False, ""


def validate_target_url(url: str) -> str:
    """Validate target URL to prevent SSRF and disallow internal/loopback targets."""
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string.")

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' URLs are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must include a valid hostname.")

    clean_host = hostname.lower().rstrip(".")

    if clean_host == "localhost" or clean_host.endswith(BLOCKED_INTERNAL_SUFFIXES):
        raise ValueError(f"Scanning internal or local hostname '{hostname}' is prohibited.")

    if "." not in clean_host:
        raise ValueError(
            f"Single-label hostname '{hostname}' is treated as internal and cannot be scanned."
        )

    # Check if hostname is an IP literal
    raw_ip = clean_host.strip("[]")
    try:
        if raw_ip.isdigit():
            ip_obj = ipaddress.IPv4Address(int(raw_ip))
        else:
            ip_obj = ipaddress.ip_address(raw_ip)
        restricted, reason = is_restricted_ip(ip_obj)
        if restricted:
            raise ValueError(f"Target IP '{ip_obj}' is a {reason} and cannot be scanned.")
    except ValueError as e:
        if "cannot be scanned" in str(e):
            raise
        # Not a direct IP literal; perform DNS resolution check to prevent DNS rebinding
        try:
            addr_info = socket.getaddrinfo(clean_host, None)
            for entry in addr_info:
                resolved_ip = ipaddress.ip_address(entry[4][0])
                restricted, reason = is_restricted_ip(resolved_ip)
                if restricted:
                    raise ValueError(
                        f"Target hostname '{hostname}' resolves to a {reason} ({resolved_ip}) and cannot be scanned."
                    )
        except (socket.gaierror, socket.herror, OSError):
            # If DNS resolution fails, allow scanner to report connectivity error
            pass

    return url.strip()


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return validate_target_url(v)


@app.post("/scan")
def scan_website(request: ScanRequest):
    header_result = scan_security_headers(request.url)
    tls_result = scan_tls(request.url)
    api_result = scan_api(request.url)

    all_findings = (
        header_result["findings"]
        + tls_result["findings"]
        + api_result["findings"]
    )

    risk_summary = calculate_summary(all_findings)

    raw_results = {
        "security_headers": header_result,
        "tls": tls_result,
        "api": api_result
    }

    scan_id = save_scan(
        target=request.url,
        risk_summary=risk_summary,
        findings=all_findings,
        raw_results=raw_results
    )

    return {
        "scan_id": scan_id,
        "target": request.url,
        "risk_summary": risk_summary,
        "security_headers": header_result,
        "tls": tls_result,
        "api": api_result
    }


@app.get("/scans")
def list_scans(limit: int = 50):
    """Return recent scan history."""
    safe_limit = max(1, min(limit, 100))
    return get_recent_scans(limit=safe_limit)


@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    """Return one complete scan with its findings."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan record with ID {scan_id} not found."
        )
    return scan


# ==============================================================================
# Controlled Local Demo Assessment Endpoints (Authorized Target Only)
# ==============================================================================

class DemoAssessmentRequest(BaseModel):
    target_url: Optional[str] = "http://127.0.0.1:8001"

    @field_validator("target_url")
    @classmethod
    def check_demo_target(cls, v: Optional[str]) -> str:
        url = v or "http://127.0.0.1:8001"
        return validate_demo_target(url)


@app.post("/assessment/demo")
def assess_demo_application(request: DemoAssessmentRequest, include_ai: bool = False):
    """
    Executes the controlled security assessment engine against the local demo application.
    Enforces that the target is strictly http://127.0.0.1:8001 (or localhost:8001).
    Resets the authorized demo target to vulnerable mode prior to assessment execution.
    Evaluates authentication integrity and performs RBAC / Broken Access Control testing.
    """
    try:
        result = run_demo_assessment(target_url=request.target_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment execution error: {str(e)}")

    # Generate deterministic API Security Map for demo target surface
    api_map = build_api_security_map(
        assessment_findings=result["findings"],
        assessment_evidence=result["evidence"]
    )

    raw_results = {
        "assessment_type": "controlled_demo",
        "tests_run": result["tests_run"],
        "evidence": result["evidence"],
        "api_security_map": api_map
    }

    ai_summary_dict = None
    if include_ai:
        ai_summary = generate_ai_assessment_summary(result)
        ai_summary_dict = ai_summary.model_dump()
        raw_results["ai_summary"] = ai_summary_dict

    scan_id = save_scan(
        target=f"{result['target']} [Demo Assessment]",
        risk_summary=result["risk_summary"],
        findings=result["findings"],
        raw_results=raw_results
    )

    scan_record = {
        "id": scan_id,
        "target": result["target"],
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "risk_level": result["risk_summary"].get("risk_level", "High"),
        "findings": result["findings"],
        "raw_results": raw_results
    }
    timeline_res = build_evidence_timeline(scan_record)

    resp = {
        "assessment_id": scan_id,
        "target": result["target"],
        "status": "completed",
        "tests_run": result["tests_run"],
        "risk_summary": result["risk_summary"],
        "findings": result["findings"],
        "evidence": result["evidence"],
        "api_security_map": api_map,
        "timeline": timeline_res.get("timeline", []),
        "final_state": timeline_res.get("final_state", "AWAITING_REMEDIATION")
    }
    if ai_summary_dict:
        resp["ai_summary"] = ai_summary_dict
    return resp


@app.get("/assessment/{assessment_id}")
def get_assessment_result(assessment_id: int):
    """Retrieves stored demo assessment results, including findings, evidence, and API security map."""
    scan = get_scan_by_id(assessment_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Assessment record with ID {assessment_id} not found."
        )

    raw_results = scan.get("raw_results", {})
    api_map = raw_results.get("api_security_map")
    if not api_map:
        api_map = build_api_security_map(
            assessment_findings=scan.get("findings", []),
            assessment_evidence=raw_results.get("evidence", [])
        )

    timeline_res = build_evidence_timeline(scan)

    resp = {
        "assessment_id": scan["id"],
        "target": scan["target"],
        "scanned_at": scan["scanned_at"],
        "status": scan["status"],
        "risk_level": scan["risk_level"],
        "total_findings": scan["total_findings"],
        "severity_counts": scan["severity_counts"],
        "tests_run": raw_results.get("tests_run", len(raw_results.get("evidence", []))),
        "findings": scan.get("findings", []),
        "evidence": raw_results.get("evidence", []),
        "api_security_map": api_map,
        "timeline": timeline_res.get("timeline", []),
        "final_state": timeline_res.get("final_state", "AWAITING_REMEDIATION")
    }
    if "ai_summary" in raw_results:
        resp["ai_summary"] = raw_results["ai_summary"]
    return resp


@app.get("/assessment/demo/api-map")
def get_demo_target_api_map():
    """Returns the current API Security Map for the authorized local demo application."""
    api_map = build_api_security_map()
    return {
        "target": "http://127.0.0.1:8001",
        "total_endpoints": len(api_map),
        "api_security_map": api_map
    }


@app.get("/assessment/{assessment_id}/api-map")
def get_assessment_api_map(assessment_id: int):
    """Retrieves the authoritative API Security Map for a completed assessment record."""
    scan = get_scan_by_id(assessment_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Assessment record with ID {assessment_id} not found."
        )
    raw_results = scan.get("raw_results", {})
    api_map = raw_results.get("api_security_map")
    if not api_map:
        api_map = build_api_security_map(
            assessment_findings=scan.get("findings", []),
            assessment_evidence=raw_results.get("evidence", [])
        )
    return {
        "assessment_id": scan["id"],
        "target": scan["target"],
        "total_endpoints": len(api_map),
        "api_security_map": api_map
    }


@app.get("/assessment/{assessment_id}/timeline")
def get_assessment_timeline(assessment_id: int):
    """
    Retrieves the authoritative Evidence Timeline / Audit Trail for a completed assessment record.
    Reconstructs the full deterministic lifecycle:
      Execution Started -> Tests Executed -> Evidence Captured -> Findings Detected ->
      Risk Analyzed -> Remediation Started -> Remediation Applied -> Retest Executed ->
      Regression Checked -> Verification Completed.
    """
    scan = get_scan_by_id(assessment_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Assessment record with ID {assessment_id} not found."
        )
    return build_evidence_timeline(scan)


# ==============================================================================
# Phase 10: AI Analysis & Prioritization Endpoints (Non-Authoritative Advisory)
# ==============================================================================

@app.post("/assessment/{assessment_id}/ai-summary")
def generate_assessment_ai_summary_endpoint(assessment_id: int):
    """
    Generates or retrieves structured AI executive and analyst summaries for an assessment.
    Uses deterministic fallback if AI provider is unconfigured or unavailable.
    Persists result into scans.raw_results['ai_summary'].
    """
    scan = get_scan_by_id(assessment_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Assessment record with ID {assessment_id} not found."
        )

    raw_results = scan.get("raw_results", {})
    assessment_data = {
        "id": scan["id"],
        "target": scan["target"],
        "risk_summary": {
            "risk_level": scan["risk_level"],
            "total_findings": scan["total_findings"],
            "severity_counts": scan["severity_counts"]
        },
        "tests_run": raw_results.get("tests_run", len(raw_results.get("evidence", []))),
        "findings": scan.get("findings", []),
        "evidence": raw_results.get("evidence", [])
    }

    ai_summary = generate_ai_assessment_summary(assessment_data)
    summary_dict = ai_summary.model_dump()

    save_assessment_ai_summary(assessment_id, summary_dict)
    return summary_dict


@app.post("/findings/{finding_id}/ai-analysis")
def generate_finding_ai_analysis_endpoint(finding_id: str):
    """
    Generates structured AI advisory analysis for an established finding.
    Uses deterministic fallback if AI provider is unconfigured or unavailable.
    Persists result into findings.metadata['ai_analysis'].
    """
    finding = get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(
            status_code=404,
            detail=f"Finding with identifier '{finding_id}' not found."
        )

    ai_analysis = generate_ai_finding_analysis(finding)
    analysis_dict = ai_analysis.model_dump()

    save_finding_ai_analysis(finding["id"], analysis_dict)
    return analysis_dict



# ==============================================================================
# Controlled Local Demo Remediation Endpoints (Authorized Target Only)
# ==============================================================================

class RemediationApplyRequest(BaseModel):
    finding_id: str = "WG-AC-004"
    target_url: Optional[str] = "http://127.0.0.1:8001"
    assessment_id: Optional[int] = None

    @field_validator("target_url")
    @classmethod
    def check_remediation_target(cls, v: Optional[str]) -> str:
        url = v or "http://127.0.0.1:8001"
        return validate_demo_target(url)


@app.post("/remediation/demo/apply")
def apply_remediation_demo(request: RemediationApplyRequest):
    """
    Executes a controlled remediation and verification workflow for a demo finding.
    Operates strictly against the authorized local demo application.
    Workflow:
      1. Precondition verification (checks vulnerable state)
      2. Apply fix on local demo target
      3. Automatic retest of Normal User (expects 403 Forbidden)
      4. Admin regression check (expects 200 OK)
      5. Safe evidence collection (secrets redacted)
      6. SQLite persistence
    """
    try:
        kwargs = {
            "finding_id": request.finding_id,
            "target_url": request.target_url,
        }
        if request.assessment_id is not None:
            kwargs["assessment_id"] = request.assessment_id

        result = apply_demo_remediation(**kwargs)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Remediation error: {str(e)}")


@app.get("/remediation/{verification_id}")
def get_remediation_result(verification_id: int):
    """Retrieves stored demo remediation verification results, including evidence and status."""
    record = get_remediation_record(verification_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"Remediation verification record with ID {verification_id} not found."
        )
    return record


# ==============================================================================
# Phase 11: Security Audit Reports Endpoints (JSON & PDF)
# ==============================================================================

@app.get("/reports/{assessment_id}/json")
def export_assessment_json_report(assessment_id: int):
    """
    Exports a comprehensive JSON security audit report for an assessment record.
    Includes deterministic findings, sanitized evidence, remediation verification,
    and non-authoritative AI advisory (if present).
    """
    try:
        report_data = build_security_report_data(assessment_id)
        return report_data
    except ValueError as e:
        raise HTTPException(
            status_code=404,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate JSON report: {str(e)}"
        )


@app.get("/reports/{assessment_id}/pdf")
def export_assessment_pdf_report(assessment_id: int):
    """
    Generates a presentation-grade, defense-ready PDF security audit report.
    Returns binary PDF stream with Content-Disposition attachment header.
    """
    try:
        report_data = build_security_report_data(assessment_id)
        pdf_bytes = generate_pdf_report(report_data)
        filename = f"worldguard_report_{assessment_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except ValueError as e:
        raise HTTPException(
            status_code=404,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF report: {str(e)}"
        )