import datetime
from typing import Optional, Any
import httpx

from backend.assessments.runner import validate_demo_target
from backend.assessments.evidence import record_evidence
from backend.database.database import save_scan, get_scan_by_id


SUPPORTED_REMEDIATION_FINDINGS = {
    "WG-AC-004": {
        "title": "Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)",
        "description": "Enforce server-side Admin role authorization on GET /api/admin.",
        "endpoint": "/api/admin",
        "method": "GET",
        "tested_role": "Normal User",
        "expected_vulnerable_status": 200,
        "expected_remediated_status": 403,
        "admin_role": "Admin",
        "expected_admin_status": 200
    }
}


def find_original_assessment_scan(
    finding_id: str,
    target_url: str = "http://127.0.0.1:8001",
    db_path: Optional[str] = None
) -> Optional[int]:
    """
    Deterministically locates the original security assessment scan ID for a given finding and target.
    Excludes verification-only records.
    """
    from backend.database.database import get_db_connection
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        clean_target = target_url.replace(" [Remediation Verification]", "").strip()
        cursor.execute(
            """
            SELECT s.id
            FROM scans s
            JOIN findings f ON s.id = f.scan_id
            WHERE s.raw_results NOT LIKE '%"record_type": "remediation_verification"%'
              AND s.target NOT LIKE '%[Remediation Verification]%'
              AND (s.target = ? OR s.target LIKE ?)
              AND (
                  f.metadata LIKE ?
                  OR f.metadata LIKE ?
                  OR f.title LIKE ?
              )
            ORDER BY s.id DESC
            LIMIT 1;
            """,
            (
                clean_target,
                f"{clean_target}%",
                f'%"evidence_id": "{finding_id}"%',
                f'%"finding_id": "{finding_id}"%',
                "%Broken Access Control%"
            )
        )
        row = cursor.fetchone()
        if row:
            return row["id"]
        return None
    finally:
        conn.close()


def apply_demo_remediation(
    finding_id: str,
    target_url: str = "http://127.0.0.1:8001",
    client: Optional[Any] = None,
    db_path: Optional[str] = None,
    assessment_id: Optional[int] = None
) -> dict:
    """
    Executes a controlled remediation and verification workflow for a demo finding.
    Operates strictly against the authorized local demo application.
    Workflow:
      1. Precondition verification (ensures target is in vulnerable state before applying fix)
      2. Apply fix on local demo target (switches vulnerable_mode to False)
      3. Automatic retest of Normal User (must receive 403 Forbidden)
      4. Admin regression check (must continue to receive 200 OK)
      5. Safe evidence collection (secrets redacted)
      6. SQLite persistence
    """
    validated_target = validate_demo_target(target_url)

    orig_scan_id = assessment_id
    if not orig_scan_id:
        orig_scan_id = find_original_assessment_scan(finding_id, validated_target, db_path=db_path)

    if finding_id not in SUPPORTED_REMEDIATION_FINDINGS:
        raise ValueError(
            f"Remediation is not supported for finding '{finding_id}'. "
            f"Supported findings: {list(SUPPORTED_REMEDIATION_FINDINGS.keys())}"
        )

    spec = SUPPORTED_REMEDIATION_FINDINGS[finding_id]

    own_client = False
    if client is None:
        client = httpx.Client(base_url=validated_target, timeout=5.0)
        own_client = True

    evidence = []

    try:
        # Step 1: Obtain synthetic demo credentials
        resp_user_login = client.post("/api/auth/login", json={"username": "user_demo", "password": "demo_user_password"})
        if resp_user_login.status_code != 200:
            raise RuntimeError(f"Failed to authenticate demo Normal User (HTTP {resp_user_login.status_code}).")
        user_token = resp_user_login.json()["token"]

        resp_admin_login = client.post("/api/auth/login", json={"username": "admin_demo", "password": "demo_admin_password"})
        if resp_admin_login.status_code != 200:
            raise RuntimeError(f"Failed to authenticate demo Admin (HTTP {resp_admin_login.status_code}).")
        admin_token = resp_admin_login.json()["token"]

        user_headers = {"Authorization": f"Bearer {user_token}"}
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Step 2: Before-state precondition verification
        # Normal User -> GET /api/admin should observe HTTP 200 in vulnerable state
        resp_pre = client.get(spec["endpoint"], headers=user_headers)
        pre_status = resp_pre.status_code
        pre_body = resp_pre.json() if pre_status in (200, 403) else resp_pre.text

        evidence.append(record_evidence(
            evidence_id="WG-REM-PRE-001",
            test_name="Pre-Remediation Vulnerability Verification",
            test_role=spec["tested_role"],
            method=spec["method"],
            endpoint=spec["endpoint"],
            expected_status=spec["expected_vulnerable_status"],
            observed_status=pre_status,
            request_headers=user_headers,
            request_body=None,
            response_body=pre_body
        ))

        # Check if vulnerable precondition was satisfied
        if pre_status != spec["expected_vulnerable_status"]:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            result = {
                "finding_id": finding_id,
                "finding_title": spec["title"],
                "target": validated_target,
                "remediation_description": spec["description"],
                "precondition_status": "precondition_failed",
                "pre_remediation_status": pre_status,
                "post_remediation_status": None,
                "verification_status": "precondition_failed",
                "verified_at": now,
                "tested_role": spec["tested_role"],
                "endpoint": spec["endpoint"],
                "method": spec["method"],
                "expected_status": spec["expected_remediated_status"],
                "observed_status": pre_status,
                "admin_regression_status": "skipped",
                "evidence": evidence,
                "message": (
                    f"Precondition failed: Expected vulnerable target returning HTTP {spec['expected_vulnerable_status']} "
                    f"for Normal User, but observed HTTP {pre_status}. Remediation not applied."
                )
            }
            # Persist failed precondition record
            scan_id = save_scan(
                target=f"{validated_target} [Remediation Verification]",
                risk_summary={"risk_level": "Medium", "total_findings": 1, "severity_counts": {"Critical": 0, "High": 0, "Medium": 1, "Low": 0, "Info": 0}},
                findings=[{"title": spec["title"], "severity": "Medium", "category": "Remediation Verification", "description": result["message"]}],
                raw_results={"record_type": "remediation_verification", "remediation_result": result},
                db_path=db_path
            )
            result["verification_id"] = scan_id
            return result

        # Step 3: Apply the controlled demo fix
        # Toggles demo target's authorization check to enforced/secure mode
        fix_payload = {"vulnerable_mode": False}
        resp_fix = client.post("/api/admin/mode", json=fix_payload)
        fix_status = resp_fix.status_code
        fix_body = resp_fix.json() if fix_status == 200 else resp_fix.text

        evidence.append(record_evidence(
            evidence_id="WG-REM-ACT-002",
            test_name="Apply Demo Server-Side Authorization Fix",
            test_role="System / Admin",
            method="POST",
            endpoint="/api/admin/mode",
            expected_status=200,
            observed_status=fix_status,
            request_headers={"Content-Type": "application/json"},
            request_body=fix_payload,
            response_body=fix_body
        ))

        # Step 4: Automatic retest (Normal User -> GET /api/admin)
        resp_retest = client.get(spec["endpoint"], headers=user_headers)
        post_status = resp_retest.status_code
        retest_body = resp_retest.json() if post_status in (200, 403) else resp_retest.text

        evidence.append(record_evidence(
            evidence_id="WG-REM-VER-003",
            test_name="Post-Remediation Verification Retest",
            test_role=spec["tested_role"],
            method=spec["method"],
            endpoint=spec["endpoint"],
            expected_status=spec["expected_remediated_status"],
            observed_status=post_status,
            request_headers=user_headers,
            request_body=None,
            response_body=retest_body
        ))

        # Step 5: Admin regression check (Admin -> GET /api/admin)
        resp_admin_check = client.get(spec["endpoint"], headers=admin_headers)
        admin_check_status = resp_admin_check.status_code
        admin_body = resp_admin_check.json() if admin_check_status in (200, 403) else resp_admin_check.text

        evidence.append(record_evidence(
            evidence_id="WG-REM-REG-004",
            test_name="Admin Legitimate Access Regression Check",
            test_role=spec["admin_role"],
            method=spec["method"],
            endpoint=spec["endpoint"],
            expected_status=spec["expected_admin_status"],
            observed_status=admin_check_status,
            request_headers=admin_headers,
            request_body=None,
            response_body=admin_body
        ))

        admin_regression_passed = (admin_check_status == spec["expected_admin_status"])
        admin_regression_status = "passed" if admin_regression_passed else "failed"

        # Step 6: Determine overall verification status
        if post_status == spec["expected_remediated_status"] and admin_regression_passed:
            verification_status = "verified"
            message = "Remediation verified successfully: Normal User received HTTP 403 Forbidden and Admin access remains functional (HTTP 200)."
        elif post_status == spec["expected_vulnerable_status"]:
            verification_status = "failed"
            message = f"Remediation failed: Target endpoint is still accessible by Normal User with HTTP {post_status}."
        else:
            verification_status = "error"
            message = f"Remediation verification encountered unexpected response: Normal User received HTTP {post_status}."

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = {
            "finding_id": finding_id,
            "finding_title": spec["title"],
            "target": validated_target,
            "remediation_description": spec["description"],
            "precondition_status": "vulnerable_confirmed",
            "pre_remediation_status": pre_status,
            "post_remediation_status": post_status,
            "verification_status": verification_status,
            "verified_at": now,
            "tested_role": spec["tested_role"],
            "endpoint": spec["endpoint"],
            "method": spec["method"],
            "expected_status": spec["expected_remediated_status"],
            "observed_status": post_status,
            "admin_regression_status": admin_regression_status,
            "evidence": evidence,
            "message": message
        }

        if orig_scan_id:
            result["original_assessment_id"] = orig_scan_id

        # Step 7: Persist verification record in SQLite
        finding_severity = "Info" if verification_status == "verified" else "High"
        scan_id = save_scan(
            target=f"{validated_target} [Remediation Verification]",
            risk_summary={
                "risk_level": finding_severity,
                "total_findings": 0 if verification_status == "verified" else 1,
                "severity_counts": {"Critical": 0, "High": 0 if verification_status == "verified" else 1, "Medium": 0, "Low": 0, "Info": 1 if verification_status == "verified" else 0}
            },
            findings=[{
                "title": spec["title"],
                "severity": finding_severity,
                "category": "Remediation Verification",
                "description": message,
                "finding_id": finding_id,
                "verification_status": verification_status
            }],
            raw_results={
                "record_type": "remediation_verification",
                "remediation_result": result
            },
            db_path=db_path
        )
        result["verification_id"] = scan_id

        # Step 8: Update original assessment scan and finding status in SQLite if present
        if orig_scan_id:
            from backend.database.database import get_db_connection
            conn = get_db_connection(db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT raw_results FROM scans WHERE id = ?;", (orig_scan_id,))
                orig_row = cursor.fetchone()
                if orig_row and orig_row["raw_results"]:
                    import json
                    orig_raw = json.loads(orig_row["raw_results"]) if orig_row["raw_results"] else {}
                    orig_raw["remediation_result"] = result
                    orig_raw["remediation_verification_id"] = scan_id
                    cursor.execute(
                        "UPDATE scans SET raw_results = ? WHERE id = ?;",
                        (json.dumps(orig_raw), orig_scan_id)
                    )
                    
                    cursor.execute(
                        """
                        SELECT id, metadata FROM findings
                        WHERE scan_id = ? AND (metadata LIKE ? OR title LIKE ?);
                        """,
                        (orig_scan_id, f'%"evidence_id": "{finding_id}"%', f'%{spec["title"][:25]}%')
                    )
                    f_row = cursor.fetchone()
                    if f_row:
                        f_meta = json.loads(f_row["metadata"]) if f_row["metadata"] else {}
                        f_meta["verification_status"] = verification_status
                        cursor.execute(
                            "UPDATE findings SET metadata = ? WHERE id = ?;",
                            (json.dumps(f_meta), f_row["id"])
                        )
                conn.commit()
            except Exception:
                pass
            finally:
                conn.close()

        return result

    finally:
        if own_client:
            client.close()


def get_remediation_record(verification_id: int, db_path: Optional[str] = None) -> Optional[dict]:
    """Retrieves a persisted remediation verification record from SQLite by ID."""
    scan = get_scan_by_id(verification_id, db_path=db_path)
    if not scan:
        return None

    raw_results = scan.get("raw_results", {})
    if raw_results.get("record_type") != "remediation_verification":
        return None

    record = raw_results.get("remediation_result")
    if record and "verification_id" not in record:
        record["verification_id"] = scan["id"]
    return record
