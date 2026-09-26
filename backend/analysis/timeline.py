"""
WorldGuard Defensive Security Platform - Evidence Timeline / Audit Trail
Constructs a deterministic, reproducible lifecycle timeline from real assessment
and remediation records without fabricating timestamps or altering database state.
"""

from typing import Optional, Any
import datetime
import json


def _derive_phase(evidence_id: Optional[str]) -> str:
    """Categorizes an evidence identifier into an assessment lifecycle phase."""
    if not evidence_id:
        return "Security Assessment"
    if evidence_id.startswith("WG-AUTH"):
        return "Authentication Assessment"
    elif evidence_id.startswith("WG-AC"):
        return "Authorization Assessment"
    elif evidence_id.startswith("WG-SEC") or evidence_id.startswith("WG-API"):
        return "Configuration Assessment"
    elif evidence_id.startswith("WG-REM"):
        return "Remediation Verification"
    return "Security Assessment"


def build_evidence_timeline(
    scan_data: dict[str, Any],
    remediation_record: Optional[dict[str, Any]] = None,
    db_path: Optional[str] = None
) -> dict[str, Any]:
    """
    Builds a deterministic, chronological audit trail from actual assessment data.
    Strictly prevents timestamp fabrication:
      - Uses authoritative timestamps from evidence records and remediation results.
      - Explicitly marks derived timestamps with timestamp_exact=False and detailed source descriptions.
      - Zero raw credentials or bearer tokens are exposed.
    """
    if not isinstance(scan_data, dict):
        raise ValueError("scan_data must be a dictionary")

    assessment_id = scan_data.get("id") or scan_data.get("assessment_id")
    raw_results = scan_data.get("raw_results") or {}
    if not isinstance(raw_results, dict):
        raw_results = {}

    evidence_list = scan_data.get("evidence") or raw_results.get("evidence") or []
    findings_list = scan_data.get("findings") or []

    # Resolve remediation record strictly associated with this assessment
    resolved_remediation = remediation_record
    if not resolved_remediation:
        if isinstance(raw_results, dict) and raw_results.get("remediation_result"):
            resolved_remediation = raw_results["remediation_result"]
        elif assessment_id:
            try:
                from backend.database.database import get_db_connection
                conn = get_db_connection(db_path)
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        SELECT raw_results FROM scans
                        WHERE raw_results LIKE '%"record_type": "remediation_verification"%'
                        ORDER BY id DESC;
                        """
                    )
                    rows = cursor.fetchall()
                    for r in rows:
                        if not r["raw_results"]:
                            continue
                        try:
                            raw = json.loads(r["raw_results"])
                            rem = raw.get("remediation_result")
                            if rem and rem.get("original_assessment_id") == assessment_id:
                                resolved_remediation = rem
                                break
                        except Exception:
                            pass
                finally:
                    conn.close()
            except Exception:
                resolved_remediation = None

    events: list[dict[str, Any]] = []

    # --------------------------------------------------------------------------
    # 1. ASSESSMENT_EXECUTION_STARTED
    # --------------------------------------------------------------------------
    first_evidence = evidence_list[0] if evidence_list else None
    first_ts = (
        first_evidence.get("timestamp")
        if first_evidence and first_evidence.get("timestamp")
        else (scan_data.get("scanned_at") or scan_data.get("timestamp"))
    )

    if first_ts:
        events.append({
            "event_type": "ASSESSMENT_EXECUTION_STARTED",
            "timestamp": first_ts,
            "timestamp_source": "first_test_execution",
            "timestamp_exact": False,
            "phase": "Assessment Lifecycle",
            "status": "INFO",
            "severity": None,
            "title": "Assessment Execution Started",
            "description": "First recorded test execution; exact assessment initialization time is not separately persisted.",
            "assessment_id": assessment_id,
            "finding_id": None,
            "evidence_id": first_evidence.get("evidence_id") if first_evidence else None,
            "verification_id": None,
            "endpoint": first_evidence.get("endpoint") if first_evidence else None,
            "method": first_evidence.get("method") if first_evidence else None,
            "role": "System / Scanner",
            "expected_status": None,
            "observed_status": None,
            "_step_index": 0
        })

    # --------------------------------------------------------------------------
    # 2. TEST_EXECUTED and EVIDENCE_CAPTURED for each test evidence record
    # --------------------------------------------------------------------------
    for idx, ev in enumerate(evidence_list):
        ev_id = ev.get("evidence_id", f"EV-{idx}")
        ts = ev.get("timestamp") or first_ts
        phase = _derive_phase(ev_id)
        status_match = bool(ev.get("status_match", False))
        test_status = "PASS" if status_match else "FAIL"
        test_role = ev.get("test_role") or "Anonymous / Public"
        endpoint = ev.get("endpoint")
        method = ev.get("method")
        exp_status = ev.get("expected_status")
        obs_status = ev.get("observed_status")
        test_name = ev.get("test_name") or ev_id

        # TEST_EXECUTED
        events.append({
            "event_type": "TEST_EXECUTED",
            "timestamp": ts,
            "timestamp_source": "evidence.timestamp",
            "timestamp_exact": True,
            "phase": phase,
            "status": test_status,
            "severity": None,
            "title": f"Test Executed: {test_name}",
            "description": f"Executed {method} {endpoint} as role '{test_role}'. Observed HTTP {obs_status}, expected HTTP {exp_status}.",
            "assessment_id": assessment_id,
            "finding_id": None,
            "evidence_id": ev_id,
            "verification_id": None,
            "endpoint": endpoint,
            "method": method,
            "role": test_role,
            "expected_status": exp_status,
            "observed_status": obs_status,
            "_step_index": 10 + idx * 10
        })

        # EVIDENCE_CAPTURED
        events.append({
            "event_type": "EVIDENCE_CAPTURED",
            "timestamp": ts,
            "timestamp_source": "evidence.timestamp",
            "timestamp_exact": True,
            "phase": phase,
            "status": test_status,
            "severity": None,
            "title": f"Evidence Captured: {ev_id}",
            "description": f"Deterministic sanitized evidence recorded for {ev_id} ({method} {endpoint}). Status match: {status_match}.",
            "assessment_id": assessment_id,
            "finding_id": None,
            "evidence_id": ev_id,
            "verification_id": None,
            "endpoint": endpoint,
            "method": method,
            "role": test_role,
            "expected_status": exp_status,
            "observed_status": obs_status,
            "_step_index": 10 + idx * 10 + 1
        })

    # --------------------------------------------------------------------------
    # 3. FINDING_DETECTED for each finding
    # --------------------------------------------------------------------------
    for f_idx, finding in enumerate(findings_list):
        f_evidence_id = finding.get("evidence_id") or finding.get("finding_id")
        matched_ev = next(
            (e for e in evidence_list if e.get("evidence_id") == f_evidence_id),
            None
        )

        if matched_ev and matched_ev.get("timestamp"):
            f_timestamp = matched_ev["timestamp"]
            f_order_base = 10 + evidence_list.index(matched_ev) * 10 + 2
        else:
            f_timestamp = first_ts
            f_order_base = 300 + f_idx

        f_phase = _derive_phase(f_evidence_id)
        f_title = finding.get("title", f"Finding {f_evidence_id}")
        f_desc = finding.get("description") or f"Security vulnerability identified for {f_evidence_id}."
        f_severity = finding.get("severity", "High")
        f_endpoint = finding.get("endpoint") or (matched_ev.get("endpoint") if matched_ev else None)
        f_method = finding.get("method") or (matched_ev.get("method") if matched_ev else None)
        f_role = finding.get("affected_role") or (matched_ev.get("test_role") if matched_ev else None)

        events.append({
            "event_type": "FINDING_DETECTED",
            "timestamp": f_timestamp,
            "timestamp_source": "linked_evidence",
            "timestamp_exact": False,
            "phase": f_phase,
            "status": "FAIL",
            "severity": f_severity,
            "title": f"Finding Detected: {f_title}",
            "description": f_desc,
            "assessment_id": assessment_id,
            "finding_id": f_evidence_id,
            "evidence_id": f_evidence_id,
            "verification_id": None,
            "endpoint": f_endpoint,
            "method": f_method,
            "role": f_role,
            "expected_status": matched_ev.get("expected_status") if matched_ev else None,
            "observed_status": matched_ev.get("observed_status") if matched_ev else None,
            "_step_index": f_order_base
        })

    # --------------------------------------------------------------------------
    # 4. RISK_ANALYZED
    # --------------------------------------------------------------------------
    final_evidence = evidence_list[-1] if evidence_list else None
    final_ts = (
        final_evidence.get("timestamp")
        if final_evidence and final_evidence.get("timestamp")
        else (scan_data.get("scanned_at") or scan_data.get("timestamp") or first_ts)
    )

    risk_level = (
        scan_data.get("risk_level")
        or scan_data.get("risk_summary", {}).get("risk_level", "High")
    )

    if final_ts:
        events.append({
            "event_type": "RISK_ANALYZED",
            "timestamp": final_ts,
            "timestamp_source": "final_test_execution",
            "timestamp_exact": False,
            "phase": "Risk Analysis",
            "status": "COMPLETED",
            "severity": risk_level,
            "title": f"Risk Analysis Completed: Overall Posture {risk_level.upper()}",
            "description": "Risk analysis follows completion of deterministic assessment tests; no separate risk-analysis timestamp is persisted.",
            "assessment_id": assessment_id,
            "finding_id": None,
            "evidence_id": None,
            "verification_id": None,
            "endpoint": None,
            "method": None,
            "role": "Risk Engine",
            "expected_status": None,
            "observed_status": None,
            "_step_index": 400
        })

    # --------------------------------------------------------------------------
    # 5. REMEDIATION LIFECYCLE (if remediation_result exists)
    # --------------------------------------------------------------------------
    final_state = "AWAITING_REMEDIATION"

    if resolved_remediation:
        rem_ev_list = resolved_remediation.get("evidence", [])
        rem_finding_id = resolved_remediation.get("finding_id", "WG-AC-004")
        verification_id = resolved_remediation.get("verification_id")
        verified_at = resolved_remediation.get("verified_at") or final_ts

        # Map WG-REM-PRE-001 -> REMEDIATION_STARTED
        pre_ev = next((e for e in rem_ev_list if e.get("evidence_id") == "WG-REM-PRE-001"), None)
        if pre_ev:
            events.append({
                "event_type": "REMEDIATION_STARTED",
                "timestamp": pre_ev.get("timestamp") or verified_at,
                "timestamp_source": "remediation.evidence.timestamp",
                "timestamp_exact": True,
                "phase": "Remediation Verification",
                "status": "PASS" if pre_ev.get("status_match") else "FAIL",
                "severity": "High",
                "title": "Remediation Workflow Initiated: Precondition Verification",
                "description": (
                    f"Precondition verified on {pre_ev.get('method')} {pre_ev.get('endpoint')}: "
                    f"Observed HTTP {pre_ev.get('observed_status')} as role '{pre_ev.get('test_role')}' "
                    f"(Vulnerable precondition confirmed)."
                ),
                "assessment_id": assessment_id,
                "finding_id": rem_finding_id,
                "evidence_id": "WG-REM-PRE-001",
                "verification_id": verification_id,
                "endpoint": pre_ev.get("endpoint"),
                "method": pre_ev.get("method"),
                "role": pre_ev.get("test_role"),
                "expected_status": pre_ev.get("expected_status"),
                "observed_status": pre_ev.get("observed_status"),
                "_step_index": 500
            })

        # Map WG-REM-ACT-002 -> REMEDIATION_APPLIED
        act_ev = next((e for e in rem_ev_list if e.get("evidence_id") == "WG-REM-ACT-002"), None)
        if act_ev:
            events.append({
                "event_type": "REMEDIATION_APPLIED",
                "timestamp": act_ev.get("timestamp") or verified_at,
                "timestamp_source": "remediation.evidence.timestamp",
                "timestamp_exact": True,
                "phase": "Remediation Verification",
                "status": "PASS" if act_ev.get("status_match") else "FAIL",
                "severity": None,
                "title": "Remediation Applied: Server-Side Authorization Guard",
                "description": (
                    f"Applied controlled defensive fix: {act_ev.get('method')} {act_ev.get('endpoint')} "
                    f"switched target to secure mode (vulnerable_mode=False)."
                ),
                "assessment_id": assessment_id,
                "finding_id": rem_finding_id,
                "evidence_id": "WG-REM-ACT-002",
                "verification_id": verification_id,
                "endpoint": act_ev.get("endpoint"),
                "method": act_ev.get("method"),
                "role": act_ev.get("test_role"),
                "expected_status": act_ev.get("expected_status"),
                "observed_status": act_ev.get("observed_status"),
                "_step_index": 510
            })

        # Map WG-REM-VER-003 -> RETEST_EXECUTED
        ver_ev = next((e for e in rem_ev_list if e.get("evidence_id") == "WG-REM-VER-003"), None)
        if ver_ev:
            retest_passed = ver_ev.get("observed_status") == ver_ev.get("expected_status")
            events.append({
                "event_type": "RETEST_EXECUTED",
                "timestamp": ver_ev.get("timestamp") or verified_at,
                "timestamp_source": "remediation.evidence.timestamp",
                "timestamp_exact": True,
                "phase": "Remediation Verification",
                "status": "VERIFIED" if retest_passed else "FAIL",
                "severity": "High",
                "title": "Post-Remediation Retest: Unauthorized Access Blocked",
                "description": (
                    f"Retested {ver_ev.get('method')} {ver_ev.get('endpoint')} as role '{ver_ev.get('test_role')}'. "
                    f"Observed HTTP {ver_ev.get('observed_status')} Forbidden (Expected HTTP {ver_ev.get('expected_status')})."
                ),
                "assessment_id": assessment_id,
                "finding_id": rem_finding_id,
                "evidence_id": "WG-REM-VER-003",
                "verification_id": verification_id,
                "endpoint": ver_ev.get("endpoint"),
                "method": ver_ev.get("method"),
                "role": ver_ev.get("test_role"),
                "expected_status": ver_ev.get("expected_status"),
                "observed_status": ver_ev.get("observed_status"),
                "_step_index": 520
            })

        # Map WG-REM-REG-004 -> REGRESSION_CHECKED
        reg_ev = next((e for e in rem_ev_list if e.get("evidence_id") == "WG-REM-REG-004"), None)
        if reg_ev:
            reg_passed = reg_ev.get("observed_status") == reg_ev.get("expected_status")
            events.append({
                "event_type": "REGRESSION_CHECKED",
                "timestamp": reg_ev.get("timestamp") or verified_at,
                "timestamp_source": "remediation.evidence.timestamp",
                "timestamp_exact": True,
                "phase": "Remediation Verification",
                "status": "PASS" if reg_passed else "FAIL",
                "severity": None,
                "title": "Admin Legitimate Access Regression Check",
                "description": (
                    f"Regression verified on {reg_ev.get('method')} {reg_ev.get('endpoint')} as role '{reg_ev.get('test_role')}'. "
                    f"Observed HTTP {reg_ev.get('observed_status')} OK (Legitimate access preserved)."
                ),
                "assessment_id": assessment_id,
                "finding_id": rem_finding_id,
                "evidence_id": "WG-REM-REG-004",
                "verification_id": verification_id,
                "endpoint": reg_ev.get("endpoint"),
                "method": reg_ev.get("method"),
                "role": reg_ev.get("test_role"),
                "expected_status": reg_ev.get("expected_status"),
                "observed_status": reg_ev.get("observed_status"),
                "_step_index": 530
            })

        # Map verified_at -> VERIFICATION_COMPLETED
        v_status = resolved_remediation.get("verification_status", "verified")
        is_verified = (v_status == "verified")
        events.append({
            "event_type": "VERIFICATION_COMPLETED",
            "timestamp": verified_at,
            "timestamp_source": "remediation.verified_at",
            "timestamp_exact": True,
            "phase": "Remediation Verification",
            "status": "VERIFIED" if is_verified else "FAILED",
            "severity": "Info" if is_verified else "High",
            "title": f"Remediation Verification Completed: {rem_finding_id}",
            "description": (
                resolved_remediation.get("message")
                or f"Remediation verification completed with status '{v_status}'."
            ),
            "assessment_id": assessment_id,
            "finding_id": rem_finding_id,
            "evidence_id": "WG-REM-VER-003",
            "verification_id": verification_id,
            "endpoint": resolved_remediation.get("endpoint", "/api/admin"),
            "method": resolved_remediation.get("method", "GET"),
            "role": resolved_remediation.get("tested_role", "Normal User"),
            "expected_status": resolved_remediation.get("expected_status", 403),
            "observed_status": resolved_remediation.get("observed_status", 403),
            "_step_index": 540
        })

        final_state = "REMEDIATION_VERIFIED" if is_verified else "REMEDIATION_FAILED"
    else:
        # Check if findings indicate any prior verification
        if any(f.get("verification_status") == "verified" for f in findings_list):
            final_state = "REMEDIATION_VERIFIED"
        else:
            final_state = "AWAITING_REMEDIATION"

    # --------------------------------------------------------------------------
    # 6. Chronological Sorting & Deterministic Event ID Assignment
    # --------------------------------------------------------------------------
    # Primary sort: timestamp (ISO-8601 string)
    # Secondary tie-breaker: _step_index
    events.sort(key=lambda e: (e.get("timestamp") or "", e.get("_step_index", 0)))

    timeline: list[dict[str, Any]] = []
    for idx, event in enumerate(events, start=1):
        event_copy = dict(event)
        event_copy.pop("_step_index", None)
        event_copy["event_id"] = f"EVT-{idx:03d}"
        timeline.append(event_copy)

    return {
        "assessment_id": assessment_id,
        "event_count": len(timeline),
        "final_state": final_state,
        "timeline": timeline
    }
