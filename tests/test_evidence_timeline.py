import unittest
import os
import json
import tempfile
from unittest.mock import patch
from fastapi.testclient import TestClient

from demo_app.main import app as demo_app_instance
from demo_app.database import init_demo_db
from backend.main import app as scanner_app_instance
from backend.database import init_db, save_scan
from backend.assessments import run_demo_assessment
from backend.remediation.service import apply_demo_remediation
from backend.analysis.timeline import build_evidence_timeline
from backend.reports.generator import build_security_report_data
from backend.reports.pdf import generate_pdf_report


class TestEvidenceTimeline(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scanner_db = os.path.join(self.temp_dir.name, "test_scanner_timeline.db")
        self.demo_db = os.path.join(self.temp_dir.name, "test_demo_timeline.db")

        os.environ["WORLD_MONITOR_DB_PATH"] = self.scanner_db
        os.environ["DEMO_APP_DB_PATH"] = self.demo_db

        init_db(self.scanner_db)
        init_demo_db(self.demo_db)

        demo_app_instance.state.vulnerable_mode = True

        self.demo_client = TestClient(demo_app_instance)
        self.scanner_client = TestClient(scanner_app_instance)

    def tearDown(self):
        os.environ.pop("WORLD_MONITOR_DB_PATH", None)
        os.environ.pop("DEMO_APP_DB_PATH", None)
        self.temp_dir.cleanup()

    def test_timeline_builds_from_real_assessment_data(self):
        """1. Verifies timeline builds accurately from actual assessment run output."""
        result = run_demo_assessment(client=self.demo_client)
        timeline_data = build_evidence_timeline(result)

        self.assertIn("timeline", timeline_data)
        self.assertIn("event_count", timeline_data)
        self.assertIn("final_state", timeline_data)
        self.assertGreater(timeline_data["event_count"], 0)

        # Baseline: 1 start + 12 test_executed + 12 evidence_captured + 4 finding_detected + 1 risk_analyzed = 30 events
        self.assertEqual(timeline_data["event_count"], 30)
        self.assertEqual(timeline_data["final_state"], "AWAITING_REMEDIATION")

    def test_timeline_chronological_ordering_and_tie_breaking(self):
        """2 & 3. Verifies chronological ordering and deterministic tie-breaking."""
        result = run_demo_assessment(client=self.demo_client)
        timeline_data = build_evidence_timeline(result)
        events = timeline_data["timeline"]

        timestamps = [e["timestamp"] for e in events]
        # Timestamps must be sorted non-decreasingly
        self.assertEqual(timestamps, sorted(timestamps))

        # Tie-breaker verification: events with identical timestamps maintain deterministic sequence
        for i in range(len(events) - 1):
            if events[i]["timestamp"] == events[i + 1]["timestamp"]:
                # E.g., TEST_EXECUTED comes before EVIDENCE_CAPTURED or FINDING_DETECTED
                type_a = events[i]["event_type"]
                type_b = events[i + 1]["event_type"]
                if type_a == "TEST_EXECUTED":
                    self.assertIn(type_b, ("EVIDENCE_CAPTURED", "FINDING_DETECTED"))

    def test_required_event_schema(self):
        """4. Validates that every event strictly matches the normalized schema."""
        result = run_demo_assessment(client=self.demo_client)
        timeline_data = build_evidence_timeline(result)
        events = timeline_data["timeline"]

        required_keys = {
            "event_id",
            "event_type",
            "timestamp",
            "timestamp_source",
            "timestamp_exact",
            "phase",
            "status",
            "severity",
            "title",
            "description",
            "assessment_id",
            "finding_id",
            "evidence_id",
            "verification_id",
            "endpoint",
            "method",
            "role",
            "expected_status",
            "observed_status",
        }

        allowed_event_types = {
            "ASSESSMENT_EXECUTION_STARTED",
            "TEST_EXECUTED",
            "EVIDENCE_CAPTURED",
            "FINDING_DETECTED",
            "RISK_ANALYZED",
            "REMEDIATION_STARTED",
            "REMEDIATION_APPLIED",
            "RETEST_EXECUTED",
            "REGRESSION_CHECKED",
            "VERIFICATION_COMPLETED",
        }

        for idx, event in enumerate(events, start=1):
            self.assertEqual(set(event.keys()), required_keys)
            self.assertEqual(event["event_id"], f"EVT-{idx:03d}")
            self.assertIn(event["event_type"], allowed_event_types)
            self.assertIsInstance(event["timestamp"], str)
            self.assertIsInstance(event["timestamp_source"], str)
            self.assertIsInstance(event["timestamp_exact"], bool)

    def test_finding_to_evidence_traceability(self):
        """5. Confirms every finding event maps directly to an authoritative evidence record."""
        result = run_demo_assessment(client=self.demo_client)
        timeline_data = build_evidence_timeline(result)
        events = timeline_data["timeline"]

        finding_events = [e for e in events if e["event_type"] == "FINDING_DETECTED"]
        self.assertEqual(len(finding_events), 4)

        expected_findings = {"WG-AC-004", "WG-AUTH-004", "WG-SEC-001", "WG-API-001"}
        actual_findings = {e["finding_id"] for e in finding_events}
        self.assertEqual(actual_findings, expected_findings)

        # Every finding's timestamp matches its corresponding evidence timestamp
        for fe in finding_events:
            ev_id = fe["evidence_id"]
            matching_ev = next(e for e in result["evidence"] if e["evidence_id"] == ev_id)
            self.assertEqual(fe["timestamp"], matching_ev["timestamp"])
            self.assertEqual(fe["timestamp_source"], "linked_evidence")
            self.assertFalse(fe["timestamp_exact"])

    def test_remediation_lifecycle_and_verification_traceability(self):
        """6, 7, 8, 9, 10, 11. Tests WG-AC-004 remediation workflow and verification events."""
        # Baseline assessment
        result = run_demo_assessment(client=self.demo_client)
        scan_id = save_scan(
            target=result["target"],
            risk_summary=result["risk_summary"],
            findings=result["findings"],
            raw_results={
                "tests_run": result["tests_run"],
                "evidence": result["evidence"]
            },
            db_path=self.scanner_db
        )

        # Apply remediation
        rem_res = apply_demo_remediation(
            finding_id="WG-AC-004",
            client=self.demo_client,
            db_path=self.scanner_db,
            assessment_id=scan_id
        )
        self.assertEqual(rem_res["verification_status"], "verified")

        # Build timeline for remediated assessment
        scan_record = {
            "id": scan_id,
            "target": result["target"],
            "scanned_at": result["timestamp"],
            "risk_level": result["risk_summary"]["risk_level"],
            "findings": result["findings"],
            "raw_results": {
                "tests_run": result["tests_run"],
                "evidence": result["evidence"],
                "remediation_result": rem_res
            }
        }
        timeline_data = build_evidence_timeline(scan_record, db_path=self.scanner_db)

        self.assertEqual(timeline_data["final_state"], "REMEDIATION_VERIFIED")

        events = timeline_data["timeline"]
        by_type = {e["event_type"]: e for e in events}

        # 8. Pre-remediation observed 200
        pre_event = by_type["REMEDIATION_STARTED"]
        self.assertEqual(pre_event["evidence_id"], "WG-REM-PRE-001")
        self.assertEqual(pre_event["expected_status"], 200)
        self.assertEqual(pre_event["observed_status"], 200)

        # 9. Post-remediation observed 403
        retest_event = by_type["RETEST_EXECUTED"]
        self.assertEqual(retest_event["evidence_id"], "WG-REM-VER-003")
        self.assertEqual(retest_event["expected_status"], 403)
        self.assertEqual(retest_event["observed_status"], 403)
        self.assertEqual(retest_event["status"], "VERIFIED")

        # 10. Admin regression observed 200
        reg_event = by_type["REGRESSION_CHECKED"]
        self.assertEqual(reg_event["evidence_id"], "WG-REM-REG-004")
        self.assertEqual(reg_event["expected_status"], 200)
        self.assertEqual(reg_event["observed_status"], 200)
        self.assertEqual(reg_event["status"], "PASS")

        # 11. Verification completed
        ver_event = by_type["VERIFICATION_COMPLETED"]
        self.assertEqual(ver_event["status"], "VERIFIED")
        self.assertEqual(ver_event["severity"], "Info")
        self.assertEqual(ver_event["timestamp_source"], "remediation.verified_at")
        self.assertTrue(ver_event["timestamp_exact"])

    def test_unremediated_assessment_handling(self):
        """12. Verifies unremediated assessments produce AWAITING_REMEDIATION without inventing events."""
        result = run_demo_assessment(client=self.demo_client)
        timeline_data = build_evidence_timeline(result)

        self.assertEqual(timeline_data["final_state"], "AWAITING_REMEDIATION")
        event_types = {e["event_type"] for e in timeline_data["timeline"]}
        self.assertNotIn("REMEDIATION_STARTED", event_types)
        self.assertNotIn("REMEDIATION_APPLIED", event_types)
        self.assertNotIn("RETEST_EXECUTED", event_types)
        self.assertNotIn("REGRESSION_CHECKED", event_types)
        self.assertNotIn("VERIFICATION_COMPLETED", event_types)

    def test_invalid_assessment_returns_404(self):
        """13. Validates that GET /assessment/{id}/timeline returns 404 for nonexistent IDs."""
        resp = self.scanner_client.get("/assessment/999999/timeline")
        self.assertEqual(resp.status_code, 404)

    def test_no_fabricated_timestamps_and_source_correctness(self):
        """14, 15, 16. Verifies exactness and source tags for all lifecycle events."""
        result = run_demo_assessment(client=self.demo_client)
        timeline_data = build_evidence_timeline(result)

        for event in timeline_data["timeline"]:
            etype = event["event_type"]
            source = event["timestamp_source"]
            exact = event["timestamp_exact"]

            if etype == "ASSESSMENT_EXECUTION_STARTED":
                self.assertEqual(source, "first_test_execution")
                self.assertFalse(exact)
            elif etype in ("TEST_EXECUTED", "EVIDENCE_CAPTURED"):
                self.assertEqual(source, "evidence.timestamp")
                self.assertTrue(exact)
            elif etype == "FINDING_DETECTED":
                self.assertEqual(source, "linked_evidence")
                self.assertFalse(exact)
            elif etype == "RISK_ANALYZED":
                self.assertEqual(source, "final_test_execution")
                self.assertFalse(exact)

    def test_zero_credential_or_token_leakage(self):
        """17 & 18. Verifies zero cleartext passwords or raw session tokens in timeline."""
        result = run_demo_assessment(client=self.demo_client)
        timeline_data = build_evidence_timeline(result)
        dumped = json.dumps(timeline_data)

        self.assertNotIn("demo_user_password", dumped)
        self.assertNotIn("demo_admin_password", dumped)
        self.assertNotIn("invalid_demo_token_99999", dumped)
        self.assertNotIn("Bearer demo-token", dumped)

    def test_http_timeline_endpoint(self):
        """19. Validates HTTP GET /assessment/{id}/timeline."""
        with patch("backend.assessments.runner.httpx.Client", return_value=self.demo_client):
            post_resp = self.scanner_client.post("/assessment/demo", json={"target_url": "http://127.0.0.1:8001"})
            self.assertEqual(post_resp.status_code, 200)
            data = post_resp.json()
            assessment_id = data["assessment_id"]

            # Query timeline endpoint
            get_resp = self.scanner_client.get(f"/assessment/{assessment_id}/timeline")
            self.assertEqual(get_resp.status_code, 200)
            t_data = get_resp.json()

            self.assertEqual(t_data["assessment_id"], assessment_id)
            self.assertGreater(t_data["event_count"], 0)
            self.assertIn("timeline", t_data)
            self.assertEqual(t_data["final_state"], "AWAITING_REMEDIATION")

    def test_report_generation_includes_timeline(self):
        """20. Verifies report generator and PDF generator seamlessly include timeline."""
        with patch("backend.assessments.runner.httpx.Client", return_value=self.demo_client):
            post_resp = self.scanner_client.post("/assessment/demo", json={"target_url": "http://127.0.0.1:8001"})
            assessment_id = post_resp.json()["assessment_id"]

            report_data = build_security_report_data(assessment_id, db_path=self.scanner_db)
            self.assertIn("timeline", report_data)
            self.assertGreater(len(report_data["timeline"]), 0)

            # Generate PDF
            pdf_bytes = generate_pdf_report(report_data)
            self.assertIsInstance(pdf_bytes, bytes)
            self.assertGreater(len(pdf_bytes), 1000)


if __name__ == "__main__":
    unittest.main()
