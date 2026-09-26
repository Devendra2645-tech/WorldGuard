import unittest
import os
import tempfile
from fastapi.testclient import TestClient

from demo_app.main import app as demo_app_instance
from demo_app.database import init_demo_db
from backend.main import app as scanner_app_instance
from backend.database import init_db
from backend.assessments import run_demo_assessment
from backend.remediation import apply_demo_remediation, get_remediation_record


class TestDashboardIntegration(unittest.TestCase):
    """
    Validates that the WorldGuard API contracts consumed by the Phase 9
    Security Analyst Dashboard remain intact, comprehensive, and secret-safe.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scanner_db = os.path.join(self.temp_dir.name, "test_scanner_dash.db")
        self.demo_db = os.path.join(self.temp_dir.name, "test_demo_dash.db")

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

    def test_dashboard_api_contracts_end_to_end(self):
        # 1. Health check for dashboard header indicator
        health_resp = self.scanner_client.get("/health")
        self.assertEqual(health_resp.status_code, 200)
        self.assertEqual(health_resp.json().get("status"), "healthy")

        # 2. History check before any runs (clean empty state)
        history_resp = self.scanner_client.get("/scans?limit=50")
        self.assertEqual(history_resp.status_code, 200)
        self.assertIsInstance(history_resp.json(), list)
        self.assertEqual(len(history_resp.json()), 0)

        # 3. Demo assessment execution (contract check for RiskOverview & FindingsTable)
        assessment_res = run_demo_assessment(
            target_url="http://127.0.0.1:8001",
            client=self.demo_client
        )
        self.assertEqual(assessment_res["status"], "completed")
        self.assertGreaterEqual(assessment_res["tests_run"], 7)
        self.assertIn("risk_summary", assessment_res)
        self.assertEqual(assessment_res["risk_summary"]["risk_level"], "High")

        findings = assessment_res["findings"]
        self.assertEqual(len(findings), 4)
        finding_ids = {f["evidence_id"] for f in findings}
        self.assertEqual(finding_ids, {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"})
        finding = next(f for f in findings if f["evidence_id"] == "WG-AC-004")

        # Verify all fields rendered in FindingDetails & FindingsTable
        expected_fields = [
            "title", "severity", "category", "description", "cwe_id",
            "owasp_category", "evidence_id", "endpoint", "method",
            "tested_role", "remediation", "severity_method", "exploitability",
            "confidentiality_impact", "integrity_impact", "availability_impact",
            "affected_role", "data_sensitivity", "business_impact", "remediation_priority"
        ]
        for field in expected_fields:
            self.assertIn(field, finding, f"Missing field '{field}' required by dashboard")

        # 4. Remediation verification execution (contract check for BeforeAfterVerification)
        remediation_res = apply_demo_remediation(
            finding_id="WG-AC-004",
            target_url="http://127.0.0.1:8001",
            client=self.demo_client,
            db_path=self.scanner_db
        )
        self.assertEqual(remediation_res["verification_status"], "verified")
        self.assertEqual(remediation_res["pre_remediation_status"], 200)
        self.assertEqual(remediation_res["post_remediation_status"], 403)
        self.assertEqual(remediation_res["admin_regression_status"], "passed")
        self.assertIn("verification_id", remediation_res)

        # 5. Remediation record retrieval via ID
        saved_rec = get_remediation_record(remediation_res["verification_id"], db_path=self.scanner_db)
        self.assertIsNotNone(saved_rec)
        self.assertEqual(saved_rec["verification_status"], "verified")

        # 6. Verify zero secrets exposed across all evidence records
        for ev in remediation_res["evidence"]:
            req_headers = ev.get("request_info", {}).get("headers", {})
            for key, val in req_headers.items():
                if "auth" in key.lower() or "token" in key.lower() or "secret" in key.lower():
                    self.assertEqual(val, "[REDACTED]")

        # 7. Audit history population check
        post_history_resp = self.scanner_client.get("/scans?limit=50")
        self.assertEqual(post_history_resp.status_code, 200)
        history_list = post_history_resp.json()
        self.assertGreaterEqual(len(history_list), 1)


if __name__ == "__main__":
    unittest.main()
