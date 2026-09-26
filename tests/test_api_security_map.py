import unittest
import os
import json
import tempfile
from fastapi.testclient import TestClient

from demo_app.main import app as demo_app_instance
from demo_app.database import init_demo_db
from backend.main import app as scanner_app_instance
from backend.database import init_db, save_scan
from backend.assessments import run_demo_assessment
from backend.remediation.service import apply_demo_remediation
from backend.analysis.api_map import DEMO_TARGET_ROUTES, build_api_security_map
from backend.reports.generator import build_security_report_data
from backend.reports.pdf import generate_pdf_report


class TestApiSecurityMap(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scanner_db = os.path.join(self.temp_dir.name, "test_scanner_map.db")
        self.demo_db = os.path.join(self.temp_dir.name, "test_demo_map.db")

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

    def test_demo_target_routes_inventory(self):
        """Verifies exactly 13 authorized routes are registered in the target inventory."""
        self.assertEqual(len(DEMO_TARGET_ROUTES), 13)

        expected_endpoints = {
            ("/", "GET"),
            ("/health", "GET"),
            ("/api/auth/login", "POST"),
            ("/api/auth/me", "GET"),
            ("/api/users", "GET"),
            ("/api/reports", "GET"),
            ("/api/reports", "POST"),
            ("/api/analytics", "GET"),
            ("/api/admin", "GET"),
            ("/api/admin/mode", "GET"),
            ("/api/admin/mode", "POST"),
            ("/openapi.json", "GET"),
            ("/docs", "GET"),
        }
        actual_endpoints = {(r["endpoint"], r["method"]) for r in DEMO_TARGET_ROUTES}
        self.assertEqual(actual_endpoints, expected_endpoints)

        for route in DEMO_TARGET_ROUTES:
            self.assertIn("endpoint", route)
            self.assertIn("method", route)
            self.assertIn("authentication", route)
            self.assertIn("required_role", route)
            self.assertIn("data_modifying", route)
            self.assertIn("module", route)
            self.assertIn("description", route)

    def test_build_api_security_map_structure_and_vocabulary(self):
        """Verifies output schema and strict status vocabulary."""
        api_map = build_api_security_map()
        self.assertEqual(len(api_map), 13)

        allowed_statuses = {"FINDING", "PASS", "PUBLIC", "NOT_ASSESSED", "VERIFIED"}
        for entry in api_map:
            self.assertIn("endpoint", entry)
            self.assertIn("method", entry)
            self.assertIn("authentication", entry)
            self.assertIn("required_role", entry)
            self.assertIn("data_modifying", entry)
            self.assertIn("security_status", entry)
            self.assertIn(entry["security_status"], allowed_statuses)
            self.assertIn("security_note", entry)
            self.assertIsInstance(entry["security_note"], str)

    def test_unassessed_routes_strictly_not_assessed(self):
        """Ensures untested routes (/api/users, /api/analytics) are NOT_ASSESSED and NEVER marked PASS."""
        result = run_demo_assessment(client=self.demo_client)
        api_map = build_api_security_map(
            assessment_findings=result["findings"],
            assessment_evidence=result["evidence"]
        )

        users_route = next(r for r in api_map if r["endpoint"] == "/api/users" and r["method"] == "GET")
        self.assertEqual(users_route["security_status"], "NOT_ASSESSED")
        self.assertNotEqual(users_route["security_status"], "PASS")

        analytics_route = next(r for r in api_map if r["endpoint"] == "/api/analytics" and r["method"] == "GET")
        self.assertEqual(analytics_route["security_status"], "NOT_ASSESSED")
        self.assertNotEqual(analytics_route["security_status"], "PASS")

    def test_vulnerable_assessment_map_correlation(self):
        """Verifies accurate finding and pass correlation during vulnerable mode assessment."""
        result = run_demo_assessment(client=self.demo_client)
        api_map = build_api_security_map(
            assessment_findings=result["findings"],
            assessment_evidence=result["evidence"]
        )
        self.assertEqual(len(api_map), 13)

        by_route = {(r["endpoint"], r["method"]): r for r in api_map}

        # 1. GET /api/admin -> FINDING (WG-AC-004)
        admin_entry = by_route[("/api/admin", "GET")]
        self.assertEqual(admin_entry["security_status"], "FINDING")
        self.assertEqual(admin_entry["finding_id"], "WG-AC-004")
        self.assertEqual(admin_entry["severity"], "High")
        self.assertEqual(admin_entry["observed_status"], 200)
        self.assertEqual(admin_entry["expected_status"], 403)

        # 2. GET / -> FINDING (WG-AUTH-004 & WG-SEC-001)
        root_entry = by_route[("/", "GET")]
        self.assertEqual(root_entry["security_status"], "FINDING")
        self.assertIn("WG-AUTH-004", root_entry["finding_ids"])
        self.assertIn("WG-SEC-001", root_entry["finding_ids"])
        self.assertEqual(root_entry["severity"], "High")

        # 3. GET /openapi.json -> FINDING (WG-API-001)
        openapi_entry = by_route[("/openapi.json", "GET")]
        self.assertEqual(openapi_entry["security_status"], "FINDING")
        self.assertEqual(openapi_entry["finding_id"], "WG-API-001")
        self.assertEqual(openapi_entry["severity"], "Info")

        # 4. Verified PASS routes
        self.assertEqual(by_route[("/api/auth/login", "POST")]["security_status"], "PASS")
        self.assertEqual(by_route[("/api/auth/me", "GET")]["security_status"], "PASS")
        self.assertEqual(by_route[("/api/reports", "GET")]["security_status"], "PASS")
        self.assertEqual(by_route[("/api/reports", "POST")]["security_status"], "PASS")

        # 5. PUBLIC endpoints
        self.assertEqual(by_route[("/health", "GET")]["security_status"], "PUBLIC")
        self.assertEqual(by_route[("/docs", "GET")]["security_status"], "PUBLIC")
        self.assertEqual(by_route[("/api/admin/mode", "GET")]["security_status"], "PUBLIC")
        self.assertEqual(by_route[("/api/admin/mode", "POST")]["security_status"], "PUBLIC")

    def test_remediation_transition_to_verified(self):
        """Verifies GET /api/admin transitions to VERIFIED after remediation while retaining historical finding integrity."""
        # 1. Run baseline vulnerable assessment
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

        # 2. Apply remediation
        rem_res = apply_demo_remediation(
            finding_id="WG-AC-004",
            client=self.demo_client,
            db_path=self.scanner_db,
            assessment_id=scan_id
        )
        self.assertEqual(rem_res["verification_status"], "verified")

        # 3. Build map with remediation record
        map_after = build_api_security_map(
            assessment_findings=result["findings"],
            assessment_evidence=result["evidence"],
            remediation_record=rem_res
        )

        admin_entry = next(r for r in map_after if r["endpoint"] == "/api/admin" and r["method"] == "GET")
        self.assertEqual(admin_entry["security_status"], "VERIFIED")
        self.assertEqual(admin_entry["observed_status"], 403)
        self.assertIn("Remediation verified", admin_entry["security_note"])

        # Historical finding IDs still preserved for traceability
        self.assertEqual(admin_entry["finding_id"], "WG-AC-004")

    def test_no_secret_or_numerical_cvss_in_map(self):
        """Verifies zero secret exposure and zero numerical CVSS generation in API Security Map."""
        result = run_demo_assessment(client=self.demo_client)
        api_map = build_api_security_map(
            assessment_findings=result["findings"],
            assessment_evidence=result["evidence"]
        )

        map_json = json.dumps(api_map)
        self.assertNotIn("demo_user_password", map_json)
        self.assertNotIn("demo_admin_password", map_json)
        self.assertNotIn("demo-token-user", map_json)
        self.assertNotIn("demo-token-admin", map_json)

        for entry in api_map:
            # Severity must be qualitative string or None
            self.assertIn(entry["severity"], [None, "Critical", "High", "Medium", "Low", "Info"])
            self.assertNotIn("cvss", entry)
            self.assertNotIn("cvss_score", entry)

    def test_http_api_map_endpoints(self):
        """Tests GET /assessment/demo/api-map and GET /assessment/{id}/api-map."""
        # 1. GET /assessment/demo/api-map without any saved scan
        resp_demo_initial = self.scanner_client.get("/assessment/demo/api-map")
        self.assertEqual(resp_demo_initial.status_code, 200)
        data = resp_demo_initial.json()
        self.assertIn("api_security_map", data)
        self.assertEqual(len(data["api_security_map"]), 13)

        # 2. Run assessment and save
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

        # 3. GET /assessment/{id}/api-map
        resp_by_id = self.scanner_client.get(f"/assessment/{scan_id}/api-map")
        self.assertEqual(resp_by_id.status_code, 200)
        data_by_id = resp_by_id.json()
        self.assertIn("api_security_map", data_by_id)
        self.assertEqual(len(data_by_id["api_security_map"]), 13)

        # 4. GET /assessment/999999/api-map -> 404
        resp_not_found = self.scanner_client.get("/assessment/999999/api-map")
        self.assertEqual(resp_not_found.status_code, 404)

    def test_reports_contain_api_security_map(self):
        """Verifies JSON and PDF reports include the API Security Map table and data."""
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

        # 1. JSON Report
        report_data = build_security_report_data(scan_id, db_path=self.scanner_db)
        self.assertIn("api_security_map", report_data)
        self.assertEqual(len(report_data["api_security_map"]), 13)

        # 2. PDF Report
        pdf_bytes = generate_pdf_report(report_data)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertTrue(len(pdf_bytes) > 2000)


if __name__ == "__main__":
    unittest.main()
