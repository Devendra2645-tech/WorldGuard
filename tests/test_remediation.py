import unittest
import os
import tempfile
from unittest.mock import patch
from fastapi.testclient import TestClient

from demo_app.main import app as demo_app_instance
from demo_app.database import init_demo_db
from backend.main import app as scanner_app_instance
from backend.database import init_db
from backend.remediation import (
    apply_demo_remediation,
    get_remediation_record,
    SUPPORTED_REMEDIATION_FINDINGS
)


class TestRemediation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scanner_db = os.path.join(self.temp_dir.name, "test_scanner_remediation.db")
        self.demo_db = os.path.join(self.temp_dir.name, "test_demo_remediation.db")

        os.environ["WORLD_MONITOR_DB_PATH"] = self.scanner_db
        os.environ["DEMO_APP_DB_PATH"] = self.demo_db

        init_db(self.scanner_db)
        init_demo_db(self.demo_db)

        # Default demo app state to vulnerable for testing
        demo_app_instance.state.vulnerable_mode = True

        self.demo_client = TestClient(demo_app_instance)
        self.scanner_client = TestClient(scanner_app_instance)

    def tearDown(self):
        os.environ.pop("WORLD_MONITOR_DB_PATH", None)
        os.environ.pop("DEMO_APP_DB_PATH", None)
        self.temp_dir.cleanup()

    def test_target_boundary_restriction(self):
        """Remediation must reject targets outside the authorized local demo target."""
        prohibited = [
            "https://google.com",
            "http://192.168.1.100:8001",
            "http://localhost:3000",
            "http://127.0.0.1:8000"
        ]
        for target in prohibited:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    apply_demo_remediation(
                        finding_id="WG-AC-004",
                        target_url=target,
                        client=self.demo_client,
                        db_path=self.scanner_db
                    )

    def test_unsupported_finding_rejected(self):
        """Remediation must reject findings that are not supported."""
        with self.assertRaises(ValueError) as ctx:
            apply_demo_remediation(
                finding_id="WG-UNKNOWN-999",
                target_url="http://127.0.0.1:8001",
                client=self.demo_client,
                db_path=self.scanner_db
            )
        self.assertIn("not supported", str(ctx.exception))

    def test_precondition_check_fails_if_not_vulnerable(self):
        """If the target is already secured (403), remediation halts without false verification."""
        demo_app_instance.state.vulnerable_mode = False

        res = apply_demo_remediation(
            finding_id="WG-AC-004",
            target_url="http://127.0.0.1:8001",
            client=self.demo_client,
            db_path=self.scanner_db
        )

        self.assertEqual(res["precondition_status"], "precondition_failed")
        self.assertEqual(res["verification_status"], "precondition_failed")
        self.assertEqual(res["pre_remediation_status"], 403)
        self.assertIsNone(res["post_remediation_status"])
        self.assertIn("Precondition failed", res["message"])
        self.assertIn("verification_id", res)

        # Confirm recorded in SQLite
        saved = get_remediation_record(res["verification_id"], db_path=self.scanner_db)
        self.assertIsNotNone(saved)
        self.assertEqual(saved["verification_status"], "precondition_failed")

    def test_full_remediation_and_verification_workflow(self):
        """Executes full workflow: verify vulnerable -> apply fix -> retest -> regression check -> persist."""
        demo_app_instance.state.vulnerable_mode = True

        res = apply_demo_remediation(
            finding_id="WG-AC-004",
            target_url="http://127.0.0.1:8001",
            client=self.demo_client,
            db_path=self.scanner_db
        )

        # 1. Overall verification fields
        self.assertEqual(res["finding_id"], "WG-AC-004")
        self.assertEqual(res["precondition_status"], "vulnerable_confirmed")
        self.assertEqual(res["pre_remediation_status"], 200)
        self.assertEqual(res["post_remediation_status"], 403)
        self.assertEqual(res["admin_regression_status"], "passed")
        self.assertEqual(res["verification_status"], "verified")
        self.assertEqual(res["tested_role"], "Normal User")
        self.assertEqual(res["endpoint"], "/api/admin")
        self.assertEqual(res["expected_status"], 403)
        self.assertEqual(res["observed_status"], 403)
        self.assertIn("verified successfully", res["message"])
        self.assertIn("verification_id", res)

        # 2. Check demo app state has been updated to secure mode
        self.assertFalse(demo_app_instance.state.vulnerable_mode)

        # 3. Evidence structure and secret redaction
        evidence = res["evidence"]
        self.assertEqual(len(evidence), 4)

        ev_map = {e["evidence_id"]: e for e in evidence}
        self.assertIn("WG-REM-PRE-001", ev_map)
        self.assertIn("WG-REM-ACT-002", ev_map)
        self.assertIn("WG-REM-VER-003", ev_map)
        self.assertIn("WG-REM-REG-004", ev_map)

        # WG-REM-PRE-001: observed 200
        self.assertEqual(ev_map["WG-REM-PRE-001"]["observed_status"], 200)
        self.assertEqual(ev_map["WG-REM-PRE-001"]["test_role"], "Normal User")

        # WG-REM-ACT-002: applied fix POST /api/admin/mode
        self.assertEqual(ev_map["WG-REM-ACT-002"]["observed_status"], 200)
        self.assertEqual(ev_map["WG-REM-ACT-002"]["endpoint"], "/api/admin/mode")

        # WG-REM-VER-003: observed 403
        self.assertEqual(ev_map["WG-REM-VER-003"]["observed_status"], 403)
        self.assertEqual(ev_map["WG-REM-VER-003"]["expected_status"], 403)
        self.assertTrue(ev_map["WG-REM-VER-003"]["status_match"])

        # WG-REM-REG-004: admin access observed 200
        self.assertEqual(ev_map["WG-REM-REG-004"]["observed_status"], 200)
        self.assertEqual(ev_map["WG-REM-REG-004"]["test_role"], "Admin")
        self.assertTrue(ev_map["WG-REM-REG-004"]["status_match"])

        # Check secret redaction across all evidence
        for ev in evidence:
            req_headers = ev.get("request_info", {}).get("headers", {})
            if "Authorization" in req_headers:
                self.assertEqual(req_headers["Authorization"], "[REDACTED]")

    def test_sqlite_persistence_and_retrieval(self):
        """Ensures remediation records are persisted into SQLite and retrievable via helper."""
        demo_app_instance.state.vulnerable_mode = True

        res = apply_demo_remediation(
            finding_id="WG-AC-004",
            target_url="http://127.0.0.1:8001",
            client=self.demo_client,
            db_path=self.scanner_db
        )

        verification_id = res["verification_id"]
        record = get_remediation_record(verification_id, db_path=self.scanner_db)

        self.assertIsNotNone(record)
        self.assertEqual(record["verification_id"], verification_id)
        self.assertEqual(record["finding_id"], "WG-AC-004")
        self.assertEqual(record["verification_status"], "verified")
        self.assertEqual(record["pre_remediation_status"], 200)
        self.assertEqual(record["post_remediation_status"], 403)
        self.assertEqual(len(record["evidence"]), 4)

        # Retrieval of non-existent ID returns None
        self.assertIsNone(get_remediation_record(99999, db_path=self.scanner_db))

    def test_api_endpoints_remediation_demo(self):
        """Tests POST /remediation/demo/apply and GET /remediation/{id} HTTP endpoints."""
        demo_app_instance.state.vulnerable_mode = True

        def mock_apply(finding_id="WG-AC-004", target_url="http://127.0.0.1:8001"):
            return apply_demo_remediation(
                finding_id=finding_id,
                target_url=target_url,
                client=self.demo_client,
                db_path=self.scanner_db
            )

        def mock_get(verification_id):
            return get_remediation_record(verification_id, db_path=self.scanner_db)

        # Use test client against scanner app with patched apply_demo_remediation
        with patch("backend.main.apply_demo_remediation", side_effect=mock_apply):
            with patch("backend.main.get_remediation_record", side_effect=mock_get):
                # 1. Trigger POST /remediation/demo/apply
                post_resp = self.scanner_client.post(
                    "/remediation/demo/apply",
                    json={"finding_id": "WG-AC-004", "target_url": "http://127.0.0.1:8001"}
                )
                self.assertEqual(post_resp.status_code, 200)
                data = post_resp.json()

                self.assertIn("verification_id", data)
                verification_id = data["verification_id"]
                self.assertEqual(data["finding_id"], "WG-AC-004")
                self.assertEqual(data["verification_status"], "verified")
                self.assertEqual(data["pre_remediation_status"], 200)
                self.assertEqual(data["post_remediation_status"], 403)
                self.assertEqual(data["admin_regression_status"], "passed")
                self.assertEqual(len(data["evidence"]), 4)

                # 2. Trigger GET /remediation/{verification_id}
                get_resp = self.scanner_client.get(f"/remediation/{verification_id}")
                self.assertEqual(get_resp.status_code, 200)
                get_data = get_resp.json()

                self.assertEqual(get_data["verification_id"], verification_id)
                self.assertEqual(get_data["finding_id"], "WG-AC-004")
                self.assertEqual(get_data["verification_status"], "verified")

                # 3. Trigger GET /remediation/{nonexistent} -> 404
                not_found_resp = self.scanner_client.get("/remediation/99999")
                self.assertEqual(not_found_resp.status_code, 404)

    def test_api_rejects_unauthorized_target(self):
        """API rejects non-demo targets with 422 Unprocessable Entity."""
        bad_resp = self.scanner_client.post(
            "/remediation/demo/apply",
            json={"finding_id": "WG-AC-004", "target_url": "https://example.com"}
        )
        self.assertEqual(bad_resp.status_code, 422)

    def test_failed_verification_when_fix_fails(self):
        """If the fix does not remediate the issue (retest returns 200), verification_status is 'failed'."""
        demo_app_instance.state.vulnerable_mode = True

        # Simulate client where /api/admin/mode doesn't change vulnerability
        original_post = self.demo_client.post
        def mock_post(url, **kwargs):
            if url == "/api/admin/mode":
                # Intercept and do not change vulnerable mode
                return original_post(url, json={"vulnerable_mode": True})
            return original_post(url, **kwargs)

        with patch.object(self.demo_client, "post", side_effect=mock_post):
            res = apply_demo_remediation(
                finding_id="WG-AC-004",
                target_url="http://127.0.0.1:8001",
                client=self.demo_client,
                db_path=self.scanner_db
            )

            self.assertEqual(res["precondition_status"], "vulnerable_confirmed")
            self.assertEqual(res["pre_remediation_status"], 200)
            self.assertEqual(res["post_remediation_status"], 200)
            self.assertEqual(res["verification_status"], "failed")
            self.assertIn("Remediation failed", res["message"])

    def test_admin_regression_failure(self):
        """If the fix inadvertently breaks Admin legitimate access (returns 403), verification fails."""
        demo_app_instance.state.vulnerable_mode = True

        original_get = self.demo_client.get
        call_count = {"get_admin": 0}

        def mock_get(url, **kwargs):
            if url == "/api/admin":
                call_count["get_admin"] += 1
                if call_count["get_admin"] == 1:
                    # 1. Precondition (Normal User): 200
                    return original_get(url, **kwargs)
                elif call_count["get_admin"] == 2:
                    # 2. Retest (Normal User): 403
                    return original_get(url, **kwargs)
                elif call_count["get_admin"] == 3:
                    # 3. Admin regression check: simulate accidental regression (403)
                    class MockResponse:
                        status_code = 403
                        def json(self):
                            return {"detail": "Forbidden"}
                    return MockResponse()
            return original_get(url, **kwargs)

        with patch.object(self.demo_client, "get", side_effect=mock_get):
            res = apply_demo_remediation(
                finding_id="WG-AC-004",
                target_url="http://127.0.0.1:8001",
                client=self.demo_client,
                db_path=self.scanner_db
            )

            self.assertEqual(res["admin_regression_status"], "failed")
            self.assertNotEqual(res["verification_status"], "verified")

    def test_non_remediation_scan_rejected_by_getter(self):
        """get_remediation_record ignores regular scan records that are not remediation verifications."""
        from backend.database import save_scan
        normal_scan_id = save_scan(
            target="http://example.com",
            risk_summary={"risk_level": "Low", "total_findings": 0, "severity_counts": {}},
            findings=[],
            raw_results={"record_type": "standard_scan"},
            db_path=self.scanner_db
        )

        record = get_remediation_record(normal_scan_id, db_path=self.scanner_db)
        self.assertIsNone(record)


if __name__ == "__main__":
    unittest.main()

