import unittest
import os
import tempfile
import json
from unittest.mock import patch
from fastapi.testclient import TestClient

from demo_app.main import app as demo_app_instance
from demo_app.database import init_demo_db
from backend.main import app as scanner_app_instance
from backend.database import init_db
from backend.assessments import (
    run_auth_assessment,
    run_authorization_assessment,
    run_demo_assessment,
    reset_demo_target_mode,
    validate_demo_target,
    redact_text,
    sanitize_headers,
    sanitize_payload
)


class TestAssessments(unittest.TestCase):
    def setUp(self):
        # Isolated temporary databases for scanner and demo app
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scanner_db = os.path.join(self.temp_dir.name, "test_scanner.db")
        self.demo_db = os.path.join(self.temp_dir.name, "test_demo.db")

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

    def test_evidence_secret_redaction(self):
        # 1. Header redaction
        headers = {
            "Authorization": "Bearer demo-token-user-abc-12345",
            "X-Demo-Token": "secret_demo_token_xyz",
            "Content-Type": "application/json"
        }
        sanitized_h = sanitize_headers(headers)
        self.assertEqual(sanitized_h["Authorization"], "[REDACTED]")
        self.assertEqual(sanitized_h["X-Demo-Token"], "[REDACTED]")
        self.assertEqual(sanitized_h["Content-Type"], "application/json")

        # 2. Payload redaction
        payload = {
            "username": "user_demo",
            "password": "demo_user_password",
            "nested": {"token": "my_secret_token", "info": "safe"}
        }
        sanitized_p = sanitize_payload(payload)
        self.assertEqual(sanitized_p["password"], "[REDACTED]")
        self.assertEqual(sanitized_p["nested"]["token"], "[REDACTED]")
        self.assertEqual(sanitized_p["nested"]["info"], "safe")

        # 3. Text redaction
        raw_text = "Bearer demo-token-user_demo-abcdef123456"
        redacted = redact_text(raw_text)
        self.assertNotIn("abcdef123456", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_target_boundary_validation(self):
        # Allowed local demo targets
        self.assertEqual(validate_demo_target("http://127.0.0.1:8001"), "http://127.0.0.1:8001")
        self.assertEqual(validate_demo_target("http://localhost:8001"), "http://localhost:8001")

        # Prohibited targets
        prohibited = [
            "http://192.168.1.1:8001",
            "https://google.com",
            "http://127.0.0.1:8000",
            "http://localhost:3000",
            "ftp://127.0.0.1:8001",
            "http://internal.company.lan:8001"
        ]
        for target in prohibited:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    validate_demo_target(target)

    def test_auth_assessment_direct(self):
        res = run_auth_assessment(client=self.demo_client)
        self.assertIsNotNone(res["user_token"])
        self.assertIsNotNone(res["admin_token"])
        self.assertEqual(len(res["findings"]), 0)

        ev_ids = [e["evidence_id"] for e in res["evidence"]]
        self.assertIn("WG-AUTH-001", ev_ids)
        self.assertIn("WG-AUTH-002", ev_ids)
        self.assertIn("WG-AUTH-003", ev_ids)
        self.assertIn("WG-AUTH-005", ev_ids)
        self.assertIn("WG-AUTH-006", ev_ids)
        self.assertEqual(len(res["evidence"]), 5)

        # Check no tokens in evidence
        for e in res["evidence"]:
            h = e["request_info"]["headers"]
            if "Authorization" in h:
                self.assertEqual(h["Authorization"], "[REDACTED]")
            self.assertNotIn("invalid_demo_token_99999", str(e))

    def test_authorization_assessment_vulnerable_mode(self):
        # In vulnerable mode, Normal User accessing /api/admin generates High finding
        demo_app_instance.state.vulnerable_mode = True
        auth_res = run_auth_assessment(client=self.demo_client)

        authz_res = run_authorization_assessment(
            client=self.demo_client,
            user_token=auth_res["user_token"],
            admin_token=auth_res["admin_token"]
        )

        self.assertEqual(len(authz_res["findings"]), 1)
        finding = authz_res["findings"][0]

        self.assertIn("Broken Access Control", finding["title"])
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["category"], "Authorization / Access Control")
        self.assertEqual(finding["severity_method"], "WorldGuard prototype rule")
        self.assertEqual(finding["cwe_id"], "CWE-862")
        self.assertEqual(finding["evidence_id"], "WG-AC-004")

        # Verify all evidence records exist
        ev_ids = [e["evidence_id"] for e in authz_res["evidence"]]
        self.assertIn("WG-AC-001", ev_ids)
        self.assertIn("WG-AC-002", ev_ids)
        self.assertIn("WG-AC-003", ev_ids)
        self.assertIn("WG-AC-004", ev_ids)

    def test_authorization_assessment_secure_mode(self):
        # In fixed/secure mode, Normal User is denied (403) and 0 findings are produced
        demo_app_instance.state.vulnerable_mode = False
        auth_res = run_auth_assessment(client=self.demo_client)

        authz_res = run_authorization_assessment(
            client=self.demo_client,
            user_token=auth_res["user_token"],
            admin_token=auth_res["admin_token"]
        )

        self.assertEqual(len(authz_res["findings"]), 0)

        # Verify WG-AC-004 observed status is 403 (matches expected)
        wg_ac_004 = next(e for e in authz_res["evidence"] if e["evidence_id"] == "WG-AC-004")
        self.assertEqual(wg_ac_004["observed_status"], 403)
        self.assertTrue(wg_ac_004["status_match"])

    def test_assessment_runner_coordination(self):
        demo_app_instance.state.vulnerable_mode = True
        result = run_demo_assessment(
            target_url="http://127.0.0.1:8001",
            client=self.demo_client
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["tests_run"], 12)
        self.assertEqual(result["risk_summary"]["risk_level"], "High")
        self.assertEqual(result["risk_summary"]["total_findings"], 4)
        self.assertEqual(
            result["risk_summary"]["severity_counts"],
            {"Critical": 0, "High": 2, "Medium": 1, "Low": 0, "Info": 1}
        )
        self.assertEqual(len(result["findings"]), 4)
        finding_ids = {f["evidence_id"] for f in result["findings"]}
        self.assertEqual(finding_ids, {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"})
        self.assertEqual(len(result["evidence"]), result["tests_run"])

    def test_api_endpoints_assessment_demo(self):
        demo_app_instance.state.vulnerable_mode = True

        # Helper to route assessment runner through demo_client
        def mock_runner(target_url="http://127.0.0.1:8001"):
            return run_demo_assessment(target_url=target_url, client=self.demo_client)

        with patch("backend.main.run_demo_assessment", side_effect=mock_runner):
            # 1. Trigger POST /assessment/demo
            post_resp = self.scanner_client.post("/assessment/demo", json={"target_url": "http://127.0.0.1:8001"})
            self.assertEqual(post_resp.status_code, 200)

            data = post_resp.json()
            self.assertIn("assessment_id", data)
            assessment_id = data["assessment_id"]
            self.assertEqual(data["status"], "completed")
            self.assertEqual(data["risk_summary"]["risk_level"], "High")
            self.assertEqual(data["risk_summary"]["total_findings"], 4)
            self.assertEqual(data["tests_run"], 12)
            self.assertEqual(len(data["findings"]), 4)
            self.assertEqual(
                {f["evidence_id"] for f in data["findings"]},
                {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"}
            )
            self.assertEqual(len(data["evidence"]), 12)

            # 2. Retrieve via GET /assessment/{assessment_id}
            get_resp = self.scanner_client.get(f"/assessment/{assessment_id}")
            self.assertEqual(get_resp.status_code, 200)
            get_data = get_resp.json()

            self.assertEqual(get_data["assessment_id"], assessment_id)
            self.assertEqual(get_data["risk_level"], "High")
            self.assertEqual(len(get_data["findings"]), 4)
            self.assertEqual(
                {f["evidence_id"] for f in get_data["findings"]},
                {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"}
            )
            self.assertEqual(len(get_data["evidence"]), 12)

            # 3. Nonexistent assessment returns 404
            not_found_resp = self.scanner_client.get("/assessment/99999")
            self.assertEqual(not_found_resp.status_code, 404)

    def test_api_rejects_unauthorized_target(self):
        # External or non-demo targets are rejected by Pydantic validator with 422
        bad_resp = self.scanner_client.post("/assessment/demo", json={"target_url": "https://example.com"})
        self.assertEqual(bad_resp.status_code, 422)

    def test_reset_demo_target_mode_authorized_and_unauthorized(self):
        # 1. Target reset succeeds on authorized demo target
        demo_app_instance.state.vulnerable_mode = False
        success = reset_demo_target_mode("http://127.0.0.1:8001", client=self.demo_client)
        self.assertTrue(success)
        self.assertTrue(demo_app_instance.state.vulnerable_mode)

        # 2. Reset strictly rejects unauthorized target
        with self.assertRaises(ValueError):
            reset_demo_target_mode("http://external-victim.org:8001", client=self.demo_client)

    def test_run_demo_assessment_resets_fixed_target(self):
        # Even if target application was left in fixed mode, demo assessment resets to vulnerable
        demo_app_instance.state.vulnerable_mode = False
        self.assertFalse(demo_app_instance.state.vulnerable_mode)

        result = run_demo_assessment(
            target_url="http://127.0.0.1:8001",
            client=self.demo_client,
            reset_mode=True
        )

        self.assertTrue(demo_app_instance.state.vulnerable_mode)
        self.assertEqual(result["risk_summary"]["risk_level"], "High")
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(
            {f["evidence_id"] for f in result["findings"]},
            {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"}
        )
        self.assertEqual(result["tests_run"], 12)
        self.assertEqual(len(result["evidence"]), 12)

    def test_run_demo_assessment_reset_mode_disabled(self):
        # If reset_mode is explicitly disabled, target remains fixed (WG-AC-004 eliminated, remaining 3 findings reported)
        demo_app_instance.state.vulnerable_mode = False
        result = run_demo_assessment(
            target_url="http://127.0.0.1:8001",
            client=self.demo_client,
            reset_mode=False
        )

        self.assertFalse(demo_app_instance.state.vulnerable_mode)
        self.assertEqual(result["risk_summary"]["risk_level"], "High")
        self.assertEqual(len(result["findings"]), 3)
        self.assertEqual(
            {f["evidence_id"] for f in result["findings"]},
            {"WG-SEC-001", "WG-API-001", "WG-AUTH-004"}
        )
        self.assertNotIn("WG-AC-004", {f["evidence_id"] for f in result["findings"]})
        self.assertEqual(result["tests_run"], 12)

    def test_demo_workflow_lifecycle_assessment_remediation_reassessment(self):
        from backend.remediation.service import apply_demo_remediation

        def mock_runner(target_url="http://127.0.0.1:8001"):
            return run_demo_assessment(target_url=target_url, client=self.demo_client)

        with patch("backend.main.run_demo_assessment", side_effect=mock_runner):
            # Step A: Target starts in fixed mode
            demo_app_instance.state.vulnerable_mode = False

            # Step B: Run initial demo assessment -> automatically resets to vulnerable mode
            resp1 = self.scanner_client.post("/assessment/demo", json={"target_url": "http://127.0.0.1:8001"})
            self.assertEqual(resp1.status_code, 200)
            data1 = resp1.json()
            scan_id_1 = data1["assessment_id"]
            self.assertEqual(data1["risk_summary"]["risk_level"], "High")
            self.assertEqual(len(data1["findings"]), 4)
            self.assertEqual(
                {f["evidence_id"] for f in data1["findings"]},
                {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"}
            )
            self.assertTrue(demo_app_instance.state.vulnerable_mode)

            # Step C: Apply remediation fix -> target is secured (vulnerable_mode = False)
            rem_res = apply_demo_remediation(
                finding_id="WG-AC-004",
                target_url="http://127.0.0.1:8001",
                client=self.demo_client,
                db_path=self.scanner_db,
                assessment_id=scan_id_1
            )
            self.assertEqual(rem_res["verification_status"], "verified")
            self.assertFalse(demo_app_instance.state.vulnerable_mode)

            # Step D: Run SECOND demo assessment -> must NOT remain stuck in fixed mode; resets to 4 findings!
            resp2 = self.scanner_client.post("/assessment/demo", json={"target_url": "http://127.0.0.1:8001"})
            self.assertEqual(resp2.status_code, 200)
            data2 = resp2.json()
            self.assertEqual(data2["risk_summary"]["risk_level"], "High")
            self.assertEqual(len(data2["findings"]), 4)
            self.assertEqual(
                {f["evidence_id"] for f in data2["findings"]},
                {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"}
            )
            self.assertEqual(data2["tests_run"], 12)
            self.assertTrue(demo_app_instance.state.vulnerable_mode)

    def test_configuration_assessments_individual_vectors(self):
        from backend.assessments.configuration_tests import (
            run_security_headers_assessment,
            run_api_docs_assessment,
            run_root_credential_exposure_assessment,
        )

        # 1. WG-SEC-001
        h_res = run_security_headers_assessment(self.demo_client)
        self.assertEqual(len(h_res["findings"]), 1)
        self.assertEqual(h_res["findings"][0]["evidence_id"], "WG-SEC-001")
        self.assertEqual(h_res["findings"][0]["severity"], "Medium")
        self.assertEqual(h_res["findings"][0]["cwe_id"], "CWE-693")

        # 2. WG-API-001
        a_res = run_api_docs_assessment(self.demo_client)
        self.assertEqual(len(a_res["findings"]), 1)
        self.assertEqual(a_res["findings"][0]["evidence_id"], "WG-API-001")
        self.assertEqual(a_res["findings"][0]["severity"], "Info")
        self.assertEqual(a_res["findings"][0]["cwe_id"], "CWE-200")

        # 3. WG-AUTH-004
        c_res = run_root_credential_exposure_assessment(self.demo_client)
        self.assertEqual(len(c_res["findings"]), 1)
        self.assertEqual(c_res["findings"][0]["evidence_id"], "WG-AUTH-004")
        self.assertEqual(c_res["findings"][0]["severity"], "High")
        self.assertEqual(c_res["findings"][0]["cwe_id"], "CWE-200")

        # Verify zero password strings in evidence
        import json
        ev_str = json.dumps(c_res["evidence"])
        self.assertNotIn("demo_admin_password", ev_str)
        self.assertNotIn("demo_user_password", ev_str)

    def test_phase12b_finding_details_and_safe_poc(self):
        """
        Phase 12B Test Suite:
        Validates that all four findings provide structured affected_component,
        expected_behavior, observed_behavior, and non-empty steps_to_reproduce.
        Ensures strict sanitization with zero passwords or plain tokens.
        """
        import json
        res = run_demo_assessment(client=self.demo_client)
        findings = res["findings"]
        evidence = res["evidence"]

        self.assertEqual(len(findings), 4)
        findings_by_id = {f["evidence_id"]: f for f in findings}

        expected_ev_ids = {"WG-AC-004", "WG-AUTH-004", "WG-SEC-001", "WG-API-001"}
        self.assertEqual(set(findings_by_id.keys()), expected_ev_ids)

        # Expected severities
        self.assertEqual(findings_by_id["WG-AC-004"]["severity"], "High")
        self.assertEqual(findings_by_id["WG-AUTH-004"]["severity"], "High")
        self.assertEqual(findings_by_id["WG-SEC-001"]["severity"], "Medium")
        self.assertEqual(findings_by_id["WG-API-001"]["severity"], "Info")

        # Verify structured PoC fields for all 4 findings
        for ev_id, finding in findings_by_id.items():
            self.assertIn("affected_component", finding, f"{ev_id} missing affected_component")
            self.assertIsInstance(finding["affected_component"], str)
            self.assertTrue(len(finding["affected_component"]) > 0)

            self.assertIn("expected_behavior", finding, f"{ev_id} missing expected_behavior")
            self.assertIsInstance(finding["expected_behavior"], str)
            self.assertTrue(len(finding["expected_behavior"]) > 0)

            self.assertIn("observed_behavior", finding, f"{ev_id} missing observed_behavior")
            self.assertIsInstance(finding["observed_behavior"], str)
            self.assertTrue(len(finding["observed_behavior"]) > 0)

            self.assertIn("steps_to_reproduce", finding, f"{ev_id} missing steps_to_reproduce")
            self.assertIsInstance(finding["steps_to_reproduce"], list, f"{ev_id} steps_to_reproduce is not a list")
            self.assertTrue(len(finding["steps_to_reproduce"]) > 0, f"{ev_id} steps_to_reproduce is empty")
            for step in finding["steps_to_reproduce"]:
                self.assertIsInstance(step, str)
                self.assertTrue(len(step) > 0)

        # Verify specific expected components
        self.assertEqual(findings_by_id["WG-AC-004"]["affected_component"], "Admin Access Guard")
        self.assertEqual(findings_by_id["WG-AUTH-004"]["affected_component"], "Public Landing Controller")
        self.assertEqual(findings_by_id["WG-SEC-001"]["affected_component"], "Security Headers Middleware")
        self.assertEqual(findings_by_id["WG-API-001"]["affected_component"], "OpenAPI Documentation Route")

        # Verify zero password or bearer token leakage across all findings and evidence
        findings_json = json.dumps(findings)
        evidence_json = json.dumps(evidence)

        self.assertNotIn("demo_admin_password", findings_json)
        self.assertNotIn("demo_user_password", findings_json)
        self.assertNotIn("demo_admin_password", evidence_json)
        self.assertNotIn("demo_user_password", evidence_json)

        # Verify no unredacted demo tokens in evidence headers
        for ev in evidence:
            req_info = ev.get("request_info", {})
            headers = req_info.get("headers", {})
            if "Authorization" in headers:
                self.assertEqual(headers["Authorization"], "[REDACTED]")

    def test_phase12d_missing_auth_token_check_wg_auth_005(self):
        """Verifies WG-AUTH-005 sends no auth headers, expects 401, and passes on demo app."""
        res = run_auth_assessment(client=self.demo_client)
        ev_wg_005 = next(e for e in res["evidence"] if e["evidence_id"] == "WG-AUTH-005")

        self.assertEqual(ev_wg_005["method"], "GET")
        self.assertEqual(ev_wg_005["endpoint"], "/api/auth/me")
        self.assertEqual(ev_wg_005["expected_status"], 401)
        self.assertEqual(ev_wg_005["observed_status"], 401)
        self.assertTrue(ev_wg_005["status_match"])
        self.assertEqual(ev_wg_005["test_role"], "Unauthenticated")
        self.assertEqual(ev_wg_005["request_info"]["headers"], {})

        # Confirms no finding is generated since observed == 401
        self.assertNotIn("WG-AUTH-005", {f.get("evidence_id") for f in res["findings"]})

    def test_phase12d_invalid_auth_token_check_wg_auth_006(self):
        """Verifies WG-AUTH-006 sends invalid synthetic token, expects 401, and passes on demo app."""
        res = run_auth_assessment(client=self.demo_client)
        ev_wg_006 = next(e for e in res["evidence"] if e["evidence_id"] == "WG-AUTH-006")

        self.assertEqual(ev_wg_006["method"], "GET")
        self.assertEqual(ev_wg_006["endpoint"], "/api/auth/me")
        self.assertEqual(ev_wg_006["expected_status"], 401)
        self.assertEqual(ev_wg_006["observed_status"], 401)
        self.assertTrue(ev_wg_006["status_match"])
        self.assertEqual(ev_wg_006["test_role"], "Unauthenticated")

        # Confirms no finding is generated since observed == 401
        self.assertNotIn("WG-AUTH-006", {f.get("evidence_id") for f in res["findings"]})

    def test_phase12d_evidence_sanitization_no_raw_invalid_token(self):
        """Verifies the actual invalid token string is never present in persisted evidence."""
        res = run_auth_assessment(client=self.demo_client)
        ev_wg_006 = next(e for e in res["evidence"] if e["evidence_id"] == "WG-AUTH-006")

        # Must sanitize Authorization header
        self.assertEqual(ev_wg_006["request_info"]["headers"]["Authorization"], "[REDACTED]")
        # Raw token must not appear in any serialized field
        dumped_evidence = json.dumps(res["evidence"])
        self.assertNotIn("invalid_demo_token_99999", dumped_evidence)

    def test_phase12d_total_assessment_metrics(self):
        """Verifies exactly 12 deterministic tests, 4 baseline findings, and unchanged severity counts."""
        result = run_demo_assessment(client=self.demo_client)
        self.assertEqual(result["tests_run"], 12)
        self.assertEqual(len(result["evidence"]), 12)
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(
            {f["evidence_id"] for f in result["findings"]},
            {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"}
        )
        self.assertEqual(
            result["risk_summary"]["severity_counts"],
            {"Critical": 0, "High": 2, "Medium": 1, "Low": 0, "Info": 1}
        )


if __name__ == "__main__":
    unittest.main()

