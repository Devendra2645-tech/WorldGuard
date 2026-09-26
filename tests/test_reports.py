"""
Unit and Integration Tests for WorldGuard Security Reports (Phase 11).
Tests JSON export, PDF generation, API endpoints, secret sanitization,
remediation verification proof, and non-authoritative AI advisory labeling.
"""

import os
import tempfile
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.database.database import (
    init_db,
    save_scan,
    get_scan_by_id,
    save_assessment_ai_summary,
)
from backend.reports import (
    build_security_report_data,
    generate_pdf_report,
)


class TestSecurityReports(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_reports.db")
        init_db(self.db_path)
        self.client = TestClient(app)

        # Seed sample assessment record
        self.scan_id = save_scan(
            target="http://127.0.0.1:8001",
            risk_summary={
                "risk_level": "High",
                "total_findings": 1,
                "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0}
            },
            findings=[{
                "title": "Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)",
                "severity": "High",
                "category": "Authorization / Access Control",
                "description": "A Normal User was able to access an administrative endpoint.",
                "evidence_id": "WG-AC-004",
                "cwe_id": "CWE-862",
                "owasp_category": "A01:2021 - Broken Access Control",
                "affected_role": "Normal User",
                "data_sensitivity": "Confidential",
                "exploitability": "High",
                "confidentiality_impact": "High",
                "integrity_impact": "High",
                "availability_impact": "Low",
                "business_impact": "Unauthorized normal users can access sensitive administrative data.",
                "remediation": "Enforce server-side role check require_role('admin') on /api/admin.",
                "remediation_priority": "P1 - High",
                "verification_status": "unverified"
            }],
            raw_results={
                "tests_run": 7,
                "evidence": [{
                    "evidence_id": "WG-AC-004",
                    "test_name": "Normal User Privilege Escalation",
                    "test_role": "Normal User",
                    "method": "GET",
                    "endpoint": "/api/admin",
                    "expected_status": 403,
                    "observed_status": 200,
                    "vulnerable": True,
                    "request_headers": {
                        "Authorization": "Bearer sensitive_jwt_token_12345",
                        "X-Demo-Token": "demo-token-secret-9999",
                        "Accept": "application/json"
                    },
                    "request_body": {"password": "super_secret_user_password"},
                    "response_body": {"status": "ok", "admin_data": "secret_dashboard"}
                }]
            },
            db_path=self.db_path
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_json_report_structure_and_metadata(self):
        """Validates that JSON security report compiles complete, well-formed metadata and findings."""
        report = build_security_report_data(self.scan_id, db_path=self.db_path)

        # 1. Metadata
        self.assertIn("report_metadata", report)
        meta = report["report_metadata"]
        self.assertEqual(meta["assessment_id"], self.scan_id)
        self.assertTrue(meta["report_id"].startswith("WGR-"))
        self.assertEqual(meta["engine_version"], "1.0.0")
        self.assertIn("CONFIDENTIAL", meta["classification"])
        self.assertIn("disclaimer", meta)

        # 2. Target Scope
        self.assertIn("target", report)
        target = report["target"]
        self.assertEqual(target["url"], "http://127.0.0.1:8001")
        self.assertEqual(target["scope_boundary"], "Authorized Local Demo Application")

        # 3. Executive Summary
        self.assertIn("executive_summary", report)
        summary = report["executive_summary"]
        self.assertEqual(summary["overall_risk_level"], "High")
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["severity_distribution"]["High"], 1)
        self.assertEqual(summary["tests_executed"], 7)
        self.assertIn("No numerical CVSS score is assigned", summary["risk_model_note"])

        # 4. Findings
        self.assertIn("findings", report)
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["evidence_id"], "WG-AC-004")
        self.assertEqual(finding["cwe_id"], "CWE-862")
        self.assertEqual(finding["owasp_category"], "A01:2021 - Broken Access Control")
        self.assertEqual(finding["remediation_priority"], "P1 - High")
        self.assertEqual(finding["impact_vectors"]["confidentiality"], "High")
        self.assertEqual(finding["impact_vectors"]["integrity"], "High")
        self.assertIn("administrative data", finding["business_impact"])
        self.assertIn("require_role", finding["technical_remediation"])

    def test_evidence_secret_redaction_in_report(self):
        """Verifies that credentials, tokens, cookies, and passwords are unconditionally redacted in report evidence."""
        report = build_security_report_data(self.scan_id, db_path=self.db_path)
        finding = report["findings"][0]
        evidence = finding["evidence"][0]

        # Verify Authorization header is redacted
        headers = evidence.get("request_headers", {})
        self.assertEqual(headers.get("Authorization"), "[REDACTED]")
        self.assertEqual(headers.get("X-Demo-Token"), "[REDACTED]")
        self.assertEqual(headers.get("Accept"), "application/json")

        # Verify password in request body is redacted
        req_body = evidence.get("request_body", {})
        self.assertEqual(req_body.get("password"), "[REDACTED]")

        # Ensure no raw secret leaked anywhere in serialized report JSON
        import json
        dumped = json.dumps(report)
        self.assertNotIn("sensitive_jwt_token_12345", dumped)
        self.assertNotIn("demo-token-secret-9999", dumped)
        self.assertNotIn("super_secret_user_password", dumped)

    def test_remediation_verification_report_integration(self):
        """Verifies that remediation verification data (before/after proof) is structured properly."""
        # Create a remediation verification record
        rem_scan_id = save_scan(
            target="http://127.0.0.1:8001 [Remediation Verification]",
            risk_summary={
                "risk_level": "Info",
                "total_findings": 0,
                "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 1}
            },
            findings=[{
                "title": "Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)",
                "severity": "Info",
                "category": "Remediation Verification",
                "description": "Remediation verified successfully: Normal User received HTTP 403 Forbidden.",
                "verification_status": "verified"
            }],
            raw_results={
                "record_type": "remediation_verification",
                "remediation_result": {
                    "verification_status": "verified",
                    "finding_id": "WG-AC-004",
                    "pre_remediation_status": 200,
                    "post_remediation_status": 403,
                    "admin_regression_status": "passed",
                    "message": "Normal User received HTTP 403 Forbidden and Admin access remains functional.",
                    "evidence": [{
                        "test_name": "Normal User Retest",
                        "method": "GET",
                        "endpoint": "/api/admin",
                        "expected_status": 403,
                        "observed_status": 403,
                        "vulnerable": False
                    }]
                }
            },
            db_path=self.db_path
        )

        report = build_security_report_data(rem_scan_id, db_path=self.db_path)
        self.assertIsNotNone(report["remediation_verification"])
        rem = report["remediation_verification"]
        self.assertEqual(rem["status"], "verified")
        self.assertEqual(rem["pre_remediation_status"], 200)
        self.assertEqual(rem["post_remediation_status"], 403)
        self.assertEqual(rem["admin_regression_status"], "passed")
        self.assertIn("Normal User received HTTP 403", rem["message"])

    def test_ai_advisory_labeling_and_demarcation(self):
        """Verifies that AI advisory is labeled as NON-AUTHORITATIVE and carries mandatory disclaimers."""
        save_assessment_ai_summary(
            self.scan_id,
            {
                "executive_summary": "Privilege escalation vulnerability requires immediate mitigation.",
                "analyst_summary": "Unrestricted administrative endpoint accessible by normal users.",
                "key_risks": ["Administrative takeover by standard user"],
                "immediate_actions": ["Deploy server-side role check"],
                "strategic_recommendations": ["Establish RBAC policy gate"],
                "compliance_notes": ["Fails OWASP A01 broken access control audit"],
                "model_used": "deterministic-fallback"
            },
            db_path=self.db_path
        )

        report = build_security_report_data(self.scan_id, db_path=self.db_path)
        self.assertIsNotNone(report["ai_advisory"])
        ai = report["ai_advisory"]
        self.assertEqual(ai["status"], "available")
        self.assertEqual(ai["label"], "AI-GENERATED ADVISORY — NON-AUTHORITATIVE")
        self.assertIn("NON-AUTHORITATIVE", ai["disclaimer"])
        self.assertIn("Privilege escalation", ai["executive_summary"])
        self.assertEqual(len(ai["key_risks"]), 1)
        self.assertEqual(len(ai["immediate_actions"]), 1)

    def test_pdf_report_binary_generation(self):
        """Verifies that ReportLab compiles a valid, non-empty binary PDF stream."""
        report = build_security_report_data(self.scan_id, db_path=self.db_path)
        pdf_bytes = generate_pdf_report(report)

        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(len(pdf_bytes) > 1000)
        # Standard PDF magic header
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))

    def test_api_endpoints_json_and_pdf(self):
        """Verifies GET /reports/{id}/json and GET /reports/{id}/pdf HTTP endpoints."""
        # Using real app with monkeypatched db_path or seeding prototype database
        from backend.database.database import get_db_path
        proto_db = get_db_path()
        init_db(proto_db)
        live_scan_id = save_scan(
            target="http://127.0.0.1:8001",
            risk_summary={"risk_level": "High", "total_findings": 1, "severity_counts": {"High": 1}},
            findings=[{"title": "Test Finding", "severity": "High", "category": "Auth"}],
            raw_results={"tests_run": 7, "evidence": []},
            db_path=proto_db
        )

        # 1. Test GET /reports/{id}/json
        resp_json = self.client.get(f"/reports/{live_scan_id}/json")
        self.assertEqual(resp_json.status_code, 200)
        data = resp_json.json()
        self.assertIn("report_metadata", data)
        self.assertIn("executive_summary", data)
        self.assertEqual(data["executive_summary"]["overall_risk_level"], "High")

        # 2. Test GET /reports/{id}/pdf
        resp_pdf = self.client.get(f"/reports/{live_scan_id}/pdf")
        self.assertEqual(resp_pdf.status_code, 200)
        self.assertEqual(resp_pdf.headers["content-type"], "application/pdf")
        self.assertIn(f"worldguard_report_{live_scan_id}.pdf", resp_pdf.headers["content-disposition"])
        self.assertTrue(resp_pdf.content.startswith(b"%PDF-"))

        # 3. Test 404 for nonexistent assessment ID
        resp_404_json = self.client.get("/reports/9999999/json")
        self.assertEqual(resp_404_json.status_code, 404)

    def test_remediation_workflow_and_consistent_report_generation(self):
        """
        Validates the complete remediation lifecycle report consistency (Requirement 10):
        A. Original assessment report: risk = HIGH, findings = 1, tests = 7
        B. After remediation: original finding is still present
        C. Finding status: VERIFIED
        D. Verification evidence: Normal User 200 -> 403, Admin 200 -> 200
        E. Report must NOT show risk = INFO, findings = 0, tests = 0 on remediated assessment
        F. Existing secret-redaction tests still pass
        """
        from demo_app.main import app as demo_app
        from demo_app.database import init_demo_db
        from backend.remediation.service import apply_demo_remediation

        demo_db_path = os.path.join(self.temp_dir.name, "test_demo_report.db")
        init_demo_db(demo_db_path)
        demo_app.state.vulnerable_mode = True
        demo_client = TestClient(demo_app)

        # 1. Create authoritative original assessment scan
        orig_scan_id = save_scan(
            target="http://127.0.0.1:8001",
            risk_summary={
                "risk_level": "High",
                "total_findings": 1,
                "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0}
            },
            findings=[{
                "title": "Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)",
                "severity": "High",
                "category": "Authorization / Access Control",
                "description": "A Normal User was able to access an administrative endpoint.",
                "evidence_id": "WG-AC-004",
                "cwe_id": "CWE-862",
                "owasp_category": "A01:2021 - Broken Access Control",
                "affected_role": "Normal User",
                "data_sensitivity": "Confidential",
                "exploitability": "High",
                "confidentiality_impact": "High",
                "integrity_impact": "High",
                "availability_impact": "Low",
                "business_impact": "Unauthorized normal users can access sensitive administrative data.",
                "remediation": "Enforce server-side role check require_role('admin') on /api/admin.",
                "remediation_priority": "P1 - High",
                "verification_status": "unverified"
            }],
            raw_results={
                "tests_run": 7,
                "evidence": [{
                    "evidence_id": "WG-AC-004",
                    "test_name": "Normal User Privilege Escalation",
                    "test_role": "Normal User",
                    "method": "GET",
                    "endpoint": "/api/admin",
                    "expected_status": 403,
                    "observed_status": 200,
                    "vulnerable": True
                }]
            },
            db_path=self.db_path
        )

        # Requirement 10.A: Original assessment report before remediation
        orig_report = build_security_report_data(orig_scan_id, db_path=self.db_path)
        self.assertEqual(orig_report["executive_summary"]["overall_risk_level"], "High")
        self.assertEqual(orig_report["executive_summary"]["total_findings"], 1)
        self.assertEqual(orig_report["executive_summary"]["tests_executed"], 7)
        self.assertEqual(len(orig_report["findings"]), 1)
        self.assertEqual(orig_report["findings"][0]["verification_status"], "unverified")
        self.assertIsNone(orig_report["remediation_verification"])

        # 2. Apply remediation and verification workflow
        rem_result = apply_demo_remediation(
            finding_id="WG-AC-004",
            target_url="http://127.0.0.1:8001",
            client=demo_client,
            db_path=self.db_path,
            assessment_id=orig_scan_id
        )
        self.assertEqual(rem_result["verification_status"], "verified")
        verification_scan_id = rem_result["verification_id"]

        # Requirements 10.B, 10.C, 10.D, 10.E:
        # Check that reports generated for BOTH orig_scan_id AND verification_scan_id are consistent
        for queried_id in (orig_scan_id, verification_scan_id):
            with self.subTest(queried_id=queried_id):
                report = build_security_report_data(queried_id, db_path=self.db_path)

                # Requirement 10.B: Original finding is still present in report
                self.assertEqual(len(report["findings"]), 1)
                finding = report["findings"][0]
                self.assertEqual(finding["evidence_id"], "WG-AC-004")
                self.assertEqual(finding["cwe_id"], "CWE-862")
                self.assertIn("Broken Access Control", finding["title"])

                # Requirement 10.C: Finding status is VERIFIED
                self.assertEqual(finding["verification_status"], "verified")

                # Requirement 10.D: Verification evidence
                self.assertIsNotNone(report["remediation_verification"])
                rem = report["remediation_verification"]
                self.assertEqual(rem["status"], "verified")
                self.assertEqual(rem["pre_remediation_status"], 200)
                self.assertEqual(rem["post_remediation_status"], 403)
                self.assertEqual(rem["admin_regression_status"], "passed")
                self.assertIn("Normal User received HTTP 403", rem["message"])

                # Requirement 10.E: Report must NOT show risk = INFO, findings = 0, tests = 0
                exec_sum = report["executive_summary"]
                self.assertEqual(exec_sum["overall_risk_level"], "High")
                self.assertNotEqual(exec_sum["overall_risk_level"], "Info")
                self.assertEqual(exec_sum["total_findings"], 1)
                self.assertNotEqual(exec_sum["total_findings"], 0)
                self.assertEqual(exec_sum["tests_executed"], 7)
                self.assertNotEqual(exec_sum["tests_executed"], 0)

                # Ensure PDF generates cleanly with this data
                pdf = generate_pdf_report(report)
                self.assertTrue(pdf.startswith(b"%PDF-"))
                self.assertTrue(len(pdf) > 2000)

        # Requirement 10.F: Secret-redaction verification
        dumped_json = str(report)
        self.assertNotIn("demo_user_password", dumped_json)
        self.assertNotIn("demo_admin_password", dumped_json)

    def test_fresh_demo_assessment_after_remediation_generates_correct_high_report(self):
        """
        Validates fix for issue where demo app left in fixed/remediated mode caused
        subsequent demonstration assessments to yield INFO / 0 findings.
        Verifies that running a new demo assessment resets the demo target to vulnerable,
        producing a valid HIGH / 1 finding / 7 tests assessment and report.
        """
        from demo_app.main import app as demo_app
        from demo_app.database import init_demo_db
        from backend.assessments import run_demo_assessment
        from backend.remediation.service import apply_demo_remediation

        demo_db_path = os.path.join(self.temp_dir.name, "test_demo_reassess.db")
        init_demo_db(demo_db_path)
        demo_client = TestClient(demo_app)

        # 1. Simulate prior state: demo app was left in remediated/fixed mode
        demo_app.state.vulnerable_mode = False

        # 2. Run fresh demo assessment (as triggered by POST /assessment/demo)
        result = run_demo_assessment(
            target_url="http://127.0.0.1:8001",
            client=demo_client,
            reset_mode=True
        )

        # Target should have been reset to vulnerable mode
        self.assertTrue(demo_app.state.vulnerable_mode)
        self.assertEqual(result["risk_summary"]["risk_level"], "High")
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(
            {f["evidence_id"] for f in result["findings"]},
            {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"}
        )
        self.assertEqual(result["tests_run"], 12)

        # Persist this fresh assessment
        new_scan_id = save_scan(
            target=f"{result['target']} [Demo Assessment]",
            risk_summary=result["risk_summary"],
            findings=result["findings"],
            raw_results={
                "assessment_type": "controlled_demo",
                "tests_run": result["tests_run"],
                "evidence": result["evidence"]
            },
            db_path=self.db_path
        )

        # 3. Generate report for this fresh assessment
        report = build_security_report_data(new_scan_id, db_path=self.db_path)
        exec_sum = report["executive_summary"]

        self.assertEqual(exec_sum["overall_risk_level"], "High")
        self.assertEqual(exec_sum["total_findings"], 4)
        self.assertEqual(exec_sum["severity_distribution"]["High"], 2)
        self.assertEqual(exec_sum["severity_distribution"]["Medium"], 1)
        self.assertEqual(exec_sum["severity_distribution"]["Info"], 1)
        self.assertEqual(exec_sum["tests_executed"], 12)
        self.assertEqual(len(report["findings"]), 4)
        report_f_ids = {f["evidence_id"] for f in report["findings"]}
        self.assertEqual(report_f_ids, {"WG-AC-004", "WG-SEC-001", "WG-API-001", "WG-AUTH-004"})
        wg_ac_finding = next(f for f in report["findings"] if f["evidence_id"] == "WG-AC-004")
        self.assertEqual(wg_ac_finding["verification_status"], "unverified")

        # 4. Now apply remediation to this assessment
        rem_result = apply_demo_remediation(
            finding_id="WG-AC-004",
            target_url="http://127.0.0.1:8001",
            client=demo_client,
            db_path=self.db_path,
            assessment_id=new_scan_id
        )
        self.assertEqual(rem_result["verification_status"], "verified")

        # 5. Report after remediation has verified status and retest proof
        rem_report = build_security_report_data(new_scan_id, db_path=self.db_path)
        self.assertEqual(rem_report["executive_summary"]["overall_risk_level"], "High")
        self.assertEqual(rem_report["executive_summary"]["total_findings"], 4)
        rem_wg_ac = next(f for f in rem_report["findings"] if f["evidence_id"] == "WG-AC-004")
        self.assertEqual(rem_wg_ac["verification_status"], "verified")
        self.assertIsNotNone(rem_report["remediation_verification"])
        self.assertEqual(rem_report["remediation_verification"]["status"], "verified")
        self.assertEqual(rem_report["remediation_verification"]["pre_remediation_status"], 200)
        self.assertEqual(rem_report["remediation_verification"]["post_remediation_status"], 403)

        pdf = generate_pdf_report(rem_report)
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertTrue(len(pdf) > 2000)

    def test_phase12b_report_poc_fields(self):
        """
        Validates that build_security_report_data enriches every finding entry with:
        - affected_component
        - expected_behavior
        - observed_behavior
        - steps_to_reproduce (non-empty list)
        And confirms that generate_pdf_report renders successfully with these blocks.
        """
        from demo_app.main import app as demo_app
        from backend.assessments import run_demo_assessment

        demo_client = TestClient(demo_app)
        demo_app.state.vulnerable_mode = True

        result = run_demo_assessment(client=demo_client)
        scan_id = save_scan(
            target=result["target"],
            risk_summary=result["risk_summary"],
            findings=result["findings"],
            raw_results={
                "tests_run": result["tests_run"],
                "evidence": result["evidence"]
            },
            db_path=self.db_path
        )

        report = build_security_report_data(scan_id, db_path=self.db_path)
        findings = report["findings"]
        self.assertEqual(len(findings), 4)

        for f in findings:
            ev_id = f["evidence_id"]
            self.assertIn("affected_component", f, f"{ev_id} missing affected_component")
            self.assertIsInstance(f["affected_component"], str)
            self.assertTrue(len(f["affected_component"]) > 0)

            self.assertIn("expected_behavior", f, f"{ev_id} missing expected_behavior")
            self.assertIsInstance(f["expected_behavior"], str)
            self.assertTrue(len(f["expected_behavior"]) > 0)

            self.assertIn("observed_behavior", f, f"{ev_id} missing observed_behavior")
            self.assertIsInstance(f["observed_behavior"], str)
            self.assertTrue(len(f["observed_behavior"]) > 0)

            self.assertIn("steps_to_reproduce", f, f"{ev_id} missing steps_to_reproduce")
            self.assertIsInstance(f["steps_to_reproduce"], list, f"{ev_id} steps_to_reproduce is not a list")
            self.assertTrue(len(f["steps_to_reproduce"]) > 0, f"{ev_id} steps_to_reproduce is empty")

        # Generate PDF and ensure it builds with all PoC tables
        pdf_bytes = generate_pdf_report(report)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertTrue(len(pdf_bytes) > 2000)


if __name__ == "__main__":
    unittest.main()
