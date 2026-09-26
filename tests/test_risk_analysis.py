import unittest
import os
import tempfile
from unittest.mock import patch
from fastapi.testclient import TestClient

from demo_app.main import app as demo_app_instance
from demo_app.database import init_demo_db
from backend.main import app as scanner_app_instance
from backend.database import init_db, save_scan, get_scan_by_id
from backend.analysis.risk import enrich_finding_risk, enrich_findings_risk
from backend.assessments import run_demo_assessment


class TestRiskAnalysis(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scanner_db = os.path.join(self.temp_dir.name, "test_scanner_risk.db")
        self.demo_db = os.path.join(self.temp_dir.name, "test_demo_risk.db")

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

    def test_enrich_finding_wg_ac_004(self):
        raw_finding = {
            "title": "Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)",
            "severity": "High",
            "category": "Authorization / Access Control",
            "description": "Normal User accessed /api/admin.",
            "cwe_id": "CWE-862",
            "owasp_category": "A01:2021-Broken Access Control",
            "evidence_id": "WG-AC-004",
            "endpoint": "/api/admin",
            "method": "GET",
            "tested_role": "Normal User",
            "remediation": "Enforce server-side role validation."
        }

        enriched = enrich_finding_risk(raw_finding)

        # 1. Verify required risk and business-impact fields
        self.assertEqual(enriched["severity"], "High")
        self.assertEqual(enriched["severity_method"], "WorldGuard prototype rule")
        self.assertEqual(enriched["exploitability"], "High")
        self.assertEqual(enriched["confidentiality_impact"], "High")
        self.assertEqual(enriched["integrity_impact"], "High")
        self.assertEqual(enriched["availability_impact"], "Low")
        self.assertEqual(enriched["affected_role"], "Normal User")
        self.assertEqual(
            enriched["data_sensitivity"],
            "Administrative system telemetry and restricted functionality"
        )
        self.assertEqual(
            enriched["business_impact"],
            "An authenticated user without administrative privileges may access restricted "
            "administrative functionality, creating a risk of unauthorized information access "
            "and unauthorized administrative actions."
        )
        self.assertEqual(enriched["remediation_priority"], "High")

        # 2. Verify preservation of existing fields
        self.assertEqual(enriched["title"], raw_finding["title"])
        self.assertEqual(enriched["category"], raw_finding["category"])
        self.assertEqual(enriched["description"], raw_finding["description"])
        self.assertEqual(enriched["cwe_id"], "CWE-862")
        self.assertEqual(enriched["owasp_category"], "A01:2021-Broken Access Control")
        self.assertEqual(enriched["evidence_id"], "WG-AC-004")
        self.assertEqual(enriched["endpoint"], "/api/admin")
        self.assertEqual(enriched["method"], "GET")
        self.assertEqual(enriched["tested_role"], "Normal User")
        self.assertEqual(enriched["remediation"], raw_finding["remediation"])

        # 3. Verify no numerical CVSS score was fabricated
        self.assertNotIn("cvss_score", enriched)
        self.assertNotIn("base_score", enriched)

    def test_enrich_findings_generic_fallback(self):
        generic_finding = {
            "title": "Missing Security Header",
            "severity": "Medium",
            "category": "Security Headers",
            "description": "CSP header missing."
        }
        enriched = enrich_finding_risk(generic_finding)

        self.assertEqual(enriched["severity"], "Medium")
        self.assertEqual(enriched["severity_method"], "WorldGuard prototype rule")
        self.assertIn("exploitability", enriched)
        self.assertIn("confidentiality_impact", enriched)
        self.assertIn("integrity_impact", enriched)
        self.assertIn("availability_impact", enriched)
        self.assertIn("affected_role", enriched)
        self.assertIn("data_sensitivity", enriched)
        self.assertIn("business_impact", enriched)
        self.assertIn("remediation_priority", enriched)

    def test_assessment_runner_produces_enriched_findings(self):
        demo_app_instance.state.vulnerable_mode = True
        result = run_demo_assessment(
            target_url="http://127.0.0.1:8001",
            client=self.demo_client
        )

        self.assertEqual(result["status"], "completed")
        self.assertGreaterEqual(len(result["findings"]), 1)

        bac_finding = next(
            f for f in result["findings"]
            if f.get("evidence_id") == "WG-AC-004"
        )

        self.assertEqual(bac_finding["severity"], "High")
        self.assertEqual(bac_finding["severity_method"], "WorldGuard prototype rule")
        self.assertEqual(bac_finding["exploitability"], "High")
        self.assertEqual(bac_finding["confidentiality_impact"], "High")
        self.assertEqual(bac_finding["integrity_impact"], "High")
        self.assertEqual(bac_finding["availability_impact"], "Low")
        self.assertEqual(bac_finding["affected_role"], "Normal User")
        self.assertEqual(bac_finding["remediation_priority"], "High")

    def test_sqlite_persistence_preserves_enriched_fields(self):
        demo_app_instance.state.vulnerable_mode = True
        result = run_demo_assessment(
            target_url="http://127.0.0.1:8001",
            client=self.demo_client
        )

        scan_id = save_scan(
            target="http://127.0.0.1:8001 [Demo Assessment]",
            risk_summary=result["risk_summary"],
            findings=result["findings"],
            raw_results={"evidence": result["evidence"]},
            db_path=self.scanner_db
        )

        # Retrieve saved scan from SQLite
        retrieved = get_scan_by_id(scan_id, db_path=self.scanner_db)
        self.assertIsNotNone(retrieved)
        self.assertEqual(len(retrieved["findings"]), len(result["findings"]))

        retrieved_bac = next(
            f for f in retrieved["findings"]
            if f.get("evidence_id") == "WG-AC-004"
        )

        # Confirm all enriched risk and business impact fields survived SQLite roundtrip
        self.assertEqual(retrieved_bac["severity"], "High")
        self.assertEqual(retrieved_bac["severity_method"], "WorldGuard prototype rule")
        self.assertEqual(retrieved_bac["exploitability"], "High")
        self.assertEqual(retrieved_bac["confidentiality_impact"], "High")
        self.assertEqual(retrieved_bac["integrity_impact"], "High")
        self.assertEqual(retrieved_bac["availability_impact"], "Low")
        self.assertEqual(retrieved_bac["affected_role"], "Normal User")
        self.assertEqual(
            retrieved_bac["data_sensitivity"],
            "Administrative system telemetry and restricted functionality"
        )
        self.assertIn("restricted administrative functionality", retrieved_bac["business_impact"])
        self.assertEqual(retrieved_bac["remediation_priority"], "High")

    def test_api_endpoints_expose_enriched_risk_analysis(self):
        demo_app_instance.state.vulnerable_mode = True

        def mock_runner(target_url="http://127.0.0.1:8001"):
            return run_demo_assessment(target_url=target_url, client=self.demo_client)

        with patch("backend.main.run_demo_assessment", side_effect=mock_runner):
            # 1. Trigger POST /assessment/demo
            post_resp = self.scanner_client.post(
                "/assessment/demo",
                json={"target_url": "http://127.0.0.1:8001"}
            )
            self.assertEqual(post_resp.status_code, 200)
            data = post_resp.json()

            self.assertIn("assessment_id", data)
            assessment_id = data["assessment_id"]

            post_finding = next(
                f for f in data["findings"]
                if f.get("evidence_id") == "WG-AC-004"
            )
            self.assertEqual(post_finding["severity"], "High")
            self.assertEqual(post_finding["exploitability"], "High")
            self.assertEqual(post_finding["confidentiality_impact"], "High")
            self.assertEqual(post_finding["integrity_impact"], "High")
            self.assertEqual(post_finding["availability_impact"], "Low")
            self.assertEqual(post_finding["affected_role"], "Normal User")
            self.assertEqual(post_finding["remediation_priority"], "High")

            # 2. Trigger GET /assessment/{assessment_id}
            get_resp = self.scanner_client.get(f"/assessment/{assessment_id}")
            self.assertEqual(get_resp.status_code, 200)
            get_data = get_resp.json()

            get_finding = next(
                f for f in get_data["findings"]
                if f.get("evidence_id") == "WG-AC-004"
            )
            self.assertEqual(get_finding["severity"], "High")
            self.assertEqual(get_finding["severity_method"], "WorldGuard prototype rule")
            self.assertEqual(get_finding["exploitability"], "High")
            self.assertEqual(get_finding["confidentiality_impact"], "High")
            self.assertEqual(get_finding["integrity_impact"], "High")
            self.assertEqual(get_finding["availability_impact"], "Low")
            self.assertEqual(get_finding["affected_role"], "Normal User")
            self.assertEqual(get_finding["remediation_priority"], "High")

    def test_enrich_findings_multi_vulnerabilities(self):
        from backend.analysis.risk import enrich_finding_risk

        # 1. WG-AUTH-004
        f_auth = enrich_finding_risk({"evidence_id": "WG-AUTH-004", "title": "Root Creds"})
        self.assertEqual(f_auth["severity"], "High")
        self.assertEqual(f_auth["exploitability"], "High")
        self.assertEqual(f_auth["confidentiality_impact"], "High")
        self.assertEqual(f_auth["integrity_impact"], "Medium")
        self.assertEqual(f_auth["remediation_priority"], "High")

        # 2. WG-SEC-001
        f_sec = enrich_finding_risk({"evidence_id": "WG-SEC-001", "title": "Headers"})
        self.assertEqual(f_sec["severity"], "Medium")
        self.assertEqual(f_sec["exploitability"], "Low")
        self.assertEqual(f_sec["confidentiality_impact"], "Low")
        self.assertEqual(f_sec["remediation_priority"], "Medium")

        # 3. WG-API-001
        f_api = enrich_finding_risk({"evidence_id": "WG-API-001", "title": "API Docs"})
        self.assertEqual(f_api["severity"], "Info")
        self.assertEqual(f_api["exploitability"], "Low")
        self.assertEqual(f_api["confidentiality_impact"], "Low")
        self.assertEqual(f_api["remediation_priority"], "Low")


if __name__ == "__main__":
    unittest.main()

