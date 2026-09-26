import unittest
import os
import json
import tempfile
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from demo_app.main import app as demo_app_instance
from demo_app.database import init_demo_db
from backend.main import app as scanner_app_instance
from backend.database import (
    init_db,
    save_scan,
    get_scan_by_id,
    get_finding_by_id,
    save_finding_ai_analysis,
    save_assessment_ai_summary
)
from backend.ai.models import FindingAIAnalysis, AssessmentAISummary
from backend.ai.prompts import (
    sanitize_finding_for_ai,
    sanitize_assessment_for_ai,
    build_finding_analysis_prompt,
    build_assessment_summary_prompt
)
from backend.ai.service import (
    generate_ai_finding_analysis,
    generate_ai_assessment_summary,
    build_fallback_finding_analysis,
    build_fallback_assessment_summary
)


class TestAIAnalysis(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scanner_db = os.path.join(self.temp_dir.name, "test_scanner_ai.db")
        self.demo_db = os.path.join(self.temp_dir.name, "test_demo_ai.db")

        os.environ["WORLD_MONITOR_DB_PATH"] = self.scanner_db
        os.environ["DEMO_APP_DB_PATH"] = self.demo_db
        os.environ["WORLDGUARD_AI_PROVIDER"] = "none"

        init_db(self.scanner_db)
        init_demo_db(self.demo_db)

        demo_app_instance.state.vulnerable_mode = True
        self.demo_client = TestClient(demo_app_instance)
        self.scanner_client = TestClient(scanner_app_instance)

        self.sample_finding = {
            "id": 1,
            "scan_id": 1,
            "title": "Broken Access Control: Unrestricted Administrative Endpoint (CWE-862)",
            "severity": "High",
            "category": "Authorization / Access Control",
            "description": "Normal User accessed /api/admin without admin role.",
            "cwe_id": "CWE-862",
            "owasp_category": "A01:2021-Broken Access Control",
            "evidence_id": "WG-AC-004",
            "endpoint": "/api/admin",
            "method": "GET",
            "tested_role": "Normal User",
            "affected_role": "Normal User",
            "remediation": "Enforce server-side role check.",
            "exploitability": "High",
            "confidentiality_impact": "High",
            "integrity_impact": "High",
            "availability_impact": "Low",
            "data_sensitivity": "Administrative system telemetry",
            "business_impact": "Unauthorized access to administrative control panel.",
            "remediation_priority": "High"
        }

        self.sample_assessment = {
            "id": 1,
            "target": "http://127.0.0.1:8001",
            "status": "completed",
            "tests_run": 7,
            "risk_summary": {
                "risk_level": "High",
                "total_findings": 1,
                "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0}
            },
            "findings": [self.sample_finding]
        }

    def tearDown(self):
        os.environ.pop("WORLD_MONITOR_DB_PATH", None)
        os.environ.pop("DEMO_APP_DB_PATH", None)
        os.environ.pop("WORLDGUARD_AI_PROVIDER", None)
        os.environ.pop("GEMINI_API_KEY", None)
        self.temp_dir.cleanup()

    def test_finding_ai_analysis_pydantic_validation(self):
        """Validates that FindingAIAnalysis schema validates proper fields and defaults."""
        analysis = FindingAIAnalysis(
            finding_id="WG-AC-004",
            title="Broken Access Control",
            explanation="Test explanation",
            business_impact="Test business impact",
            prioritization_rationale="Test rationale",
            remediation_guidance="Test guidance",
            verification_procedure="Test verification",
            generated_by="deterministic_fallback"
        )
        self.assertEqual(analysis.finding_id, "WG-AC-004")
        self.assertFalse(analysis.authoritative)
        self.assertEqual(analysis.disclaimer, "AI-GENERATED ADVISORY — NON-AUTHORITATIVE")
        # Ensure no CVSS attribute exists
        self.assertFalse(hasattr(analysis, "cvss_score"))
        self.assertFalse(hasattr(analysis, "base_score"))

    def test_assessment_ai_summary_pydantic_validation(self):
        """Validates that AssessmentAISummary schema validates correctly."""
        summary = AssessmentAISummary(
            assessment_id=1,
            target="http://127.0.0.1:8001",
            executive_summary="Leadership summary text",
            analyst_summary="Technical digest text",
            key_risks=["[HIGH] Broken Access Control"],
            recommended_actions=["Enforce server-side role validation"]
        )
        self.assertEqual(summary.assessment_id, 1)
        self.assertFalse(summary.authoritative)
        self.assertEqual(summary.disclaimer, "AI-GENERATED ADVISORY — NON-AUTHORITATIVE")
        self.assertFalse(hasattr(summary, "cvss_score"))

    def test_secret_sanitization_in_prompt_generation(self):
        """Ensures passwords, Bearer tokens, Authorization headers, and API keys are strictly redacted."""
        finding_with_secrets = dict(self.sample_finding)
        finding_with_secrets["authorization"] = "Bearer demo-token-secret-99999"
        finding_with_secrets["password"] = "SuperSecretPassword123!"
        finding_with_secrets["api_key"] = "my_secret_api_key_abc"
        finding_with_secrets["description"] = "User demo with Bearer secret-tok-123 accessed endpoint."

        sanitized = sanitize_finding_for_ai(finding_with_secrets)
        prompt = build_finding_analysis_prompt(finding_with_secrets)

        # Check raw secrets never leaked
        self.assertNotIn("demo-token-secret-99999", prompt)
        self.assertNotIn("SuperSecretPassword123!", prompt)
        self.assertNotIn("my_secret_api_key_abc", prompt)
        self.assertNotIn("secret-tok-123", prompt)

        # Confirm explicit prompt rules
        self.assertIn("SOURCE OF TRUTH", prompt)
        self.assertIn("Do NOT invent", prompt)
        self.assertIn("Do NOT generate, calculate, or mention numerical CVSS scores", prompt)

    def test_deterministic_fallback_when_no_provider_configured(self):
        """When WORLDGUARD_AI_PROVIDER is 'none' or unset, deterministic fallback is produced."""
        os.environ["WORLDGUARD_AI_PROVIDER"] = "none"
        analysis = generate_ai_finding_analysis(self.sample_finding)

        self.assertEqual(analysis.generated_by, "deterministic_fallback")
        self.assertFalse(analysis.authoritative)
        self.assertEqual(analysis.disclaimer, "AI-GENERATED ADVISORY — NON-AUTHORITATIVE")
        self.assertIn("GET /api/admin", analysis.explanation)
        self.assertIn("No numerical CVSS score is assigned", analysis.prioritization_rationale)
        self.assertIn("Depends(require_admin)", analysis.remediation_guidance)
        self.assertIn("403 Forbidden", analysis.verification_procedure)

    def test_deterministic_fallback_for_assessment_summary(self):
        """Assessment summary fallback generates accurate executive and analyst summaries without provider."""
        summary = generate_ai_assessment_summary(self.sample_assessment)

        self.assertEqual(summary.generated_by, "deterministic_fallback")
        self.assertFalse(summary.authoritative)
        self.assertIn("http://127.0.0.1:8001", summary.executive_summary)
        self.assertIn("HIGH", summary.executive_summary)
        self.assertIn("High: 1", summary.analyst_summary)
        self.assertTrue(len(summary.key_risks) >= 1)
        self.assertTrue(len(summary.recommended_actions) >= 1)

    def test_fallback_when_provider_fails(self):
        """When provider call fails (e.g. HTTP 500 or timeout), fallback is returned without crash."""
        os.environ["WORLDGUARD_AI_PROVIDER"] = "gemini"
        os.environ["GEMINI_API_KEY"] = "fake-test-key-not-real"

        with patch("backend.ai.service._call_gemini_api", side_effect=Exception("API connection timeout")):
            analysis = generate_ai_finding_analysis(self.sample_finding)
            self.assertEqual(analysis.generated_by, "deterministic_fallback")
            self.assertIn("GET /api/admin", analysis.explanation)

    def test_fallback_when_provider_returns_malformed_json(self):
        """When provider returns unparseable content, fallback handles it safely."""
        os.environ["WORLDGUARD_AI_PROVIDER"] = "gemini"
        os.environ["GEMINI_API_KEY"] = "fake-test-key-not-real"

        with patch("backend.ai.service._call_gemini_api", side_effect=ValueError("Invalid JSON from LLM")):
            summary = generate_ai_assessment_summary(self.sample_assessment)
            self.assertEqual(summary.generated_by, "deterministic_fallback")
            self.assertIn("executive_summary", summary.model_dump())

    def test_mock_successful_ai_response(self):
        """When AI provider succeeds, structured response is validated and marked as generated_by='ai'."""
        os.environ["WORLDGUARD_AI_PROVIDER"] = "gemini"
        os.environ["GEMINI_API_KEY"] = "fake-test-key-not-real"

        mock_llm_json = {
            "explanation": "Custom LLM explanation of broken access control.",
            "business_impact": "Custom LLM business impact analysis.",
            "prioritization_rationale": "High priority due to unauthenticated admin exposure.",
            "remediation_guidance": "Add role dependency in FastAPI.",
            "verification_procedure": "Retest with curl and verify 403 status."
        }

        with patch("backend.ai.service._call_gemini_api", return_value=mock_llm_json):
            analysis = generate_ai_finding_analysis(self.sample_finding)
            self.assertEqual(analysis.generated_by, "ai")
            self.assertFalse(analysis.authoritative)
            self.assertEqual(analysis.disclaimer, "AI-GENERATED ADVISORY — NON-AUTHORITATIVE")
            self.assertEqual(analysis.explanation, "Custom LLM explanation of broken access control.")

    def test_no_cvss_score_produced(self):
        """Verifies that no numerical CVSS score is present in fallback or AI output."""
        analysis = build_fallback_finding_analysis(self.sample_finding)
        data = analysis.model_dump()
        for key in data:
            self.assertNotIn("cvss", key.lower())
            self.assertNotIn("score", key.lower())
        self.assertIn("No numerical CVSS score is assigned", data["prioritization_rationale"])

    def test_existing_severity_and_finding_remain_intact(self):
        """AI analysis never alters the deterministic finding's severity or title."""
        original_severity = self.sample_finding["severity"]
        original_title = self.sample_finding["title"]

        analysis = generate_ai_finding_analysis(self.sample_finding)

        # Finding original attributes untouched
        self.assertEqual(self.sample_finding["severity"], original_severity)
        self.assertEqual(self.sample_finding["title"], original_title)
        # Analysis matches finding metadata
        self.assertEqual(analysis.title, original_title)

    def test_finding_ai_analysis_persistence(self):
        """Ensures AI analysis is safely persisted into findings.metadata['ai_analysis']."""
        scan_id = save_scan(
            target="http://127.0.0.1:8001",
            risk_summary={"risk_level": "High", "total_findings": 1, "severity_counts": {"High": 1}},
            findings=[self.sample_finding],
            db_path=self.scanner_db
        )

        scan = get_scan_by_id(scan_id, db_path=self.scanner_db)
        finding_id = scan["findings"][0]["id"]

        analysis = generate_ai_finding_analysis(self.sample_finding)
        ok = save_finding_ai_analysis(finding_id, analysis.model_dump(), db_path=self.scanner_db)
        self.assertTrue(ok)

        # Retrieve and verify finding metadata preserved
        retrieved_finding = get_finding_by_id(finding_id, db_path=self.scanner_db)
        self.assertIsNotNone(retrieved_finding)
        self.assertEqual(retrieved_finding["title"], self.sample_finding["title"])
        self.assertEqual(retrieved_finding["severity"], "High")
        self.assertIn("ai_analysis", retrieved_finding)
        self.assertEqual(
            retrieved_finding["ai_analysis"]["disclaimer"],
            "AI-GENERATED ADVISORY — NON-AUTHORITATIVE"
        )

    def test_assessment_ai_summary_persistence(self):
        """Ensures assessment AI summary is safely persisted into scans.raw_results['ai_summary']."""
        scan_id = save_scan(
            target="http://127.0.0.1:8001",
            risk_summary={"risk_level": "High", "total_findings": 1, "severity_counts": {"High": 1}},
            findings=[self.sample_finding],
            raw_results={"tests_run": 7},
            db_path=self.scanner_db
        )

        summary = generate_ai_assessment_summary(self.sample_assessment)
        ok = save_assessment_ai_summary(scan_id, summary.model_dump(), db_path=self.scanner_db)
        self.assertTrue(ok)

        retrieved_scan = get_scan_by_id(scan_id, db_path=self.scanner_db)
        self.assertIsNotNone(retrieved_scan)
        raw = retrieved_scan.get("raw_results", {})
        self.assertEqual(raw.get("tests_run"), 7)
        self.assertIn("ai_summary", raw)
        self.assertEqual(
            raw["ai_summary"]["disclaimer"],
            "AI-GENERATED ADVISORY — NON-AUTHORITATIVE"
        )

    def test_new_api_endpoints(self):
        """Tests POST /assessment/{id}/ai-summary and POST /findings/{id}/ai-analysis endpoints."""
        scan_id = save_scan(
            target="http://127.0.0.1:8001",
            risk_summary={"risk_level": "High", "total_findings": 1, "severity_counts": {"High": 1}},
            findings=[self.sample_finding],
            raw_results={"tests_run": 7},
            db_path=self.scanner_db
        )
        scan = get_scan_by_id(scan_id, db_path=self.scanner_db)
        finding_id = scan["findings"][0]["id"]

        # 1. POST /assessment/{scan_id}/ai-summary
        resp_summary = self.scanner_client.post(f"/assessment/{scan_id}/ai-summary")
        self.assertEqual(resp_summary.status_code, 200)
        data_summary = resp_summary.json()
        self.assertIn("executive_summary", data_summary)
        self.assertIn("analyst_summary", data_summary)
        self.assertEqual(data_summary["disclaimer"], "AI-GENERATED ADVISORY — NON-AUTHORITATIVE")

        # 2. POST /findings/{finding_id}/ai-analysis
        resp_finding = self.scanner_client.post(f"/findings/{finding_id}/ai-analysis")
        self.assertEqual(resp_finding.status_code, 200)
        data_finding = resp_finding.json()
        self.assertIn("explanation", data_finding)
        self.assertIn("remediation_guidance", data_finding)
        self.assertEqual(data_finding["disclaimer"], "AI-GENERATED ADVISORY — NON-AUTHORITATIVE")

        # 3. Check 404 for non-existent assessment/finding
        resp_not_found = self.scanner_client.post("/assessment/99999/ai-summary")
        self.assertEqual(resp_not_found.status_code, 404)
        resp_f_not_found = self.scanner_client.post("/findings/99999/ai-analysis")
        self.assertEqual(resp_f_not_found.status_code, 404)

    def test_existing_assessment_api_backward_compatibility(self):
        """Confirms existing POST /assessment/demo and GET /assessment/{id} continue working seamlessly."""
        from backend.assessments import run_demo_assessment

        def mock_runner(target_url="http://127.0.0.1:8001"):
            return run_demo_assessment(target_url=target_url, client=self.demo_client)

        with patch("backend.main.run_demo_assessment", side_effect=mock_runner):
            # 1. POST /assessment/demo default (include_ai=False)
            resp = self.scanner_client.post("/assessment/demo", json={"target_url": "http://127.0.0.1:8001"})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIn("assessment_id", data)
            self.assertIn("findings", data)
            self.assertNotIn("ai_summary", data)

            # 2. POST /assessment/demo with include_ai=True
            resp_ai = self.scanner_client.post("/assessment/demo?include_ai=true", json={"target_url": "http://127.0.0.1:8001"})
            self.assertEqual(resp_ai.status_code, 200)
            data_ai = resp_ai.json()
            self.assertIn("assessment_id", data_ai)
            self.assertIn("ai_summary", data_ai)
            self.assertEqual(data_ai["ai_summary"]["disclaimer"], "AI-GENERATED ADVISORY — NON-AUTHORITATIVE")



if __name__ == "__main__":
    unittest.main()
