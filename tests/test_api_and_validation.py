import unittest
import os
import tempfile
from fastapi.testclient import TestClient
from unittest.mock import patch

from backend.main import app, validate_target_url, is_restricted_ip
from backend.database import init_db


class TestAPIAndValidation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_api_val.db")
        os.environ["WORLD_MONITOR_DB_PATH"] = self.db_path
        init_db(self.db_path)
        self.client = TestClient(app)

    def tearDown(self):
        os.environ.pop("WORLD_MONITOR_DB_PATH", None)
        self.temp_dir.cleanup()

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"message": "World Monitor Security Assessment API is running"}
        )

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "healthy"})

    def test_cors_headers(self):
        response = self.client.get(
            "/health",
            headers={"Origin": "http://localhost:5173"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("access-control-allow-origin"),
            "http://localhost:5173"
        )
        self.assertEqual(
            response.headers.get("access-control-allow-credentials"),
            "true"
        )

    def test_ssrf_rejects_localhost_and_internal_hosts(self):
        blocked_urls = [
            "http://localhost",
            "http://localhost:8000",
            "http://127.0.0.1",
            "http://127.0.0.1:8080/scan",
            "http://[::1]",
            "http://10.0.0.1",
            "http://192.168.1.1",
            "http://172.16.0.1",
            "http://169.254.169.254",
            "http://intranet",
            "http://service.internal",
            "http://router.lan",
            "http://app.local",
            "http://127.0.0.1.nip.io",
            "ftp://example.com",
            "javascript:alert(1)",
            "file:///etc/passwd"
        ]

        for url in blocked_urls:
            with self.subTest(url=url):
                response = self.client.post("/scan", json={"url": url})
                self.assertEqual(
                    response.status_code,
                    422,
                    f"Expected 422 for blocked URL: {url}, got {response.status_code}: {response.text}"
                )

    def test_valid_url_accepted_by_validator(self):
        valid_urls = [
            "https://example.com",
            "http://example.com/test",
            "https://sub.domain.example.org:8443/api"
        ]
        for url in valid_urls:
            with self.subTest(url=url):
                validated = validate_target_url(url)
                self.assertEqual(validated, url)

    @patch("backend.main.scan_security_headers")
    @patch("backend.main.scan_tls")
    @patch("backend.main.scan_api")
    def test_scan_endpoint_orchestration(self, mock_api, mock_tls, mock_headers):
        mock_headers.return_value = {
            "target": "https://example.com",
            "status_code": 200,
            "findings": [
                {
                    "title": "Missing Content-Security-Policy",
                    "severity": "Medium",
                    "category": "Security Headers",
                    "description": "CSP header missing"
                }
            ]
        }
        mock_tls.return_value = {
            "target": "https://example.com",
            "https": True,
            "tls_version": "TLSv1.3",
            "findings": []
        }
        mock_api.return_value = {
            "target": "https://example.com",
            "openapi_spec": None,
            "findings": []
        }

        response = self.client.post("/scan", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("scan_id", data)
        self.assertIsInstance(data["scan_id"], int)
        self.assertEqual(data["target"], "https://example.com")
        self.assertIn("risk_summary", data)
        self.assertEqual(data["risk_summary"]["risk_level"], "Medium")
        self.assertEqual(data["risk_summary"]["total_findings"], 1)
        self.assertEqual(data["risk_summary"]["severity_counts"]["Medium"], 1)


if __name__ == "__main__":
    unittest.main()
