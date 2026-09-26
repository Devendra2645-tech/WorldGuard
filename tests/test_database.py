import unittest
import os
import tempfile
import json
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.database.database import (
    init_db,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    get_db_connection
)
from backend.main import app


class TestDatabaseDirect(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_scans.db")
        os.environ["WORLD_MONITOR_DB_PATH"] = self.db_path
        init_db(self.db_path)

    def tearDown(self):
        os.environ.pop("WORLD_MONITOR_DB_PATH", None)
        self.temp_dir.cleanup()

    def test_init_db_creates_tables(self):
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row["name"] for row in cursor.fetchall()]
        conn.close()

        self.assertIn("scans", tables)
        self.assertIn("findings", tables)

    def test_save_and_retrieve_scan(self):
        risk_summary = {
            "risk_level": "High",
            "total_findings": 2,
            "severity_counts": {"Critical": 0, "High": 1, "Medium": 1, "Low": 0, "Info": 0}
        }
        findings = [
            {
                "title": "Missing Strict-Transport-Security",
                "severity": "High",
                "category": "Security Headers",
                "description": "HSTS header is absent."
            },
            {
                "title": "Server Information Disclosure",
                "severity": "Low",
                "category": "Information Disclosure",
                "description": "Server header exposes version.",
                "server_token": "nginx/1.18.0"  # extra metadata
            }
        ]
        raw_results = {
            "security_headers": {"status_code": 200},
            "tls": {"https": True, "tls_version": "TLSv1.3"},
            "api": {"openapi_spec": None}
        }

        scan_id = save_scan(
            target="https://example.com",
            risk_summary=risk_summary,
            findings=findings,
            raw_results=raw_results,
            db_path=self.db_path
        )
        self.assertIsInstance(scan_id, int)
        self.assertGreaterEqual(scan_id, 1)

        # Retrieve recent scans list
        recent = get_recent_scans(limit=10, db_path=self.db_path)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["id"], scan_id)
        self.assertEqual(recent[0]["target"], "https://example.com")
        self.assertEqual(recent[0]["risk_level"], "High")
        self.assertEqual(recent[0]["total_findings"], 2)
        self.assertEqual(recent[0]["severity_counts"]["High"], 1)

        # Retrieve single complete scan by ID
        detail = get_scan_by_id(scan_id, db_path=self.db_path)
        self.assertIsNotNone(detail)
        self.assertEqual(detail["id"], scan_id)
        self.assertEqual(detail["target"], "https://example.com")
        self.assertEqual(len(detail["findings"]), 2)

        # Check preserved finding fields and metadata
        f1 = detail["findings"][0]
        self.assertEqual(f1["title"], "Missing Strict-Transport-Security")
        self.assertEqual(f1["severity"], "High")
        self.assertEqual(f1["category"], "Security Headers")

        f2 = detail["findings"][1]
        self.assertEqual(f2["title"], "Server Information Disclosure")
        self.assertEqual(f2.get("server_token"), "nginx/1.18.0")

        # Check raw results preserved
        self.assertEqual(detail["raw_results"]["tls"]["tls_version"], "TLSv1.3")

    def test_get_nonexistent_scan_returns_none(self):
        res = get_scan_by_id(9999, db_path=self.db_path)
        self.assertIsNone(res)


class TestScansAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_api_scans.db")
        os.environ["WORLD_MONITOR_DB_PATH"] = self.db_path
        init_db(self.db_path)
        self.client = TestClient(app)

    def tearDown(self):
        os.environ.pop("WORLD_MONITOR_DB_PATH", None)
        self.temp_dir.cleanup()

    @patch("backend.main.scan_security_headers")
    @patch("backend.main.scan_tls")
    @patch("backend.main.scan_api")
    def test_post_scan_persists_and_returns_scan_id(self, mock_api, mock_tls, mock_headers):
        mock_headers.return_value = {
            "target": "https://secure-target.com",
            "status_code": 200,
            "findings": [
                {
                    "title": "Missing Content-Security-Policy",
                    "severity": "Medium",
                    "category": "Security Headers",
                    "description": "CSP is missing."
                }
            ]
        }
        mock_tls.return_value = {
            "target": "https://secure-target.com",
            "https": True,
            "tls_version": "TLSv1.3",
            "findings": []
        }
        mock_api.return_value = {
            "target": "https://secure-target.com",
            "openapi_spec": None,
            "findings": []
        }

        # 1. Trigger POST /scan
        response = self.client.post("/scan", json={"url": "https://secure-target.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertIn("scan_id", data)
        scan_id = data["scan_id"]
        self.assertIsInstance(scan_id, int)
        self.assertEqual(data["target"], "https://secure-target.com")
        self.assertIn("risk_summary", data)
        self.assertIn("security_headers", data)
        self.assertIn("tls", data)
        self.assertIn("api", data)

        # 2. Trigger GET /scans (history)
        history_resp = self.client.get("/scans")
        self.assertEqual(history_resp.status_code, 200)
        history_list = history_resp.json()
        self.assertIsInstance(history_list, list)
        self.assertEqual(len(history_list), 1)
        self.assertEqual(history_list[0]["id"], scan_id)
        self.assertEqual(history_list[0]["target"], "https://secure-target.com")

        # 3. Trigger GET /scans/{scan_id} (detail)
        detail_resp = self.client.get(f"/scans/{scan_id}")
        self.assertEqual(detail_resp.status_code, 200)
        detail_data = detail_resp.json()
        self.assertEqual(detail_data["id"], scan_id)
        self.assertEqual(detail_data["target"], "https://secure-target.com")
        self.assertEqual(len(detail_data["findings"]), 1)
        self.assertEqual(detail_data["findings"][0]["title"], "Missing Content-Security-Policy")

    def test_get_scan_not_found(self):
        resp = self.client.get("/scans/99999")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("not found", resp.json()["detail"].lower())

    def test_get_scan_invalid_id_type(self):
        resp = self.client.get("/scans/not-an-integer")
        self.assertEqual(resp.status_code, 422)


if __name__ == "__main__":
    unittest.main()
