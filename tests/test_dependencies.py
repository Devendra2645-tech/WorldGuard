import unittest
from unittest.mock import patch, MagicMock, mock_open
import httpx

from backend.scanners.dependencies import (
    scan_dependencies,
    parse_requirement_line,
    _map_osv_severity,
    _extract_affected_info
)


class TestDependencyScanner(unittest.TestCase):
    def test_parse_requirement_line_variations(self):
        cases = [
            ("requests==2.25.1", ("requests", "==2.25.1", "2.25.1")),
            ("jinja2 === 2.10.0", ("jinja2", "=== 2.10.0", "2.10.0")),
            ("urllib3=='1.26.5'", ("urllib3", "=='1.26.5'", "1.26.5")),
            ('certifi=="2021.5.30"', ("certifi", '=="2021.5.30"', "2021.5.30")),
            ("pydantic[email]==1.8.2", ("pydantic", "==1.8.2", "1.8.2")),
            ("flask >= 1.0, < 2.0", ("flask", ">= 1.0, < 2.0", None)),
            ("fastapi", ("fastapi", None, None)),
            ("Django~=3.2.0", ("Django", "~=3.2.0", None)),
            ("cryptography >= 3.4.0 ; sys_platform == 'linux'", ("cryptography", ">= 3.4.0", None)),
            ("  uvicorn[standard] == 0.15.0  # web server", ("uvicorn", "== 0.15.0", "0.15.0")),
            ("# comment line", None),
            ("-r requirements-dev.txt", None),
            ("--extra-index-url https://example.com", None),
            ("-e .", None),
            ("", None),
            ("   ", None),
        ]

        for line, expected in cases:
            with self.subTest(line=line):
                res = parse_requirement_line(line)
                self.assertEqual(res, expected)

    def test_missing_requirements_file(self):
        result = scan_dependencies("/non/existent/path")
        self.assertIsNone(result["requirements_file"])
        self.assertEqual(result["packages_found"], [])
        self.assertEqual(result["findings"], [])

    def test_map_osv_severity(self):
        self.assertEqual(_map_osv_severity({"database_specific": {"severity": "CRITICAL"}}), "Critical")
        self.assertEqual(_map_osv_severity({"database_specific": {"severity": "HIGH"}}), "High")
        self.assertEqual(_map_osv_severity({"database_specific": {"severity": "MODERATE"}}), "Medium")
        self.assertEqual(_map_osv_severity({"database_specific": {"severity": "LOW"}}), "Low")
        # CVSS score fallback
        self.assertEqual(_map_osv_severity({"severity": [{"score": 9.5}]}), "Critical")
        self.assertEqual(_map_osv_severity({"severity": [{"score": 7.5}]}), "High")
        self.assertEqual(_map_osv_severity({"severity": [{"score": 5.0}]}), "Medium")
        self.assertEqual(_map_osv_severity({"severity": [{"score": 2.0}]}), "Low")
        # Default
        self.assertEqual(_map_osv_severity({}), "Medium")

    def test_extract_affected_info(self):
        sample_vuln = {
            "affected": [
                {
                    "package": {"name": "jinja2"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.10.1"}
                            ]
                        }
                    ]
                }
            ]
        }
        summary, fixed = _extract_affected_info(sample_vuln, "jinja2")
        self.assertEqual(fixed, "2.10.1")
        self.assertEqual(summary, "< 2.10.1")

    @patch("backend.scanners.dependencies.os.path.exists")
    @patch("backend.scanners.dependencies.open", new_callable=mock_open, read_data="jinja2==2.10\nrequests==2.25.1\n")
    @patch("backend.scanners.dependencies.httpx.post")
    def test_mocked_osv_vulnerability_detection(self, mock_post, mock_file, mock_exists):
        mock_exists.return_value = True

        def osv_mock_response(url, json=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            pkg_name = json.get("package", {}).get("name") if json else ""
            if pkg_name == "jinja2":
                resp.json.return_value = {
                    "vulns": [
                        {
                            "id": "GHSA-462w-v97r-4m45",
                            "summary": "Jinja2 sandbox escape via string formatting",
                            "aliases": ["CVE-2019-10906"],
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {
                                    "package": {"name": "jinja2"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]
                                        }
                                    ]
                                }
                            ],
                            "references": [
                                {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906"}
                            ]
                        }
                    ]
                }
            else:
                resp.json.return_value = {"vulns": []}
            return resp

        mock_post.side_effect = osv_mock_response

        result = scan_dependencies("dummy_project")
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]

        # Verify unified finding structure
        self.assertEqual(finding["title"], "Vulnerable Dependency: jinja2 (CVE-2019-10906)")
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["category"], "Dependency Security")
        self.assertIn("Jinja2 sandbox escape", finding["description"])
        self.assertIn("Fixed in version: 2.10.1", finding["description"])

        # Verify advisory information
        self.assertEqual(finding["package"], "jinja2")
        self.assertEqual(finding["version_constraint"], "==2.10")
        self.assertEqual(finding["installed_version"], "2.10")
        self.assertEqual(finding["advisory_id"], "GHSA-462w-v97r-4m45")
        self.assertEqual(finding["cve_id"], "CVE-2019-10906")
        self.assertEqual(finding["affected_versions"], "< 2.10.1")
        self.assertEqual(finding["fixed_version"], "2.10.1")
        self.assertEqual(finding["references"], ["https://nvd.nist.gov/vuln/detail/CVE-2019-10906"])

    @patch("backend.scanners.dependencies.os.path.exists")
    @patch("backend.scanners.dependencies.open", new_callable=mock_open, read_data="fastapi==0.100.0\n")
    @patch("backend.scanners.dependencies.httpx.post")
    def test_mocked_osv_error_handling(self, mock_post, mock_file, mock_exists):
        mock_exists.return_value = True
        mock_post.side_effect = httpx.ConnectError("Connection to OSV failed")

        result = scan_dependencies("dummy_project")
        self.assertIn("error", result)
        self.assertIn("OSV vulnerability lookup error", result["error"])
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
