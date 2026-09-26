import unittest
from unittest.mock import patch, MagicMock
import httpx
import ssl
import datetime

from backend.scanners.headers import scan_security_headers
from backend.scanners.tls import scan_tls
from backend.scanners.api import scan_api


class TestHeaderScanner(unittest.TestCase):
    @patch("backend.scanners.headers.httpx.get")
    def test_missing_all_security_headers(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = httpx.Headers({})
        mock_get.return_value = mock_resp

        result = scan_security_headers("https://example.com")
        self.assertEqual(result["status_code"], 200)
        titles = [f["title"] for f in result["findings"]]

        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertIn("Missing Strict-Transport-Security", titles)
        self.assertIn("Missing X-Content-Type-Options", titles)
        self.assertIn("Missing X-Frame-Options", titles)
        self.assertIn("Missing Referrer-Policy", titles)
        self.assertIn("Missing Permissions-Policy", titles)

    @patch("backend.scanners.headers.httpx.get")
    def test_header_values_and_info_disclosure(self, mock_get):
        raw_headers = {
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'; script-src *",
            "Strict-Transport-Security": "max-age=0",
            "X-Content-Type-Options": "sniff-enabled",
            "X-Frame-Options": "ALLOW-FROM https://evil.com",
            "Referrer-Policy": "unsafe-url",
            "Permissions-Policy": "geolocation=()",
            "Server": "Apache/2.4.52 (Ubuntu)",
            "X-Powered-By": "Express"
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = httpx.Headers(raw_headers)
        mock_get.return_value = mock_resp

        result = scan_security_headers("https://example.com")
        titles = [f["title"] for f in result["findings"]]

        # Value inspection findings
        self.assertIn("HSTS Max-Age Set to Zero", titles)
        self.assertIn("Improper X-Content-Type-Options Value", titles)
        self.assertIn("Improper X-Frame-Options Value", titles)
        self.assertIn("Content-Security-Policy with Unsafe Directives", titles)
        self.assertIn("Content-Security-Policy Overly Permissive Wildcard", titles)
        self.assertIn("Permissive Referrer-Policy Configuration", titles)

        # Info disclosure findings
        self.assertIn("Server Information Disclosure", titles)
        self.assertIn("X-Powered-By Information Disclosure", titles)

    @patch("backend.scanners.headers.httpx.get")
    def test_short_hsts_duration(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = httpx.Headers({
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=86400; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()"
        })
        mock_get.return_value = mock_resp

        result = scan_security_headers("https://example.com")
        titles = [f["title"] for f in result["findings"]]
        self.assertIn("Short HSTS Max-Age Duration", titles)

    @patch("backend.scanners.headers.httpx.get")
    def test_header_scanner_error_handling(self, mock_get):
        mock_get.side_effect = httpx.ConnectError("Network connection refused")
        result = scan_security_headers("https://example.com")
        self.assertIn("error", result)
        self.assertEqual(result["findings"], [])


class TestTLSScanner(unittest.TestCase):
    def test_non_https_url(self):
        result = scan_tls("http://example.com")
        self.assertFalse(result["https"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["title"], "HTTPS is not enabled")
        self.assertEqual(result["findings"][0]["severity"], "High")

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_tls_certificate_and_version_checks(self, mock_context_cls, mock_conn):
        mock_ctx = MagicMock()
        mock_context_cls.return_value = mock_ctx

        mock_socket = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_socket
        mock_socket.version.return_value = "TLSv1.3"

        # Certificate expires in 200 days
        future_dt = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=200)
        not_after_str = future_dt.strftime("%b %d %H:%M:%S %Y GMT")

        mock_socket.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "notAfter": not_after_str,
            "notBefore": "Jan 01 00:00:00 2026 GMT"
        }

        result = scan_tls("https://example.com")
        self.assertTrue(result["https"])
        self.assertEqual(result["tls_version"], "TLSv1.3")
        self.assertIn("certificate", result)
        self.assertEqual(result["certificate"]["subject"]["commonName"], "example.com")
        self.assertEqual(result["certificate"]["issuer"]["organizationName"], "Let's Encrypt")
        self.assertIn("www.example.com", result["certificate"]["sans"])
        self.assertGreaterEqual(result["certificate"]["days_until_expiration"], 199)
        self.assertEqual(result["findings"], [])

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_deprecated_tls_version_and_expired_certificate(self, mock_context_cls, mock_conn):
        mock_ctx = MagicMock()
        mock_context_cls.return_value = mock_ctx

        mock_socket = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_socket
        mock_socket.version.return_value = "TLSv1"

        past_dt = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=10)
        not_after_str = past_dt.strftime("%b %d %H:%M:%S %Y GMT")

        mock_socket.getpeercert.return_value = {
            "subject": ((("commonName", "legacy.example.com"),),),
            "issuer": ((("commonName", "Legacy CA"),),),
            "subjectAltName": (),
            "notAfter": not_after_str,
            "notBefore": "Jan 01 00:00:00 2020 GMT"
        }

        result = scan_tls("https://legacy.example.com")
        titles = [f["title"] for f in result["findings"]]
        severities = {f["title"]: f["severity"] for f in result["findings"]}

        self.assertIn("Deprecated TLS Protocol Version", titles)
        self.assertEqual(severities["Deprecated TLS Protocol Version"], "High")

        self.assertIn("TLS Certificate Expired", titles)
        self.assertEqual(severities["TLS Certificate Expired"], "Critical")

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_expiring_soon_certificate(self, mock_context_cls, mock_conn):
        mock_ctx = MagicMock()
        mock_context_cls.return_value = mock_ctx
        mock_socket = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_socket
        mock_socket.version.return_value = "TLSv1.3"

        # 5 days remaining -> Expiring Imminently (High)
        soon_dt = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=5)
        mock_socket.getpeercert.return_value = {
            "subject": ((("commonName", "renew.example.com"),),),
            "issuer": ((("commonName", "CA"),),),
            "notAfter": soon_dt.strftime("%b %d %H:%M:%S %Y GMT"),
            "notBefore": "Jan 01 00:00:00 2026 GMT"
        }

        result = scan_tls("https://renew.example.com")
        titles = [f["title"] for f in result["findings"]]
        self.assertIn("TLS Certificate Expiring Imminently", titles)


class TestAPIScanner(unittest.TestCase):
    @patch("backend.scanners.api.httpx.get")
    def test_detect_openapi_json(self, mock_get):
        def side_effect(url, **kwargs):
            resp = MagicMock()
            if url == "https://example.com/openapi.json":
                resp.status_code = 200
                resp.headers = {"content-type": "application/json"}
                resp.text = '{"openapi": "3.0.0", "info": {"title": "Test API"}}'
            else:
                resp.status_code = 404
                resp.headers = {}
                resp.text = "Not Found"
            return resp

        mock_get.side_effect = side_effect
        result = scan_api("https://example.com")

        self.assertEqual(result["openapi_spec"], "https://example.com/openapi.json")
        titles = [f["title"] for f in result["findings"]]
        self.assertIn("OpenAPI specification exposed", titles)

    @patch("backend.scanners.api.httpx.get")
    def test_detect_docs_ui(self, mock_get):
        def side_effect(url, **kwargs):
            resp = MagicMock()
            if url == "https://example.com/docs":
                resp.status_code = 200
                resp.headers = {"content-type": "text/html"}
                resp.text = '<html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div></body></html>'
            else:
                resp.status_code = 404
                resp.headers = {}
                resp.text = "Not Found"
            return resp

        mock_get.side_effect = side_effect
        result = scan_api("https://example.com")

        self.assertIn("https://example.com/docs", result["documentation_endpoints"])
        titles = [f["title"] for f in result["findings"]]
        self.assertIn("Public API Documentation Interface Exposed", titles)

    @patch("backend.scanners.api.httpx.get")
    def test_no_api_specs_detected(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.headers = {}
        mock_resp.text = "Not Found"
        mock_get.return_value = mock_resp

        result = scan_api("https://example.com")
        self.assertIsNone(result["openapi_spec"])
        self.assertEqual(result["documentation_endpoints"], [])
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
