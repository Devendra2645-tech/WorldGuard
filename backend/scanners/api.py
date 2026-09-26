import httpx
from urllib.parse import urljoin


OPENAPI_PATHS = [
    "openapi.json",
    "swagger.json",
    "api/openapi.json",
    "api/swagger.json",
    "v1/openapi.json",
    "v2/swagger.json"
]

DOCS_UI_PATHS = [
    "docs",
    "redoc",
    "swagger-ui.html",
    "swagger-ui/index.html",
    "api/docs"
]


def scan_api(url: str):
    findings = []
    base_url = url.rstrip("/") + "/"

    detected_spec = None
    detected_docs = []

    try:
        # 1. Detection of OpenAPI/Swagger JSON specifications
        for path in OPENAPI_PATHS:
            test_url = urljoin(base_url, path)
            try:
                response = httpx.get(
                    test_url,
                    timeout=5,
                    follow_redirects=True
                )

                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "").lower()
                    if "json" in content_type or "yaml" in content_type:
                        text_sample = response.text[:1000].lower()
                        if "openapi" in text_sample or "swagger" in text_sample or "paths" in text_sample:
                            detected_spec = test_url
                            break
            except Exception:
                continue

        if detected_spec:
            findings.append({
                "title": "OpenAPI specification exposed",
                "severity": "Info",
                "category": "API Security",
                "description": (
                    f"An OpenAPI/Swagger specification is publicly accessible at {detected_spec}. "
                    "Review whether the exposed API documentation contains sensitive internal endpoints or data."
                )
            })

        # 2. Detection of interactive API documentation UI interfaces
        for path in DOCS_UI_PATHS:
            test_url = urljoin(base_url, path)
            if test_url == detected_spec:
                continue
            try:
                response = httpx.get(
                    test_url,
                    timeout=5,
                    follow_redirects=True
                )

                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "").lower()
                    if "html" in content_type:
                        text_sample = response.text[:2000].lower()
                        if any(sig in text_sample for sig in ("swagger", "swagger-ui", "redoc", "openapi", "rapidoc")):
                            detected_docs.append(test_url)
            except Exception:
                continue

        if detected_docs:
            findings.append({
                "title": "Public API Documentation Interface Exposed",
                "severity": "Info",
                "category": "API Security",
                "description": (
                    f"Interactive API documentation was detected at: {', '.join(detected_docs)}. "
                    "Verify that public exposure of interactive documentation is intentional and does not expose protected endpoints."
                )
            })

        return {
            "target": url,
            "openapi_spec": detected_spec,
            "documentation_endpoints": detected_docs,
            "findings": findings
        }

    except Exception as e:
        return {
            "target": url,
            "error": str(e),
            "findings": []
        }