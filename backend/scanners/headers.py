import re
import httpx


SECURITY_HEADERS = {
    "Content-Security-Policy": "Medium",
    "Strict-Transport-Security": "High",
    "X-Content-Type-Options": "Medium",
    "X-Frame-Options": "Medium",
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Low"
}

INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version"
]


def _check_header_values(headers: httpx.Headers, findings: list):
    """Inspects values of existing security headers for weak configurations."""
    # 1. Strict-Transport-Security value checks
    if "Strict-Transport-Security" in headers:
        hsts_val = headers.get("Strict-Transport-Security", "")
        hsts_lower = hsts_val.lower()
        match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
        if match:
            max_age = int(match.group(1))
            if max_age == 0:
                findings.append({
                    "title": "HSTS Max-Age Set to Zero",
                    "severity": "Medium",
                    "category": "Security Headers",
                    "description": "Strict-Transport-Security header has max-age=0, effectively disabling HSTS protection."
                })
            elif max_age < 10886400:  # less than ~126 days
                findings.append({
                    "title": "Short HSTS Max-Age Duration",
                    "severity": "Low",
                    "category": "Security Headers",
                    "description": f"Strict-Transport-Security max-age is set to {max_age} seconds. A minimum of 31,536,000 seconds (1 year) is recommended."
                })
        else:
            findings.append({
                "title": "Missing HSTS Max-Age Directive",
                "severity": "Low",
                "category": "Security Headers",
                "description": "The Strict-Transport-Security header is present but lacks a valid max-age directive."
            })

    # 2. X-Content-Type-Options value checks
    if "X-Content-Type-Options" in headers:
        xcto_val = headers.get("X-Content-Type-Options", "").strip().lower()
        if xcto_val != "nosniff":
            findings.append({
                "title": "Improper X-Content-Type-Options Value",
                "severity": "Low",
                "category": "Security Headers",
                "description": f"The X-Content-Type-Options header is set to '{xcto_val}', but should be set to 'nosniff'."
            })

    # 3. X-Frame-Options value checks
    if "X-Frame-Options" in headers:
        xfo_val = headers.get("X-Frame-Options", "").strip().upper()
        if xfo_val not in ("DENY", "SAMEORIGIN"):
            findings.append({
                "title": "Improper X-Frame-Options Value",
                "severity": "Low",
                "category": "Security Headers",
                "description": f"The X-Frame-Options header is set to '{xfo_val}'. The recommended values are 'DENY' or 'SAMEORIGIN'."
            })

    # 4. Content-Security-Policy value checks
    if "Content-Security-Policy" in headers:
        csp_val = headers.get("Content-Security-Policy", "")
        csp_lower = csp_val.lower()
        if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
            findings.append({
                "title": "Content-Security-Policy with Unsafe Directives",
                "severity": "Low",
                "category": "Security Headers",
                "description": "The Content-Security-Policy header contains 'unsafe-inline' or 'unsafe-eval', which reduces resistance against cross-site scripting (XSS)."
            })
        if "default-src *" in csp_lower or "script-src *" in csp_lower:
            findings.append({
                "title": "Content-Security-Policy Overly Permissive Wildcard",
                "severity": "Low",
                "category": "Security Headers",
                "description": "The Content-Security-Policy header includes a wildcard '*' source in script or default directives, allowing loading from arbitrary origins."
            })

    # 5. Referrer-Policy value checks
    if "Referrer-Policy" in headers:
        rp_val = headers.get("Referrer-Policy", "").strip().lower()
        if any(p in rp_val for p in ("unsafe-url", "no-referrer-when-downgrade")):
            findings.append({
                "title": "Permissive Referrer-Policy Configuration",
                "severity": "Low",
                "category": "Security Headers",
                "description": f"The Referrer-Policy is set to '{rp_val}', which may leak sensitive URL parameters across domains or protocol downgrades."
            })


def _check_info_disclosure(headers: httpx.Headers, findings: list):
    """Detects headers that disclose server or application framework information."""
    for header in INFO_DISCLOSURE_HEADERS:
        if header in headers:
            val = headers.get(header, "").strip()
            findings.append({
                "title": f"{header} Information Disclosure",
                "severity": "Low",
                "category": "Information Disclosure",
                "description": f"The '{header}' response header discloses underlying technology details: '{val}'."
            })


def scan_security_headers(url: str):
    findings = []

    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)

        for header, severity in SECURITY_HEADERS.items():
            if header not in response.headers:
                findings.append({
                    "title": f"Missing {header}",
                    "severity": severity,
                    "category": "Security Headers",
                    "description": f"The {header} security header is not present."
                })

        _check_header_values(response.headers, findings)
        _check_info_disclosure(response.headers, findings)

        return {
            "target": url,
            "status_code": response.status_code,
            "findings": findings
        }

    except Exception as e:
        return {
            "target": url,
            "error": str(e),
            "findings": []
        }