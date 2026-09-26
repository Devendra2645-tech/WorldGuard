import ssl
import socket
import datetime
from urllib.parse import urlparse


def _extract_cert_info(cert: dict) -> dict:
    """Safely extracts structured metadata from a peer certificate dictionary."""
    cert_info = {}

    # Subject extraction
    subject_dict = {}
    for rdn in cert.get("subject", ()):
        for key, val in rdn:
            subject_dict[key] = val
    cert_info["subject"] = subject_dict

    # Issuer extraction
    issuer_dict = {}
    for rdn in cert.get("issuer", ()):
        for key, val in rdn:
            issuer_dict[key] = val
    cert_info["issuer"] = issuer_dict

    # Subject Alternative Names (SANs)
    sans = [val for kind, val in cert.get("subjectAltName", ()) if kind == "DNS"]
    cert_info["sans"] = sans

    # Expiration dates
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    cert_info["not_after"] = not_after
    cert_info["not_before"] = not_before

    return cert_info


def scan_tls(url: str):
    findings = []

    parsed_url = urlparse(url)

    if parsed_url.scheme != "https":
        findings.append({
            "title": "HTTPS is not enabled",
            "severity": "High",
            "category": "TLS/HTTPS",
            "description": "The target URL does not use HTTPS."
        })

        return {
            "target": url,
            "https": False,
            "findings": findings
        }

    hostname = parsed_url.hostname
    port = parsed_url.port or 443

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                tls_version = secure_socket.version()
                cert = secure_socket.getpeercert()

        # Check TLS protocol version
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            findings.append({
                "title": "Deprecated TLS Protocol Version",
                "severity": "High",
                "category": "TLS/HTTPS",
                "description": f"The server negotiated {tls_version}. Deprecated protocols are vulnerable to cryptographic weaknesses and lack forward secrecy."
            })

        # Non-destructive certificate inspection
        cert_info = _extract_cert_info(cert) if cert else {}

        if cert and "notAfter" in cert:
            try:
                expire_secs = ssl.cert_time_to_seconds(cert["notAfter"])
                expire_dt = datetime.datetime.fromtimestamp(expire_secs, tz=datetime.timezone.utc)
                now = datetime.datetime.now(tz=datetime.timezone.utc)
                days_remaining = (expire_dt - now).days
                cert_info["days_until_expiration"] = days_remaining

                if days_remaining < 0:
                    findings.append({
                        "title": "TLS Certificate Expired",
                        "severity": "Critical",
                        "category": "TLS/HTTPS",
                        "description": f"The SSL/TLS certificate expired {abs(days_remaining)} day(s) ago on {cert['notAfter']}."
                    })
                elif days_remaining <= 14:
                    findings.append({
                        "title": "TLS Certificate Expiring Imminently",
                        "severity": "High",
                        "category": "TLS/HTTPS",
                        "description": f"The SSL/TLS certificate will expire in {days_remaining} day(s) on {cert['notAfter']}. Urgent renewal required."
                    })
                elif days_remaining <= 30:
                    findings.append({
                        "title": "TLS Certificate Expiring Soon",
                        "severity": "Medium",
                        "category": "TLS/HTTPS",
                        "description": f"The SSL/TLS certificate will expire in {days_remaining} day(s) on {cert['notAfter']}."
                    })
            except Exception:
                pass

        result = {
            "target": url,
            "https": True,
            "tls_version": tls_version,
            "findings": findings
        }
        if cert_info:
            result["certificate"] = cert_info

        return result

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "title": "TLS Certificate Verification Failed",
            "severity": "High",
            "category": "TLS/HTTPS",
            "description": f"Certificate verification failed: {e.verify_message if hasattr(e, 'verify_message') and e.verify_message else str(e)}."
        })

        return {
            "target": url,
            "https": True,
            "findings": findings
        }

    except Exception as e:
        findings.append({
            "title": "TLS connection could not be established",
            "severity": "High",
            "category": "TLS/HTTPS",
            "description": str(e)
        })

        return {
            "target": url,
            "https": True,
            "findings": findings
        }