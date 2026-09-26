import datetime
import re
from typing import Any, Optional


def redact_text(text: str) -> str:
    """Redacts potential tokens or passwords from string text."""
    if not text:
        return text
    # Redact Bearer tokens
    text = re.sub(r'(Bearer\s+)[A-Za-z0-9_\-\.]+', r'\1[REDACTED]', text, flags=re.IGNORECASE)
    # Redact demo tokens
    text = re.sub(r'(demo-token-)[A-Za-z0-9_\-]+', r'[REDACTED]', text, flags=re.IGNORECASE)
    # Redact password fields in JSON or key-values
    text = re.sub(r'("password"\s*:\s*)"[^"]+"', r'\1"[REDACTED]"', text, flags=re.IGNORECASE)
    text = re.sub(r'("token"\s*:\s*)"[^"]+"', r'\1"[REDACTED]"', text, flags=re.IGNORECASE)
    # Redact demo synthetic password values if present in raw text
    text = re.sub(r'demo_[a-z0-9_]*password[a-z0-9_]*', '[REDACTED]', text, flags=re.IGNORECASE)
    return text


def sanitize_headers(headers: dict) -> dict:
    """Returns a sanitized copy of headers with sensitive authorization values redacted."""
    sanitized = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in ("authorization", "x-demo-token", "cookie", "token", "password", "secret"):
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = str(v)
    return sanitized


def sanitize_payload(payload: Any) -> Any:
    """Recursively returns a sanitized copy of a request/response payload."""
    if isinstance(payload, dict):
        sanitized = {}
        for k, v in payload.items():
            if k.lower() in ("password", "token", "secret", "credentials", "x_demo_token", "api_key"):
                if isinstance(v, (str, int, float, bool)):
                    sanitized[k] = "[REDACTED]"
                else:
                    sanitized[k] = sanitize_payload(v)
            else:
                sanitized[k] = sanitize_payload(v)
        return sanitized
    elif isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]
    elif isinstance(payload, str):
        return redact_text(payload)
    return payload


def record_evidence(
    evidence_id: str,
    test_name: str,
    test_role: str,
    method: str,
    endpoint: str,
    expected_status: int,
    observed_status: int,
    request_headers: Optional[dict] = None,
    request_body: Optional[Any] = None,
    response_body: Optional[Any] = None
) -> dict:
    """
    Constructs a deterministic, secret-redacted evidence record.
    Strictly avoids storing passwords or bearer tokens in cleartext.
    """
    excerpt = None
    if response_body is not None:
        if isinstance(response_body, (dict, list)):
            sanitized_body = sanitize_payload(response_body)
            excerpt = redact_text(str(sanitized_body))[:300]
        elif isinstance(response_body, str):
            excerpt = redact_text(response_body)[:300]

    return {
        "evidence_id": evidence_id,
        "test_name": test_name,
        "test_role": test_role,
        "method": method.upper(),
        "endpoint": endpoint,
        "expected_status": expected_status,
        "observed_status": observed_status,
        "status_match": expected_status == observed_status,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "request_info": {
            "headers": sanitize_headers(request_headers or {}),
            "body": sanitize_payload(request_body) if request_body is not None else None
        },
        "response_status": observed_status,
        "response_excerpt": excerpt
    }
