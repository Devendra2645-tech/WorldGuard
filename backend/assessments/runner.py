import datetime
from urllib.parse import urlparse
from typing import Optional, Any
import httpx

from backend.analysis.severity import calculate_summary
from backend.assessments.auth_tests import run_auth_assessment
from backend.assessments.authorization_tests import run_authorization_assessment
from backend.assessments.configuration_tests import run_configuration_assessment


AUTHORIZED_DEMO_HOSTS = ("127.0.0.1", "localhost")
AUTHORIZED_DEMO_PORT = 8001


def validate_demo_target(target_url: str) -> str:
    """
    Enforces strict security boundary:
    Assessment engine is authorized exclusively against the local demo application.
    """
    if not target_url or not isinstance(target_url, str):
        raise ValueError("Target URL must be provided.")

    parsed = urlparse(target_url.strip())
    if parsed.scheme.lower() != "http":
        raise ValueError("Demo application assessment requires 'http' scheme (local demo).")

    hostname = (parsed.hostname or "").lower()
    port = parsed.port or 80

    if hostname not in AUTHORIZED_DEMO_HOSTS or port != AUTHORIZED_DEMO_PORT:
        raise ValueError(
            f"Security Boundary Enforced: Controlled demo assessment is strictly restricted to "
            f"the authorized local demo target (http://127.0.0.1:{AUTHORIZED_DEMO_PORT}). "
            f"Target '{target_url}' is not permitted."
        )

    return f"http://{hostname}:{port}"


def reset_demo_target_mode(
    target_url: str = "http://127.0.0.1:8001",
    client: Optional[Any] = None
) -> bool:
    """
    Resets the authorized local demo target application to vulnerable mode (vulnerable_mode=True).
    Strictly applies ONLY to the authorized local demo target (http://127.0.0.1:8001).
    """
    validated_target = validate_demo_target(target_url)

    # In-process state update if demo_app is imported in the same runtime
    try:
        from demo_app.main import app as demo_app_instance
        demo_app_instance.state.vulnerable_mode = True
    except Exception:
        pass

    own_client = False
    if client is None:
        client = httpx.Client(base_url=validated_target, timeout=5.0)
        own_client = True

    try:
        resp = client.post("/api/admin/mode", json={"vulnerable_mode": True})
        return resp.status_code == 200
    except Exception:
        return False
    finally:
        if own_client:
            client.close()


def run_demo_assessment(
    target_url: str = "http://127.0.0.1:8001",
    client: Optional[Any] = None,
    reset_mode: bool = True
) -> dict:
    """
    Executes the controlled security assessment against the authorized local demo application.
    Combines authentication and authorization test suites with automated evidence collection.

    If reset_mode is True (default), resets the authorized demo target to vulnerable_mode=True
    prior to executing security tests, ensuring clean and repeatable demonstration runs.
    """
    validated_target = validate_demo_target(target_url)

    own_client = False
    if client is None:
        client = httpx.Client(base_url=validated_target, timeout=5.0)
        own_client = True

    try:
        # Phase 0: Reset authorized demo target to vulnerable state for repeatable demo runs
        if reset_mode:
            reset_demo_target_mode(target_url=validated_target, client=client)

        # Phase 1: Authentication Assessment
        auth_result = run_auth_assessment(client)
        user_token = auth_result.get("user_token")
        admin_token = auth_result.get("admin_token")

        # Phase 2: Authorization & RBAC Assessment
        authz_result = run_authorization_assessment(
            client=client,
            user_token=user_token,
            admin_token=admin_token
        )

        # Phase 3: Configuration, API Surface & Exposure Assessment
        config_result = run_configuration_assessment(client)

        raw_findings = (
            auth_result.get("findings", []) +
            authz_result.get("findings", []) +
            config_result.get("findings", [])
        )
        all_evidence = (
            auth_result.get("evidence", []) +
            authz_result.get("evidence", []) +
            config_result.get("evidence", [])
        )

        # Phase 7: Deterministic risk and business-impact enrichment
        from backend.analysis.risk import enrich_findings_risk
        all_findings = enrich_findings_risk(raw_findings)

        risk_summary = calculate_summary(all_findings)

        return {
            "target": validated_target,
            "status": "completed",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tests_run": len(all_evidence),
            "risk_summary": risk_summary,
            "findings": all_findings,
            "evidence": all_evidence
        }
    finally:
        if own_client:
            client.close()
