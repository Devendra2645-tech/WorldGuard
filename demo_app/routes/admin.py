from fastapi import APIRouter, Depends, HTTPException, Request, Header, Query
from typing import Optional
from demo_app.auth import get_current_user
from demo_app.models import VulnerabilityModeRequest

router = APIRouter(prefix="/api/admin", tags=["Demo Admin & Vulnerability Benchmark"])


@router.get("")
def get_admin_system_overview(
    request: Request,
    current_user: dict = Depends(get_current_user),
    x_enforce_auth: Optional[str] = Header(None, alias="X-Enforce-Auth"),
    fix: Optional[bool] = Query(None)
):
    """
    Admin system control panel.
    
    ==================================================================================
    CONTROLLED DEMONSTRATION VULNERABILITY (CWE-862: Missing Authorization)
    ==================================================================================
    - Vulnerable State (Default):
      The endpoint authenticates the user, but FAILS to verify that the user's role is 'Admin'.
      A 'Normal User' (or Operator/Analyst) requesting this endpoint receives 200 OK and restricted
      synthetic admin system details.
      
    - Fixed/Secure State:
      When vulnerable_mode is toggled OFF (or header 'X-Enforce-Auth: true' / query '?fix=true' is sent),
      the endpoint enforces strict role validation. Non-admin roles receive 403 Forbidden.
      
    - Safety Notice:
      This endpoint returns purely synthetic demo metadata. It contains no real secrets,
      credentials, file access, command execution, or destructive capabilities.
    ==================================================================================
    """
    # Check if vulnerability fix is activated (via global state, header override, or query param)
    is_vulnerable = getattr(request.app.state, "vulnerable_mode", True)
    if fix is not None:
        is_vulnerable = not fix
    elif x_enforce_auth and x_enforce_auth.strip().lower() in ("true", "1", "yes"):
        is_vulnerable = False

    # In secure state, enforce that the user must possess the Admin role
    if not is_vulnerable:
        if current_user.get("role") != "Admin":
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Admin role required. User '{current_user.get('username')}' has role '{current_user.get('role')}'."
            )

    return {
        "status": "operational",
        "system_name": "World Monitor Core Node #01",
        "demo_mode": True,
        "vulnerability_active": is_vulnerable,
        "authorized_as": current_user.get("role"),
        "admin_telemetry": {
            "sensor_nodes_online": 48,
            "synthetic_control_channel": "CH-ALPHA-01",
            "maintenance_window": "Sunday 02:00 - 04:00 UTC",
            "synthetic_device_key_id": "SYNTHETIC-DEMO-KEY-8812"
        },
        "message": (
            "VULNERABILITY DEMONSTRATED: Access granted without Admin role check."
            if is_vulnerable and current_user.get("role") != "Admin"
            else "Access authorized for Admin role."
        )
    }


@router.get("/mode")
def get_vulnerability_mode(request: Request):
    """Inspects the current state of the demo authorization vulnerability."""
    vulnerable = getattr(request.app.state, "vulnerable_mode", True)
    return {
        "vulnerable_mode": vulnerable,
        "description": (
            "Vulnerable state ACTIVE (Normal User can access /api/admin without 403)."
            if vulnerable
            else "Fixed state ACTIVE (Role check enforced: non-admins receive 403 Forbidden)."
        )
    }


@router.post("/mode")
def set_vulnerability_mode(payload: VulnerabilityModeRequest, request: Request):
    """
    Toggles the controlled demonstration vulnerability between vulnerable and secure/fixed states.
    Allows automated test suites and live presentations to demonstrate Before vs After security postures.
    """
    request.app.state.vulnerable_mode = payload.vulnerable_mode
    return {
        "vulnerable_mode": request.app.state.vulnerable_mode,
        "message": (
            "Vulnerability enabled: /api/admin will permit any authenticated user."
            if request.app.state.vulnerable_mode
            else "Vulnerability fixed: /api/admin strictly requires role == Admin."
        )
    }
