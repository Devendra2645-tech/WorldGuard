from fastapi import Header, HTTPException, Depends
from typing import Optional, Callable
from demo_app.database import get_user_by_token


def get_current_user(
    authorization: Optional[str] = Header(None),
    x_demo_token: Optional[str] = Header(None)
) -> dict:
    """
    Extracts and authenticates the demo user from Bearer header or X-Demo-Token header.
    (Demo-only authentication mechanism).
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1].strip()
    elif x_demo_token:
        token = x_demo_token.strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Missing demo authentication token. Provide 'Authorization: Bearer <token>' or 'X-Demo-Token: <token>' header."
        )

    user = get_user_by_token(token)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Invalid or expired demo token."
        )

    return user


def require_role(allowed_roles: list[str]) -> Callable:
    """Dependency that enforces Role-Based Access Control (RBAC)."""
    def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        user_role = current_user.get("role")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Insufficient privileges. Required role in {allowed_roles}, but user has role '{user_role}'."
            )
        return current_user
    return role_checker
