from fastapi import APIRouter, Depends
from demo_app.auth import require_role
from demo_app.database import get_all_users
from demo_app.models import UserResponse

router = APIRouter(prefix="/api/users", tags=["Demo Users"])


@router.get("", response_model=list[UserResponse])
def list_users(current_user: dict = Depends(require_role(["Admin", "Analyst"]))):
    """
    Lists demo user accounts.
    Protected by RBAC: Only Admin and Analyst roles can view user management lists.
    """
    users = get_all_users()
    return [
        UserResponse(
            id=u["id"],
            username=u["username"],
            role=u["role"],
            full_name=u["full_name"],
            email=u["email"]
        )
        for u in users
    ]
