from fastapi import APIRouter, HTTPException, Depends
from demo_app.models import LoginRequest, LoginResponse, UserResponse
from demo_app.database import get_user_by_username, hash_demo_password, create_demo_token
from demo_app.auth import get_current_user

router = APIRouter(prefix="/api/auth", tags=["Demo Authentication"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    """
    Demo login endpoint.
    Accepts synthetic demo credentials and returns a Bearer session token.
    (DEMO ONLY: Not for production use).
    """
    user = get_user_by_username(payload.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid demo username or password.")

    expected_hash = hash_demo_password(payload.password)
    if user["password_hash"] != expected_hash:
        raise HTTPException(status_code=401, detail="Invalid demo username or password.")

    token = create_demo_token(user["username"])
    user_resp = UserResponse(
        id=user["id"],
        username=user["username"],
        role=user["role"],
        full_name=user["full_name"],
        email=user["email"]
    )
    return LoginResponse(token=token, user=user_resp)


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """Returns profile information for the authenticated demo user."""
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        role=current_user["role"],
        full_name=current_user["full_name"],
        email=current_user["email"]
    )
