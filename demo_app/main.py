from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

from demo_app.database import init_demo_db
from demo_app.routes import auth, users, reports, analytics, admin

app = FastAPI(
    title="World Monitor Demo Target Application",
    description=(
        "Controlled, local-only demo application representing the World Monitor target. "
        "Contains a deliberately controlled Missing Server-Side Authorization benchmark (CWE-862) "
        "for demonstrating WorldGuard defensive security assessment capabilities."
    ),
    version="1.0.0"
)

# App state configuration for vulnerability demonstration
app.state.vulnerable_mode = os.environ.get("DEMO_APP_VULNERABLE_MODE", "true").lower() in ("true", "1", "yes")

# CORS middleware for local demo testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000", "http://127.0.0.1:5173", "http://localhost:8001", "http://127.0.0.1:8001"],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    """Initializes the demo SQLite database and seeds deterministic demo records."""
    init_demo_db()


# Mount demo application routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(reports.router)
app.include_router(analytics.router)
app.include_router(admin.router)


@app.get("/")
def home():
    """Landing endpoint providing overview of the demo target and available demo credentials."""
    return {
        "service": "World Monitor Demo Application (Local Target)",
        "security_notice": "DEMO ONLY. Intended strictly as an authorized, local defensive security benchmark.",
        "localhost_only": True,
        "vulnerable_mode_active": app.state.vulnerable_mode,
        "demo_credentials": {
            "Admin": {"username": "admin_demo", "password": "demo_admin_password"},
            "Analyst": {"username": "analyst_demo", "password": "demo_analyst_password"},
            "Operator": {"username": "operator_demo", "password": "demo_operator_password"},
            "Normal User": {"username": "user_demo", "password": "demo_user_password"}
        },
        "endpoints": {
            "login": "POST /api/auth/login",
            "profile": "GET /api/auth/me",
            "users": "GET /api/users",
            "reports": "GET /api/reports, POST /api/reports",
            "analytics": "GET /api/analytics",
            "admin_controlled_vuln": "GET /api/admin",
            "vulnerability_toggle": "GET /api/admin/mode, POST /api/admin/mode",
            "swagger_docs": "GET /docs"
        }
    }


@app.get("/health")
def health_check():
    """Health check endpoint for the demo application."""
    return {
        "status": "healthy",
        "service": "World Monitor Demo Target",
        "vulnerable_mode": app.state.vulnerable_mode
    }


if __name__ == "__main__":
    import uvicorn
    # Enforces strict local binding to 127.0.0.1
    uvicorn.run("demo_app.main:app", host="127.0.0.1", port=8001, reload=True)
