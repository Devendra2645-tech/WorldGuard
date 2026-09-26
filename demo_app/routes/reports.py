from fastapi import APIRouter, Depends, HTTPException
from demo_app.auth import get_current_user, require_role
from demo_app.database import get_all_reports, create_demo_report
from demo_app.models import ReportCreate, ReportResponse

router = APIRouter(prefix="/api/reports", tags=["Demo Reports"])


@router.get("", response_model=list[ReportResponse])
def list_reports(current_user: dict = Depends(get_current_user)):
    """
    Lists surveillance and telemetry reports.
    Accessible to all authenticated demo users (Admin, Analyst, Operator, Normal User).
    """
    reports = get_all_reports()
    return [
        ReportResponse(
            id=r["id"],
            title=r["title"],
            category=r["category"],
            summary=r["summary"],
            status=r["status"],
            created_by=r["created_by"],
            created_at=r["created_at"]
        )
        for r in reports
    ]


@router.post("", response_model=ReportResponse, status_code=201)
def create_report(
    payload: ReportCreate,
    current_user: dict = Depends(require_role(["Admin", "Analyst", "Operator"]))
):
    """
    Creates a new operational report.
    Protected by RBAC: Requires Admin, Analyst, or Operator role. (Normal User is rejected with 403).
    """
    report = create_demo_report(
        title=payload.title,
        category=payload.category,
        summary=payload.summary,
        status=payload.status or "Open",
        created_by=current_user["username"]
    )
    return ReportResponse(
        id=report["id"],
        title=report["title"],
        category=report["category"],
        summary=report["summary"],
        status=report["status"],
        created_by=report["created_by"],
        created_at=report["created_at"]
    )
