from fastapi import APIRouter, Depends
from demo_app.auth import require_role
from demo_app.database import get_all_analytics
from demo_app.models import AnalyticsMetric

router = APIRouter(prefix="/api/analytics", tags=["Demo Analytics"])


@router.get("", response_model=list[AnalyticsMetric])
def get_analytics(current_user: dict = Depends(require_role(["Admin", "Analyst"]))):
    """
    Retrieves telemetry metrics and sensor health analytics.
    Protected by RBAC: Requires Admin or Analyst role. (Operator and Normal User are rejected with 403).
    """
    records = get_all_analytics()
    return [
        AnalyticsMetric(
            id=a["id"],
            metric_name=a["metric_name"],
            metric_value=a["metric_value"],
            unit=a["unit"],
            timestamp=a["timestamp"]
        )
        for a in records
    ]
