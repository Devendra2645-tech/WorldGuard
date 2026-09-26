from pydantic import BaseModel
from typing import Optional, Any


class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    full_name: str
    email: str


class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    user: UserResponse


class ReportCreate(BaseModel):
    title: str
    category: str
    summary: str
    status: Optional[str] = "Open"


class ReportResponse(BaseModel):
    id: int
    title: str
    category: str
    summary: str
    status: str
    created_by: str
    created_at: str


class AnalyticsMetric(BaseModel):
    id: int
    metric_name: str
    metric_value: str
    unit: str
    timestamp: str


class VulnerabilityModeRequest(BaseModel):
    vulnerable_mode: bool
