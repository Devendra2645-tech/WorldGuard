from pydantic import BaseModel
from typing import Optional, Any


class FindingRecord(BaseModel):
    id: Optional[int] = None
    scan_id: Optional[int] = None
    title: str
    severity: str
    category: str
    description: str
    metadata: Optional[dict[str, Any]] = None


class ScanSummaryRecord(BaseModel):
    id: int
    target: str
    scanned_at: str
    risk_level: str
    total_findings: int
    severity_counts: dict[str, int]
    status: str


class ScanDetailRecord(BaseModel):
    id: int
    target: str
    scanned_at: str
    risk_level: str
    total_findings: int
    severity_counts: dict[str, int]
    status: str
    findings: list[dict[str, Any]]
    raw_results: Optional[dict[str, Any]] = None
