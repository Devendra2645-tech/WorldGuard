from pydantic import BaseModel, Field
from typing import Optional, List


class FindingAIAnalysis(BaseModel):
    """
    Structured AI advisory model for a specific deterministic finding.
    Strictly non-authoritative; explains already-discovered vulnerability data.
    """
    finding_id: Optional[str] = Field(
        default=None,
        description="Evidence ID or database identifier of the finding."
    )
    title: Optional[str] = Field(
        default=None,
        description="Vulnerability title from deterministic assessment."
    )
    explanation: str = Field(
        ...,
        description="Plain-language technical explanation of what caused the vulnerability and how it manifests."
    )
    business_impact: str = Field(
        ...,
        description="Operational and business consequence explanation contextualized to the affected role and data sensitivity."
    )
    prioritization_rationale: str = Field(
        ...,
        description="Reasoning behind remediation urgency based on exploitability and impact factors without CVSS scores."
    )
    remediation_guidance: str = Field(
        ...,
        description="Advisory developer guidance and safe coding pattern recommendations."
    )
    verification_procedure: str = Field(
        ...,
        description="Recommended retest and validation procedure to confirm effective remediation."
    )
    generated_by: str = Field(
        default="deterministic_fallback",
        description="Origin of the analysis: 'ai' or 'deterministic_fallback'."
    )
    authoritative: bool = Field(
        default=False,
        description="Always False: AI and advisory text are strictly non-authoritative."
    )
    disclaimer: str = Field(
        default="AI-GENERATED ADVISORY — NON-AUTHORITATIVE",
        description="Mandatory disclaimer label declaring non-authoritative status."
    )


class AssessmentAISummary(BaseModel):
    """
    Structured AI advisory summary for a complete security assessment.
    Aggregates deterministic findings into executive and technical perspectives.
    """
    assessment_id: Optional[int] = Field(
        default=None,
        description="Identifier of the associated assessment record."
    )
    target: Optional[str] = Field(
        default=None,
        description="Evaluated target URL."
    )
    executive_summary: str = Field(
        ...,
        description="High-level security posture summary suitable for leadership and executives."
    )
    analyst_summary: str = Field(
        ...,
        description="Technical digest detailing evaluated endpoints, authorization controls, and findings."
    )
    key_risks: List[str] = Field(
        default_factory=list,
        description="Key identified security risks requiring prioritization."
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Ordered list of recommended remediation steps."
    )
    generated_by: str = Field(
        default="deterministic_fallback",
        description="Origin of the summary: 'ai' or 'deterministic_fallback'."
    )
    authoritative: bool = Field(
        default=False,
        description="Always False: AI outputs are non-authoritative."
    )
    disclaimer: str = Field(
        default="AI-GENERATED ADVISORY — NON-AUTHORITATIVE",
        description="Mandatory disclaimer label declaring non-authoritative status."
    )
