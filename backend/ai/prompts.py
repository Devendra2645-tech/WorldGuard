import json
from typing import Optional, Any
from backend.assessments.evidence import redact_text, sanitize_headers, sanitize_payload

SENSITIVE_PROMPT_KEYS = (
    "token", "password", "secret", "authorization", "x-demo-token",
    "cookie", "session", "api_key", "bearer", "credentials"
)


def sanitize_finding_for_ai(finding: dict) -> dict:
    """
    Extracts and sanitizes finding data to ensure no credentials, tokens,
    or secret headers are ever passed to an external AI service.
    """
    safe_fields = (
        "evidence_id", "title", "severity", "category", "cwe_id",
        "owasp_category", "affected_role", "tested_role", "endpoint",
        "method", "description", "exploitability", "confidentiality_impact",
        "integrity_impact", "availability_impact", "data_sensitivity",
        "business_impact", "remediation_priority", "remediation"
    )
    sanitized = {}
    for key in safe_fields:
        if key in finding and finding[key] is not None:
            val = finding[key]
            if isinstance(val, str):
                sanitized[key] = redact_text(val)
            else:
                sanitized[key] = sanitize_payload(val)

    # Double check no sensitive strings leaked
    for k, v in list(sanitized.items()):
        if any(s in k.lower() for s in ("token", "password", "secret", "auth")):
            if k not in ("owasp_category", "affected_role", "tested_role"):
                sanitized[k] = "[REDACTED]"

    return sanitized


def sanitize_assessment_for_ai(assessment: dict) -> dict:
    """
    Sanitizes assessment summary and its findings for prompt construction.
    """
    raw_findings = assessment.get("findings", [])
    sanitized_findings = [sanitize_finding_for_ai(f) for f in raw_findings]

    return {
        "target": assessment.get("target", "http://127.0.0.1:8001"),
        "risk_summary": assessment.get("risk_summary", {}),
        "tests_run": assessment.get("tests_run", len(sanitized_findings)),
        "findings": sanitized_findings
    }


def build_finding_analysis_prompt(finding: dict) -> str:
    """
    Constructs a strictly bounded system and user prompt for analyzing a single finding.
    """
    sanitized = sanitize_finding_for_ai(finding)
    finding_json = json.dumps(sanitized, indent=2)

    return f"""You are the WorldGuard Defensive Security Advisory Assistant.

CORE SYSTEM CONSTRAINTS:
1. The deterministic WorldGuard automated assessment engine is the sole SOURCE OF TRUTH.
2. The finding below has ALREADY been established and verified by deterministic automated tests.
3. Do NOT invent new vulnerabilities or speculate about unverified weaknesses.
4. Do NOT modify the severity rating (maintain severity: {sanitized.get('severity', 'High')}).
5. Do NOT generate, calculate, or mention numerical CVSS scores under any circumstances.
6. Base your explanation ONLY on the structured finding data provided below.
7. Remediation guidance is ADVISORY ONLY. Never propose automated command execution or arbitrary source code modification.
8. Output MUST be valid JSON with the exact structure specified below. Do not wrap in markdown or backticks.

STRUCTURED FINDING DATA:
{finding_json}

JSON RESPONSE SCHEMA:
{{
  "explanation": "Clear technical explanation of what caused the vulnerability and how it manifests.",
  "business_impact": "Operational and business consequence explanation contextualized to the affected role and data sensitivity.",
  "prioritization_rationale": "Reasoning behind the remediation priority based on exploitability and impact factors. No CVSS scores.",
  "remediation_guidance": "Advisory step-by-step developer guidance and safe coding pattern recommendations.",
  "verification_procedure": "Recommended retest and validation procedure to confirm effective remediation."
}}
"""


def build_assessment_summary_prompt(assessment: dict) -> str:
    """
    Constructs a strictly bounded prompt for synthesizing an assessment-level summary.
    """
    sanitized = sanitize_assessment_for_ai(assessment)
    assessment_json = json.dumps(sanitized, indent=2)

    return f"""You are the WorldGuard Defensive Security Advisory Assistant.

CORE SYSTEM CONSTRAINTS:
1. The deterministic WorldGuard automated assessment engine is the sole SOURCE OF TRUTH.
2. Summarize ONLY the evaluated findings provided below.
3. Do NOT invent vulnerabilities, alter finding counts, or modify risk levels.
4. Do NOT calculate or invent numerical CVSS scores.
5. Provide both an Executive Summary (for leadership) and an Analyst Technical Digest (for security engineers).
6. Recommended actions are ADVISORY ONLY.
7. Output MUST be valid JSON with the exact structure specified below. Do not wrap in markdown or backticks.

ASSESSMENT EVALUATION DATA:
{assessment_json}

JSON RESPONSE SCHEMA:
{{
  "executive_summary": "High-level security posture summary suitable for leadership and executives.",
  "analyst_summary": "Technical digest detailing evaluated endpoints, authorization controls, and findings.",
  "key_risks": [
    "Key identified risk 1",
    "Key identified risk 2"
  ],
  "recommended_actions": [
    "Ordered remediation step 1",
    "Ordered remediation step 2"
  ]
}}
"""
