import os
import json
import logging
from typing import Optional, Any
import httpx
from pydantic import ValidationError

from backend.ai.models import FindingAIAnalysis, AssessmentAISummary
from backend.ai.prompts import (
    sanitize_finding_for_ai,
    sanitize_assessment_for_ai,
    build_finding_analysis_prompt,
    build_assessment_summary_prompt
)

logger = logging.getLogger("worldguard.ai")
DEFAULT_AI_TIMEOUT = 10.0


# ==============================================================================
# Deterministic Fallback Synthesizers (100% Offline Capable & Safe)
# ==============================================================================

def build_fallback_finding_analysis(finding: dict) -> FindingAIAnalysis:
    """
    Generates deterministic, rule-based expert analysis when no external AI
    provider is configured, available, or when an error occurs.
    Derived purely from deterministic finding data. Never invents CVSS scores.
    """
    title = finding.get("title", "Security Finding")
    severity = finding.get("severity", "Medium")
    cwe = finding.get("cwe_id", "CWE-Unknown")
    role = finding.get("affected_role") or finding.get("tested_role") or "Normal User"
    endpoint = finding.get("endpoint", "/api/admin")
    method = finding.get("method", "GET")
    desc = finding.get("description", "")
    priority = finding.get("remediation_priority", severity)
    exploitability = finding.get("exploitability", "High")
    conf_impact = finding.get("confidentiality_impact", "High")
    sensitivity = finding.get("data_sensitivity", "restricted functionality and system configuration")
    business_impact = finding.get(
        "business_impact",
        f"An authenticated user with '{role}' access may interact with restricted functionality, "
        f"creating confidentiality and integrity risks."
    )

    explanation = (
        f"The endpoint {method} {endpoint} is accessible to users with the '{role}' role without "
        f"enforcing strict server-side authorization checks ({cwe}). Under vulnerable application state, "
        f"the endpoint returned HTTP 200 OK instead of the expected HTTP 403 Forbidden. {desc}".strip()
    )

    prioritization_rationale = (
        f"Prioritized as {priority} priority based on {exploitability} exploitability and {conf_impact} "
        f"confidentiality impact on {sensitivity}. Deterministic WorldGuard rules rank this finding "
        f"as an immediate remediation target. No numerical CVSS score is assigned."
    )

    remediation_guidance = (
        f"1. Implement server-side role validation on {method} {endpoint}.\n"
        f"2. In FastAPI, enforce role boundaries using a security dependency: Depends(require_admin).\n"
        f"3. Reject unauthorized roles immediately with HTTP 403 Forbidden before executing business logic.\n"
        f"4. Ensure authorization checks are performed server-side and do not rely on client-side routing guards."
    )

    verification_procedure = (
        f"1. Baseline Verification: Issue {method} {endpoint} with '{role}' credentials; observe HTTP 200 OK (vulnerable).\n"
        f"2. Apply Configuration Fix: Enforce role-based access control.\n"
        f"3. Retest Unauthorized Role: Issue {method} {endpoint} with '{role}' credentials; confirm HTTP 403 Forbidden.\n"
        f"4. Admin Regression Check: Issue {method} {endpoint} with Admin credentials; confirm legitimate HTTP 200 OK access."
    )

    return FindingAIAnalysis(
        finding_id=finding.get("evidence_id") or str(finding.get("id", "")),
        title=title,
        explanation=explanation,
        business_impact=business_impact,
        prioritization_rationale=prioritization_rationale,
        remediation_guidance=remediation_guidance,
        verification_procedure=verification_procedure,
        generated_by="deterministic_fallback",
        authoritative=False,
        disclaimer="AI-GENERATED ADVISORY — NON-AUTHORITATIVE"
    )


def build_fallback_assessment_summary(assessment: dict) -> AssessmentAISummary:
    """
    Generates deterministic, rule-based executive and analyst summaries
    when external AI is unavailable.
    """
    target = assessment.get("target", "http://127.0.0.1:8001")
    risk_summary = assessment.get("risk_summary", {})
    risk_level = risk_summary.get("risk_level", "Low")
    total_findings = risk_summary.get("total_findings", len(assessment.get("findings", [])))
    counts = risk_summary.get("severity_counts", {})
    tests_run = assessment.get("tests_run", 7)
    findings = assessment.get("findings", [])

    high_crit = counts.get("Critical", 0) + counts.get("High", 0)

    if total_findings == 0 or (counts.get("High", 0) == 0 and counts.get("Critical", 0) == 0 and any(f.get("verification_status") == "verified" for f in findings)):
        exec_summary = (
            f"The security assessment of target {target} completed across {tests_run} deterministic tests. "
            f"All identified access control vulnerabilities have been remediated and verified. The current defensive "
            f"security posture is stable and operating in verified compliance with role-based access control policies."
        )
    else:
        exec_summary = (
            f"The automated security assessment of target {target} identified an overall risk posture of '{risk_level.upper()}'. "
            f"A total of {total_findings} finding(s) were discovered across {tests_run} deterministic authentication and "
            f"authorization tests, including {high_crit} high-priority finding(s) requiring remediation attention."
        )

    analyst_summary = (
        f"Evaluation performed against {target} covering {tests_run} automated test vectors. "
        f"Severity breakdown: Critical: {counts.get('Critical', 0)}, High: {counts.get('High', 0)}, "
        f"Medium: {counts.get('Medium', 0)}, Low: {counts.get('Low', 0)}, Info: {counts.get('Info', 0)}. "
        f"Key authorization controls and role-based endpoints were inspected deterministically."
    )

    key_risks = []
    recommended_actions = []

    for f in findings:
        t = f.get("title", "Finding")
        s = f.get("severity", "Medium")
        cwe = f.get("cwe_id", "CWE")
        key_risks.append(f"[{s.upper()}] {t} ({cwe})")

        if "Broken Access Control" in t or "WG-AC-004" in str(f.get("evidence_id", "")):
            recommended_actions.append("Enforce server-side Admin role check on GET /api/admin.")
            recommended_actions.append("Execute automated verification retest to confirm HTTP 403 Forbidden.")
            recommended_actions.append("Verify legitimate Admin access remains intact (HTTP 200 OK regression test).")

    if not key_risks:
        key_risks.append("No active unmitigated risks identified.")
    if not recommended_actions:
        recommended_actions.append("Maintain continuous automated defensive scanning and periodic regression audits.")

    return AssessmentAISummary(
        assessment_id=assessment.get("id") or assessment.get("assessment_id"),
        target=target,
        executive_summary=exec_summary,
        analyst_summary=analyst_summary,
        key_risks=key_risks,
        recommended_actions=recommended_actions,
        generated_by="deterministic_fallback",
        authoritative=False,
        disclaimer="AI-GENERATED ADVISORY — NON-AUTHORITATIVE"
    )


# ==============================================================================
# External Provider Integrations (httpx REST Client)
# ==============================================================================

def _strip_markdown_json(text: str) -> str:
    """Strips markdown code fences like ```json ... ``` if returned by an LLM."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    return cleaned


def _call_gemini_api(prompt: str, api_key: str, timeout: float = DEFAULT_AI_TIMEOUT) -> dict:
    """
    Calls Google Gemini REST API using httpx without third-party SDK dependencies.
    Never exposes API key in exceptions.
    """
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.2
        }
    }

    with httpx.Client(timeout=timeout) as client:
        resp = client.post(endpoint, json=payload)
        resp.raise_for_status()
        data = resp.json()

        try:
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            cleaned = _strip_markdown_json(raw_text)
            return json.loads(cleaned)
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to parse structured JSON from provider response: {e}")


# ==============================================================================
# Main Orchestration Services
# ==============================================================================

def generate_ai_finding_analysis(
    finding: dict,
    provider: Optional[str] = None,
    timeout: float = DEFAULT_AI_TIMEOUT
) -> FindingAIAnalysis:
    """
    Generates structured AI advisory analysis for a deterministic security finding.
    Transparently falls back to deterministic expert analysis on any failure.
    """
    active_provider = (provider or os.environ.get("WORLDGUARD_AI_PROVIDER", "none")).lower().strip()

    if active_provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key:
            try:
                prompt = build_finding_analysis_prompt(finding)
                raw_result = _call_gemini_api(prompt, api_key, timeout=timeout)

                analysis = FindingAIAnalysis(
                    finding_id=finding.get("evidence_id") or str(finding.get("id", "")),
                    title=finding.get("title", ""),
                    explanation=raw_result.get("explanation", ""),
                    business_impact=raw_result.get("business_impact", ""),
                    prioritization_rationale=raw_result.get("prioritization_rationale", ""),
                    remediation_guidance=raw_result.get("remediation_guidance", ""),
                    verification_procedure=raw_result.get("verification_procedure", ""),
                    generated_by="ai",
                    authoritative=False,
                    disclaimer="AI-GENERATED ADVISORY — NON-AUTHORITATIVE"
                )
                return analysis
            except Exception as err:
                logger.warning("External AI provider call failed (%s); reverting to deterministic fallback.", type(err).__name__)

    # Default / Fallback behavior
    return build_fallback_finding_analysis(finding)


def generate_ai_assessment_summary(
    assessment: dict,
    provider: Optional[str] = None,
    timeout: float = DEFAULT_AI_TIMEOUT
) -> AssessmentAISummary:
    """
    Generates structured AI executive and technical summaries for an assessment.
    Transparently falls back to deterministic expert analysis on any failure.
    """
    active_provider = (provider or os.environ.get("WORLDGUARD_AI_PROVIDER", "none")).lower().strip()

    if active_provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key:
            try:
                prompt = build_assessment_summary_prompt(assessment)
                raw_result = _call_gemini_api(prompt, api_key, timeout=timeout)

                summary = AssessmentAISummary(
                    assessment_id=assessment.get("id") or assessment.get("assessment_id"),
                    target=assessment.get("target"),
                    executive_summary=raw_result.get("executive_summary", ""),
                    analyst_summary=raw_result.get("analyst_summary", ""),
                    key_risks=raw_result.get("key_risks", []),
                    recommended_actions=raw_result.get("recommended_actions", []),
                    generated_by="ai",
                    authoritative=False,
                    disclaimer="AI-GENERATED ADVISORY — NON-AUTHORITATIVE"
                )
                return summary
            except Exception as err:
                logger.warning("External AI provider call failed (%s); reverting to deterministic fallback.", type(err).__name__)

    # Default / Fallback behavior
    return build_fallback_assessment_summary(assessment)
