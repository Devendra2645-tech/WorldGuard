from typing import Any

# Specific risk & business impact evaluation rules for WorldGuard findings
EVIDENCE_RISK_RULES = {
    "WG-AC-004": {
        "severity": "High",
        "severity_method": "WorldGuard prototype rule",
        "exploitability": "High",
        "confidentiality_impact": "High",
        "integrity_impact": "High",
        "availability_impact": "Low",
        "affected_role": "Normal User",
        "data_sensitivity": "Administrative system telemetry and restricted functionality",
        "business_impact": (
            "An authenticated user without administrative privileges may access restricted "
            "administrative functionality, creating a risk of unauthorized information access "
            "and unauthorized administrative actions."
        ),
        "remediation_priority": "High"
    },
    "WG-AUTH-004": {
        "severity": "High",
        "severity_method": "WorldGuard prototype rule",
        "exploitability": "High",
        "confidentiality_impact": "High",
        "integrity_impact": "Medium",
        "availability_impact": "Low",
        "affected_role": "Anonymous / Public",
        "data_sensitivity": "Synthetic application credentials and account access secrets",
        "business_impact": (
            "Unauthenticated users can obtain credentials directly from the root landing endpoint, "
            "leading to immediate credential exposure and unauthorized access to privileged roles."
        ),
        "remediation_priority": "High"
    },
    "WG-SEC-001": {
        "severity": "Medium",
        "severity_method": "WorldGuard prototype rule",
        "exploitability": "Low",
        "confidentiality_impact": "Low",
        "integrity_impact": "Low",
        "availability_impact": "Low",
        "affected_role": "Anonymous / Public",
        "data_sensitivity": "HTTP response headers and client-side rendering context",
        "business_impact": (
            "Missing defense-in-depth security headers increases exposure to clickjacking, "
            "MIME-type sniffing, and cross-site execution vulnerabilities."
        ),
        "remediation_priority": "Medium"
    },
    "WG-API-001": {
        "severity": "Info",
        "severity_method": "WorldGuard prototype rule",
        "exploitability": "Low",
        "confidentiality_impact": "Low",
        "integrity_impact": "Low",
        "availability_impact": "Low",
        "affected_role": "Anonymous / Public",
        "data_sensitivity": "API schema definitions, route specifications, and parameter metadata",
        "business_impact": (
            "Publicly accessible OpenAPI specifications and Swagger documentation expose "
            "the system's internal API surface and attack surface to unauthorized actors."
        ),
        "remediation_priority": "Low"
    },
    "WG-AC-003": {
        "severity": "Medium",
        "severity_method": "WorldGuard prototype rule",
        "exploitability": "Medium",
        "confidentiality_impact": "Low",
        "integrity_impact": "Medium",
        "availability_impact": "Low",
        "affected_role": "Normal User",
        "data_sensitivity": "Operational surveillance reports",
        "business_impact": (
            "Unprivileged users can inject unauthorized operational reports into the "
            "monitoring database."
        ),
        "remediation_priority": "Medium"
    },
    "WG-AUTH-002": {
        "severity": "Critical",
        "severity_method": "WorldGuard prototype rule",
        "exploitability": "High",
        "confidentiality_impact": "High",
        "integrity_impact": "High",
        "availability_impact": "High",
        "affected_role": "Unauthenticated",
        "data_sensitivity": "Full system and authenticated user data",
        "business_impact": (
            "Unauthenticated attackers can bypass login mechanisms and access system "
            "resources without valid credentials."
        ),
        "remediation_priority": "Critical"
    },
    "WG-AUTH-005": {
        "severity": "High",
        "severity_method": "WorldGuard prototype rule",
        "exploitability": "High",
        "confidentiality_impact": "High",
        "integrity_impact": "Low",
        "availability_impact": "Low",
        "affected_role": "Unauthenticated",
        "data_sensitivity": "Protected user profile and session identity data",
        "business_impact": (
            "Unauthenticated actors can access protected user profile endpoints without providing "
            "authentication credentials, compromising user data confidentiality."
        ),
        "remediation_priority": "High"
    },
    "WG-AUTH-006": {
        "severity": "Critical",
        "severity_method": "WorldGuard prototype rule",
        "exploitability": "High",
        "confidentiality_impact": "High",
        "integrity_impact": "High",
        "availability_impact": "Low",
        "affected_role": "Unauthenticated",
        "data_sensitivity": "Protected user profile and authenticated session controls",
        "business_impact": (
            "Arbitrary, forged, or malformed authentication tokens are accepted by the server, "
            "allowing complete authentication bypass."
        ),
        "remediation_priority": "Critical"
    }
}


def _derive_default_impact(finding: dict) -> dict:
    """
    Deterministically derives default risk metrics for generic findings
    where a specific prototype rule is not explicitly defined.
    Does NOT calculate or invent an official CVSS score.
    """
    severity = finding.get("severity", "Medium")
    category = finding.get("category", "General")

    if severity in ("Critical", "High"):
        exploitability = "High"
        conf_impact = "High" if "Information Disclosure" in category else "Medium"
        integ_impact = "Medium"
        avail_impact = "High" if "TLS" in category and severity == "Critical" else "Low"
        rem_priority = "High"
    elif severity == "Medium":
        exploitability = "Medium"
        conf_impact = "Medium" if "Information Disclosure" in category else "Low"
        integ_impact = "Low"
        avail_impact = "Low"
        rem_priority = "Medium"
    else:
        exploitability = "Low"
        conf_impact = "Low"
        integ_impact = "Low"
        avail_impact = "Low"
        rem_priority = "Low"

    return {
        "severity": severity,
        "severity_method": finding.get("severity_method", "WorldGuard prototype rule"),
        "exploitability": exploitability,
        "confidentiality_impact": conf_impact,
        "integrity_impact": integ_impact,
        "availability_impact": avail_impact,
        "affected_role": finding.get("tested_role") or "Any User",
        "data_sensitivity": finding.get("data_sensitivity") or "General application configuration and network traffic",
        "business_impact": finding.get("business_impact") or "Potential compromise of system defensive controls and compliance standards.",
        "remediation_priority": rem_priority
    }


def enrich_finding_risk(finding: dict) -> dict:
    """
    Enriches a security finding with structured risk and business-impact analysis.
    Preserves all existing fields and adds deterministic risk fields.
    """
    enriched = dict(finding)
    evidence_id = finding.get("evidence_id")

    if evidence_id and evidence_id in EVIDENCE_RISK_RULES:
        rule_data = EVIDENCE_RISK_RULES[evidence_id]
        for field, value in rule_data.items():
            enriched[field] = value
    else:
        default_data = _derive_default_impact(finding)
        for field, value in default_data.items():
            if field not in enriched:
                enriched[field] = value

    return enriched


def enrich_findings_risk(findings: list[dict]) -> list[dict]:
    """Enriches a collection of security findings with risk and business-impact fields."""
    return [enrich_finding_risk(f) for f in findings]
