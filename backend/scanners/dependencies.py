import os
import re
import importlib.metadata
import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

REQ_PATTERN = re.compile(
    r"^\s*([a-zA-Z0-9_\.\-]+)(?:\[[^\]]*\])?\s*([<>=!~].*)?$"
)


def parse_requirement_line(line: str) -> tuple[str, str | None, str | None] | None:
    """
    Safely parses a single requirement line.
    Returns: (package_name, version_constraint, exact_version) or None if ignored.
    Does not execute any code.
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None

    # Strip inline comments and environment markers
    cleaned = line.split(" #")[0].split(";")[0].strip()
    if not cleaned:
        return None

    match = REQ_PATTERN.match(cleaned)
    if not match:
        return None

    package_name = match.group(1).strip()
    version_constraint = match.group(2).strip() if match.group(2) else None

    exact_version = None
    if version_constraint:
        exact_match = re.match(
            r"^={2,3}\s*['\"]?([a-zA-Z0-9_\.\-]+)['\"]?",
            version_constraint
        )
        if exact_match:
            exact_version = exact_match.group(1)

    return package_name, version_constraint, exact_version


def _map_osv_severity(vuln: dict) -> str:
    """Maps OSV severity metadata to Critical, High, Medium, Low, or Info."""
    db_spec = vuln.get("database_specific", {})
    if isinstance(db_spec, dict) and "severity" in db_spec:
        sev_str = str(db_spec["severity"]).strip().upper()
        if sev_str == "CRITICAL":
            return "Critical"
        if sev_str == "HIGH":
            return "High"
        if sev_str in ("MODERATE", "MEDIUM"):
            return "Medium"
        if sev_str == "LOW":
            return "Low"

    severities = vuln.get("severity", [])
    if isinstance(severities, list):
        for entry in severities:
            if isinstance(entry, dict) and "score" in entry:
                try:
                    score_num = float(entry["score"])
                    if score_num >= 9.0:
                        return "Critical"
                    if score_num >= 7.0:
                        return "High"
                    if score_num >= 4.0:
                        return "Medium"
                    return "Low"
                except (ValueError, TypeError):
                    pass

    return "Medium"


def _extract_affected_info(vuln: dict, package_name: str) -> tuple[str, str | None]:
    """Extracts human-readable affected versions and the first fixed version."""
    fixed_versions = []
    affected_ranges = []

    for item in vuln.get("affected", []):
        pkg = item.get("package", {})
        if pkg.get("name", "").lower() == package_name.lower():
            for rng in item.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])
                    if "introduced" in event and event["introduced"] != "0":
                        affected_ranges.append(f">= {event['introduced']}")

    fixed_str = fixed_versions[0] if fixed_versions else None
    if fixed_versions:
        affected_summary = f"< {fixed_versions[0]}"
    elif affected_ranges:
        affected_summary = ", ".join(affected_ranges)
    else:
        affected_summary = "All versions"

    return affected_summary, fixed_str


def _query_osv_package(package_name: str, version: str | None = None) -> list[dict]:
    """Queries the OSV public API for a single PyPI package."""
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        }
    }
    if version:
        payload["version"] = version

    response = httpx.post(
        OSV_QUERY_URL,
        json=payload,
        timeout=10
    )
    if response.status_code == 200:
        return response.json().get("vulns", [])
    return []


def scan_dependencies(project_path: str):
    findings = []
    packages_found = []

    if os.path.isfile(project_path):
        requirements_file = project_path
    else:
        requirements_file = os.path.join(project_path, "requirements.txt")

    if not os.path.exists(requirements_file):
        return {
            "target": project_path,
            "requirements_file": None,
            "packages_found": [],
            "findings": []
        }

    try:
        with open(requirements_file, "r", encoding="utf-8") as file:
            lines = file.readlines()
    except Exception as e:
        return {
            "target": project_path,
            "requirements_file": requirements_file,
            "packages_found": [],
            "findings": [],
            "error": f"Failed to read requirements file: {str(e)}"
        }

    parsed_dependencies = []
    for line in lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue
        packages_found.append(line_clean)

        parsed = parse_requirement_line(line_clean)
        if parsed:
            parsed_dependencies.append(parsed)

    seen_vulns = set()

    for package_name, version_constraint, exact_version in parsed_dependencies:
        # Determine the version to test against OSV
        tested_version = exact_version
        if not tested_version:
            try:
                tested_version = importlib.metadata.version(package_name)
            except Exception:
                tested_version = None

        try:
            vulns = _query_osv_package(package_name, tested_version)
        except Exception as e:
            return {
                "target": project_path,
                "requirements_file": requirements_file,
                "packages_found": packages_found,
                "findings": findings,
                "error": f"OSV vulnerability lookup error for {package_name}: {str(e)}"
            }

        for vuln in vulns:
            vuln_id = vuln.get("id", "Unknown Advisory")
            unique_key = (package_name.lower(), vuln_id)
            if unique_key in seen_vulns:
                continue
            seen_vulns.add(unique_key)

            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
            display_id = cve_id or vuln_id

            severity = _map_osv_severity(vuln)
            affected_summary, fixed_str = _extract_affected_info(vuln, package_name)

            summary_text = vuln.get("summary") or vuln.get("details", "")
            if fixed_str:
                description = f"{summary_text} Fixed in version: {fixed_str}."
            else:
                description = summary_text

            reference_urls = [
                ref["url"]
                for ref in vuln.get("references", [])
                if isinstance(ref, dict) and "url" in ref
            ][:5]

            finding = {
                "title": f"Vulnerable Dependency: {package_name} ({display_id})",
                "severity": severity,
                "category": "Dependency Security",
                "description": description,
                "package": package_name,
                "version_constraint": version_constraint,
                "installed_version": tested_version,
                "advisory_id": vuln_id,
                "cve_id": cve_id,
                "aliases": aliases,
                "summary": vuln.get("summary", ""),
                "affected_versions": affected_summary,
                "fixed_version": fixed_str,
                "references": reference_urls
            }
            findings.append(finding)

    return {
        "target": project_path,
        "requirements_file": requirements_file,
        "packages_found": packages_found,
        "findings": findings
    }