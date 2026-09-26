def calculate_summary(findings):
    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for finding in findings:
        severity = finding.get("severity", "Info")

        if severity in summary:
            summary[severity] += 1

    total = len(findings)

    if summary["Critical"] > 0:
        risk_level = "Critical"
    elif summary["High"] > 0:
        risk_level = "High"
    elif summary["Medium"] > 0:
        risk_level = "Medium"
    elif summary["Low"] > 0:
        risk_level = "Low"
    else:
        risk_level = "Info"

    return {
        "risk_level": risk_level,
        "total_findings": total,
        "severity_counts": summary
    }