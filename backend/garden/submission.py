"""Competition JSON and readable output are projections of the same scanner findings."""
import re

from garden.models import Finding


def row(finding: Finding) -> dict:
    result = {"category": finding.category, "path": finding.path, "severity": finding.severity.upper(),
              "description": finding.title, "remediation": finding.fix}
    if finding.category == "SCA":
        dependency = finding.dependency
        if dependency is not None:
            result.update(dependency.model_dump())
        else:
            # Older local runs stored coordinates only in the detector's generated title.
            match = re.match(r"^([\w.-]+):([\w.-]+) ([0-9.]+) входит в диапазон ", finding.title)
            if not match:
                raise ValueError("Для выгрузки старого отчёта повторите проверку зависимостей")
            result.update(zip(("group", "artifact", "version"), match.groups()))
        result["advisoryId"] = finding.advisory
    else:
        result["class"] = finding.classification or (
            "route-authorization" if finding.rule == "SPRING-OPEN-DEFAULT" else finding.rule)
        result["line"] = finding.line
    return result


def submission(findings: list[Finding]) -> dict:
    return {"findings": [row(f) for f in findings]}
