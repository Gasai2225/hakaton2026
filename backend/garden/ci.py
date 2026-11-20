"""Run the editor's three static checks on a checked-out project."""
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from garden.scanners import analyze
from garden.scenarios import sources
from garden.submission import submission


def check(root: Path, output: Path, sca_inventory: Path | None = None) -> int:
    files = sources(root)
    findings = []
    issues = []
    lock_critical = 0
    for kind in ("secrets", "sast", "sca"):
        analysis = analyze(kind, files, "*")
        findings.extend(analysis.findings)
        issues.extend(analysis.issues)
        if kind == "sca":
            print(f"Maven declarations checked: {analysis.checked_packages}/{len(analysis.packages)}")
            lock = analysis.lockfile
            if lock.files:
                advisories = [a for p in lock.packages for a in p.advisories]
                lock_critical = sum(a.severity == "critical" for a in advisories)
                print(f"Additional locked versions checked: {lock.checked}/{len(lock.packages)}, "
                      f"advisories: {len(advisories)}, critical: {lock_critical}")
                issues.extend(lock.issues)
            if sca_inventory is not None:
                sca_inventory.parent.mkdir(parents=True, exist_ok=True)
                inventory = {"checked": analysis.checked_packages, "total": len(analysis.packages),
                             "packages": [asdict(p) for p in analysis.packages], "issues": analysis.issues,
                             "lockfile": lock.model_dump()}
                sca_inventory.write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(submission(findings), ensure_ascii=False, indent=2), encoding="utf-8")
    critical = sum(f.severity == "critical" for f in findings)
    print(f"Files: {len(files)}, findings: {len(findings)}, critical: {critical}")
    if issues:
        print("\n".join(dict.fromkeys(issues)), file=sys.stderr)
        return 2
    return int(critical > 0 or lock_critical > 0)


def main() -> int:
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--project", type=Path, required=True)
    args.add_argument("--output", type=Path, required=True)
    args.add_argument("--sca-inventory", type=Path)
    options = args.parse_args()
    try:
        return check(options.project, options.output, options.sca_inventory)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
