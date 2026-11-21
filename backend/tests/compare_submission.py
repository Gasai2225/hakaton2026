"""Compare an exported competition report with an independent training-findings.json."""
import argparse
import json
import sys
from pathlib import Path


def matches(row: dict, reference: dict) -> bool:
    if row["category"] != reference["category"]:
        return False
    path = row["path"].replace("\\", "/")
    if row["category"] == "SCA":
        return (path == reference["path"].replace("\\", "/")
                and all(row[k] == reference[k] for k in ("group", "artifact", "version"))
                and row["advisoryId"] in reference["advisoryIds"])
    if row["class"] != reference["class"]:
        return False
    return any(path == loc["path"].replace("\\", "/") and loc["line"] <= row["line"] <= loc["endLine"]
               for loc in [reference, *reference.get("alternateLocations", [])])


def records(document: dict, key: str, *, reference: bool) -> list[dict]:
    data = document.get(key) if isinstance(document, dict) else None
    label = ("reference" if reference else "report") + "." + key
    if not isinstance(data, list):
        raise ValueError(f"{label} must be an array")
    ids_seen = set()
    for number, row in enumerate(data, 1):
        error = ValueError(f"Invalid matching fields in {label} #{number}")
        if not isinstance(row, dict) or row.get("category") not in ("SECRET", "SAST", "SCA"):
            raise error
        if reference and "id" in row:
            if not isinstance(row["id"], str) or not row["id"]:
                raise error
            if row["id"] in ids_seen:
                raise ValueError(f"Duplicate label ID in {label} #{number}")
            ids_seen.add(row["id"])
        if "severity" in row and (not isinstance(row["severity"], str) or not row["severity"]):
            raise error
        fields = ["path"]
        if row["category"] == "SCA":
            fields.extend(["group", "artifact", "version"])
            if reference:
                ids = row.get("advisoryIds")
                if not isinstance(ids, list) or not ids or not all(isinstance(it, str) and it for it in ids):
                    raise error
            else:
                fields.append("advisoryId")
        else:
            fields.append("class")
            alternates = row.get("alternateLocations", []) if reference else []
            if not isinstance(alternates, list):
                raise error
            for loc in [row, *alternates]:
                if not isinstance(loc, dict) or not isinstance(loc.get("path"), str) or type(loc.get("line")) is not int:
                    raise error
                end = loc.get("endLine", None if reference else loc["line"])
                if loc["line"] < 1 or type(end) is not int or end < loc["line"] or (not reference and end > loc["line"] + 14):
                    raise error
        if not all(isinstance(row.get(key), str) and row[key].strip() for key in fields):
            raise error
    return data


def compare(report: dict, reference: dict) -> list[str]:
    rows = records(report, "findings", reference=False)
    expected = records(reference, "findings", reference=True)
    controls = records(reference, "controls", reference=True)
    counts = [0] * len(expected)
    errors = []
    for number, row in enumerate(rows, 1):
        labels = [i for i, item in enumerate(expected) if matches(row, item)]
        for i in labels:
            counts[i] += 1
        if not labels:
            errors.append(f"Unexpected report finding #{number}")
        elif len(labels) > 1:
            errors.append(f"Ambiguous report finding #{number} matches {len(labels)} reference findings")
        else:
            item = expected[labels[0]]
            if "severity" in item and row.get("severity") != item["severity"]:
                errors.append(f"Severity mismatch for report finding #{number} and reference finding #{labels[0] + 1}")
        for i, control in enumerate(controls, 1):
            if matches(row, control):
                errors.append(f"Report finding #{number} matches negative control #{i}")
    for i, count in enumerate(counts, 1):
        if count != 1:
            errors.append(f"Reference finding #{i} matched {count} times (expected once)")
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("reference", type=Path)
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_bytes())
        reference = json.loads(args.reference.read_bytes())
        errors = compare(report, reference)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Cannot compare inputs: {error}", file=sys.stderr)
        return 2
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Matched {len(report['findings'])}/{len(reference['findings'])} findings. "
          f"Negative controls matched: 0/{len(reference['controls'])}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
