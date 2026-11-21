"""Merge opt-in OSV Maven checks into the direct and locked inventories."""
from collections import defaultdict
from dataclasses import replace

import httpx

from garden import osv_client
from garden.maven import Entry
from garden.models import Dependency, LockAdvisory, Source
from garden.scanners import Analysis, finding


def queryable(package: str, version: str | None) -> bool:
    return len(package) <= 256 and bool(osv_client.PACKAGE.fullmatch(package)) and osv_client.exact_version(version)


def advisory_index(entries: list[Entry], online: osv_client.OsvResult):
    # A local GHSA and an OSV record can be joined through a third record's CVE alias.
    parents = {}

    def root(identifier):
        key = identifier.upper()
        parents.setdefault(key, key)
        while key != parents[key]:
            parents[key] = parents[parents[key]]
            key = parents[key]
        return key

    for record in (*entries, *online.advisories):
        group = root(record.id)
        for alias in record.aliases:
            parents[root(alias)] = group

    groups = {alias: root(alias) for alias in parents}
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    bulletins = {}
    for record in sorted(online.advisories, key=lambda a: (-levels.get(a.severity, 0), not a.id.startswith("CVE-"), a.id)):
        bulletins.setdefault(groups[record.id.upper()], record)
    return groups, bulletins


def matched_advisories(local, index):
    """Retain the first local finding in each equivalence class and attach its online record."""
    groups, bulletins = index
    seen = set()
    for identifier, existing in local:
        key = groups.get(identifier.upper(), identifier.upper())
        if key not in seen:
            seen.add(key)
            yield existing, bulletins.get(key)
    for key, record in bulletins.items():
        if key not in seen:
            yield None, record


def new_finding(file, row, record):
    group, artifact = row.package.split(":")
    title = f"OSV указывает {record.id} для {row.package} {row.version}."
    if record.severity is None:
        title += " Важность в OSV не указана. В отчёте принят средний уровень."
    fix = (f"Проверьте обновление до {record.fixed_version} для устранения {record.id}."
           if record.fixed_version else f"Сверьте исправленные версии {row.package} в записи OSV.")
    hit = finding(file, "GRADLE-OSV-ADVISORY", row.line, 1, title, fix, record.severity or "medium",
                  record.id, f"{row.package}@{row.version}")
    hit.dependency = Dependency(group=group, artifact=artifact, version=row.version)
    hit.advisory_url = record.url
    hit.fixed_version = record.fixed_version
    hit.severity_estimated = record.severity is None
    return hit


def check_inventory(analysis: Analysis, files: dict[str, Source], entries: dict[str, list[Entry]]) -> None:
    rows = [*analysis.packages, *analysis.lockfile.packages]
    coordinates = {(p.package, p.version) for p in rows if queryable(p.package, p.version)}
    results = {}
    if coordinates:
        try:
            results = osv_client.check_maven(sorted(coordinates))
        except (httpx.HTTPError, OSError, ValueError):
            # The offline findings and every successfully parsed declaration remain available.
            pass
    missing = osv_client.OsvResult(error="OSV не вернул результат")
    indexes = {key: advisory_index(entries.get(key[0], []), reply) for key, reply in results.items() if reply.advisories}

    def status(row, issues):
        if (row.package, row.version) not in coordinates:
            issues.add(f"OSV: координаты или версия не определены в {row.path}, строка {row.line} ({row.package})")
            return "skipped"
        response = results.get((row.package, row.version), missing)
        if not response.complete:
            issues.add(f"OSV: неполная проверка {row.package} {row.version}: {response.error}")
            return "incomplete"
        return "checked"

    by_location = defaultdict(list)
    for hit in analysis.findings:
        dep = hit.dependency
        if dep is not None and hit.advisory:
            by_location[hit.path, hit.line, f"{dep.group}:{dep.artifact}", dep.version].append(hit)
    direct_issues = set()
    suppressed = set()
    processed = set()
    for i, row in enumerate(analysis.packages):
        key = row.package, row.version
        analysis.packages[i] = replace(row, osv_status=status(row, direct_issues))
        loc = row.path, row.line, *key
        if loc in processed or key not in indexes:
            continue
        processed.add(loc)
        local = by_location[loc]
        retained = set()
        for existing, record in matched_advisories(((hit.advisory, hit) for hit in local), indexes[key]):
            if existing is None:
                analysis.findings.append(new_finding(files[row.path], row, record))
            else:
                retained.add(existing.id)
                if record is not None:
                    existing.advisory_url = record.url
        suppressed.update(hit.id for hit in local if hit.id not in retained)
    if suppressed:
        analysis.findings[:] = [hit for hit in analysis.findings if hit.id not in suppressed]
    analysis.issues.extend(sorted(direct_issues))

    lock_issues = set()
    for row in analysis.lockfile.packages:
        key = row.package, row.version
        row.osv_status = status(row, lock_issues)
        if key not in indexes:
            continue
        advisories = []
        for existing, record in matched_advisories(((a.id, a) for a in row.advisories), indexes[key]):
            if existing is None:
                existing = LockAdvisory(id=record.id, severity=record.severity or "medium", severity_estimated=record.severity is None)
            if record is not None:
                existing.advisory_url = record.url
            advisories.append(existing)
        row.advisories = advisories
    analysis.lockfile.issues.extend(sorted(lock_issues))
