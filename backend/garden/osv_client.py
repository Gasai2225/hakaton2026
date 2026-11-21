"""Read OSV's Maven advisories for exact component versions."""

import json
import re
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from time import monotonic

import httpx
from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

from garden.maven import DATED_SNAPSHOT, version
from garden.models import Severity


Coordinate = tuple[str, str]
PACKAGE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,150}")
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
LEVELS = ("low", "medium", "high", "critical")
BATCH_SIZE = 100
MAX_COORDINATES = 2048
MAX_REQUESTS = 128
MAX_BYTES = 4 * 1024 * 1024
MAX_SECONDS = 30


def exact_version(value: str | None) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= 160
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value) is not None
            and any(c.isdigit() for c in value) and not value.endswith("+")
            and not value.upper().endswith("-SNAPSHOT") and not value.lower().startswith("latest."))


@dataclass(frozen=True)
class OsvAdvisory:
    id: str
    aliases: tuple[str, ...]
    severity: Severity | None
    fixed_version: str | None
    url: str


@dataclass(frozen=True)
class OsvResult:
    advisories: tuple[OsvAdvisory, ...] = ()
    error: str | None = None

    @property
    def complete(self) -> bool:
        return self.error is None


class OsvError(ValueError):
    pass


def objects(value) -> list[dict]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise OsvError("Некорректный список в ответе OSV")
    return value


def strings(value) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(s, str) and s for s in value):
        raise OsvError("Некорректный список строк в записи OSV")
    return value


def timestamp(value) -> datetime | None:
    if not isinstance(value, str) or len(value) > 48 or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def rating(record: dict) -> Severity | None:
    for key in ("database_specific", "ecosystem_specific"):
        metadata = record.get(key)
        label = metadata.get("severity") if isinstance(metadata, dict) else None
        if isinstance(label, str):
            label = label.lower()
            if label in LEVELS:
                return label
            if label == "moderate":
                return "medium"
    levels = []
    for entry in objects(record.get("severity", [])):
        kind = entry.get("type")
        if not isinstance(kind, str):
            raise OsvError("Некорректная оценка серьёзности OSV")
        parser = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}.get(kind)
        vector = entry.get("score")
        if parser and isinstance(vector, str) and len(vector) <= 512:
            try:
                level = parser(vector).severities()[0].lower()
            except CVSSError:
                continue
            if level in LEVELS:
                levels.append(level)
    return max(levels, key=LEVELS.index, default=None)


@dataclass(frozen=True)
class AffectedRange:
    start: str
    end: str | None
    event: str | None

    def contains(self, v: str) -> bool:
        if self.start != "0" and version(v) < version(self.start):
            return False
        return self.end is None or version(v) < version(self.end) or (self.event == "last_affected" and version(v) == version(self.end))


def intervals(events) -> list[AffectedRange]:
    boundaries = []
    limits = []
    for entry in objects(events):
        if len(entry) != 1:
            raise OsvError("Некорректная граница Maven-диапазона OSV")
        kind, value = next(iter(entry.items()))
        if kind not in {"introduced", "fixed", "last_affected", "limit"} or not isinstance(value, str) or not value or len(value) > 160:
            raise OsvError("Некорректная граница Maven-диапазона OSV")
        if kind == "limit":
            limits.append(value)
        else:
            boundaries.append((kind, value))
    # OSV event arrays are not guaranteed to be sorted. A fix at the same
    # version as a new introduction closes the earlier interval first.
    boundaries.sort(key=lambda b: (b != ("introduced", "0"), version(b[1]), {"fixed": 0, "introduced": 1}.get(b[0], 2)))
    start = None
    result = []
    for kind, value in boundaries:
        if kind == "introduced" and start is None:
            start = value
        elif kind != "introduced" and start is not None:
            result.append(AffectedRange(start, value, kind))
            start = None
        else:
            raise OsvError("Неполный Maven-диапазон OSV")
    if start is not None:
        result.append(AffectedRange(start, None, None))
    if not result:
        raise OsvError("Пустой Maven-диапазон OSV")
    if limits and "*" not in limits:
        # A limit caps the whole range and is not evidence of a fix.
        cap = max(limits, key=version)
        clipped = []
        for r in result:
            if r.start != "0" and version(r.start) >= version(cap):
                continue
            if r.end is None or version(r.end) > version(cap) or (version(r.end) == version(cap) and r.event == "last_affected"):
                r = AffectedRange(r.start, cap, "limit")
            clipped.append(r)
        return clipped
    return result


def advisory(record: dict, identifier: str, coord: Coordinate) -> OsvAdvisory | None:
    if record.get("id") != identifier or not timestamp(record.get("modified")):
        raise OsvError("Неполная карточка уязвимости OSV")
    if "withdrawn" in record:
        if not timestamp(record["withdrawn"]):
            raise OsvError("Некорректная отметка об отзыве записи OSV")
        return None
    package, ver = coord
    affected = []
    for item in objects(record.get("affected")):
        spec = item.get("package")
        if isinstance(spec, dict) and spec.get("name") == package and spec.get("ecosystem") == "Maven":
            affected.append(item)
    if not affected:
        raise OsvError("Карточка OSV не подтверждает Maven-координаты")
    ranges, listed, scoped = [], set(), []
    unknown_ranges = False
    for item in affected:
        before = len(ranges)
        versions = strings(item.get("versions", []))
        listed.update(versions)
        for item_range in objects(item.get("ranges", [])):
            if item_range.get("type") != "ECOSYSTEM":
                unknown_ranges = True
                continue
            ranges.extend(intervals(item_range.get("events")))
        if ver in versions or any(r.contains(ver) for r in ranges[before:]):
            level = rating(item)
            if level:
                scoped.append(level)
    matched = [r for r in ranges if r.contains(ver)]
    if not matched and ver not in listed:
        raise OsvError("Карточка OSV не подтверждает запрошенную версию Maven")
    candidates = {r.end for r in matched if r.event == "fixed" and exact_version(r.end)}
    fixed = None if unknown_ranges else min((v for v in candidates if v not in listed and not any(r.contains(v) for r in ranges)),
                                            key=version, default=None)
    aliases = set(strings(record.get("aliases", []))) | {identifier}
    if not all(ID.fullmatch(a) for a in aliases):
        raise OsvError("Некорректный идентификатор уязвимости OSV")
    canonical = min((a for a in aliases if CVE.fullmatch(a)), default=identifier)
    return OsvAdvisory(canonical, tuple(sorted(aliases)), max(scoped, key=LEVELS.index) if scoped else rating(record),
                       fixed, f"https://osv.dev/vulnerability/{identifier}")


def merge_aliases(advisories: Iterable[OsvAdvisory]) -> tuple[OsvAdvisory, ...]:
    groups: list[OsvAdvisory] = []
    for item in advisories:
        overlap = [a for a in groups if not set(a.aliases).isdisjoint(item.aliases)]
        if not overlap:
            groups.append(item)
            continue
        groups = [a for a in groups if a not in overlap]
        merged = [*overlap, item]
        aliases = sorted({name for a in merged for name in a.aliases})
        canonical = next((a for a in aliases if CVE.fullmatch(a)), min(a.id for a in merged))
        fixes = {a.fixed_version for a in merged}
        severity = max((a.severity for a in merged if a.severity), key=LEVELS.index, default=None)
        groups.append(OsvAdvisory(canonical, tuple(aliases), severity, fixes.pop() if len(fixes) == 1 else None,
                                  min(a.url for a in merged)))
    return tuple(sorted(groups, key=lambda a: a.id))


class Session:
    def __init__(self, client: httpx.Client):
        self.client = client
        self.deadline = monotonic() + MAX_SECONDS
        self.requests = 0

    def request(self, path: str, body: dict | None = None) -> dict:
        time_left = self.deadline - monotonic()
        if self.requests >= MAX_REQUESTS or time_left <= 0:
            raise OsvError("Достигнут лимит запросов или времени OSV")
        self.requests += 1
        try:
            with self.client.stream("GET" if body is None else "POST", path, json=body, timeout=min(6.0, time_left)) as response:
                response.raise_for_status()
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise OsvError("OSV вернул неподдерживаемое сжатие ответа")
                raw = bytearray()
                for part in response.iter_bytes(chunk_size=65536):
                    if len(raw) + len(part) > MAX_BYTES or monotonic() >= self.deadline:
                        raise OsvError("Превышен лимит размера или времени ответа OSV")
                    raw.extend(part)
        except httpx.HTTPError as exc:
            status = f" (HTTP {exc.response.status_code})" if isinstance(exc, httpx.HTTPStatusError) else ""
            raise OsvError("Не удалось получить ответ OSV" + status) from exc
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise OsvError("Некорректный JSON ответа OSV") from exc
        if not isinstance(data, dict):
            raise OsvError("Некорректный ответ OSV")
        return data


def check_maven(coordinates: Iterable[Coordinate], *, transport: httpx.BaseTransport | None = None) -> dict[Coordinate, OsvResult]:
    owners: dict[Coordinate, list[Coordinate]] = defaultdict(list)
    errors: dict[Coordinate, set[str]] = defaultdict(set)
    invalid = {}
    hits: dict[Coordinate, list[OsvAdvisory]] = defaultdict(list)
    inputs = list(dict.fromkeys(coordinates))
    for i, coord in enumerate(inputs):
        package, ver = coord
        if i >= MAX_COORDINATES or not isinstance(package, str) or len(package) > 256 or not PACKAGE.fullmatch(package) or not exact_version(ver):
            invalid[coord] = OsvResult(error="Недопустимые координаты или превышен лимит пакетов OSV")
            continue
        owners[coord].append(coord)
        if snapshot := DATED_SNAPSHOT.fullmatch(ver):
            owners[(package, snapshot[1] + "-SNAPSHOT")].append(coord)
    if not owners:
        return invalid

    pending = deque((q, "") for q in owners)
    pages: dict[Coordinate, set[str]] = defaultdict(set)
    references: dict[str, dict[Coordinate, datetime]] = defaultdict(dict)
    with httpx.Client(base_url="https://api.osv.dev", transport=transport, follow_redirects=False,
                      headers={"Accept": "application/json", "Accept-Encoding": "identity"}) as client:
        session = Session(client)
        while pending:
            batch = [pending.popleft() for _ in range(min(len(pending), BATCH_SIZE))]
            queries = [{"package": {"ecosystem": "Maven", "name": p}, "version": v, **({"page_token": t} if t else {})}
                       for (p, v), t in batch]
            try:
                result = session.request("/v1/querybatch", {"queries": queries}).get("results")
                if not isinstance(result, list) or len(result) != len(batch):
                    raise OsvError("Число результатов OSV не совпадает с числом запросов")
            except OsvError as exc:
                for q, _ in batch:
                    errors[q].add(str(exc))
                continue
            for (q, _), row in zip(batch, result):
                try:
                    if not isinstance(row, dict) or row.keys() - {"vulns", "next_page_token"}:
                        raise OsvError("Некорректный результат OSV по пакету")
                    for stub in objects(row.get("vulns", [])):
                        key = stub.get("id")
                        if not isinstance(key, str) or not ID.fullmatch(key):
                            raise OsvError("Некорректный идентификатор уязвимости OSV")
                        modified = timestamp(stub.get("modified"))
                        if modified is None:
                            raise OsvError("Неполная запись в списке OSV")
                        if key not in references and len(references) >= MAX_REQUESTS:
                            raise OsvError("Достигнут лимит карточек OSV")
                        references[key][q] = max(references[key].get(q, modified), modified)
                    token = row.get("next_page_token", "")
                    if not isinstance(token, str) or len(token) > 8192 or token in pages[q]:
                        raise OsvError("Некорректная пагинация OSV")
                    if token:
                        pages[q].add(token)
                        pending.append((q, token))
                except OsvError as exc:
                    errors[q].add(str(exc))
        for identifier, queries in references.items():
            try:
                record = session.request(f"/v1/vulns/{identifier}")
            except OsvError as exc:
                for q in queries:
                    errors[q].add(str(exc))
                continue
            updated = timestamp(record.get("modified"))
            for q, listed_at in queries.items():
                try:
                    if updated is None or updated < listed_at:
                        raise OsvError("Версия карточки OSV отстаёт от списка уязвимостей")
                    item = advisory(record, identifier, q)
                    if item is not None:
                        for coord in owners[q]:
                            hits[coord].append(item)
                except OsvError as exc:
                    errors[q].add(str(exc))
    for q, coords in owners.items():
        for coord in coords:
            errors[coord].update(errors[q])
    return {k: invalid.get(k) or OsvResult(merge_aliases(hits[k]), ", ".join(sorted(errors[k])) or None) for k in inputs}
