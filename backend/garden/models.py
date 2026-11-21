from collections.abc import Iterable
from dataclasses import dataclass
from graphlib import CycleError, TopologicalSorter
from pathlib import PurePosixPath
from typing import Annotated, Literal, get_args

import regex
from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from garden.path_masks import parse_masks


Kind = Literal["manual", "schedule", "git_event", "secrets", "sca", "sast", "condition", "explain", "webhook"]
GitEventName = Literal["push", "pull_request"]
Status = Literal["pending", "running", "succeeded", "warning", "failed", "skipped"]
AnalysisStatus = Literal["complete", "partial", "not_run"]
Severity = Literal["low", "medium", "high", "critical"]
FindingCategory = Literal["SECRET", "SAST", "SCA"]
ConditionPredicate = Literal["count_gte", "count_eq", "count_lte", "severity_eq", "severity_gte",
                             "category_eq", "path_matches", "rule_regex", "analysis_status_eq"]
OsvStatus = Literal["checked", "incomplete", "skipped"]
Branch = Literal["yes", "no"]
Destination = Literal["configured", "inbox", "https", "telegram", "email", "browser"]
Id = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
TRIGGERS = {"manual", "schedule", "git_event"}
ANALYZERS = ("secrets", "sast", "sca")
SEVERITY_LEVELS = get_args(Severity)


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class GitEvent(Model):
    name: GitEventName
    sha: str = Field(pattern=r"^[a-fA-F0-9]{40}$")


class Source(Model):
    path: str = Field(min_length=1, max_length=350)
    text: str = Field(max_length=300_000)

    @field_validator("path")
    @classmethod
    def relative_path(cls, value: str) -> str:
        path = PurePosixPath(value.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts or ":" in value or not path.name:
            raise ValueError("Укажите относительный путь файла")
        return path.as_posix()


class Target(Model):
    connection: Id
    model: str = Field(default="", max_length=180)

    @field_validator("model")
    @classmethod
    def trim_model(cls, value: str) -> str:
        return value.strip()


class Node(Model):
    id: Id
    kind: Kind
    x: float = Field(ge=-100_000, le=100_000)
    y: float = Field(ge=-100_000, le=100_000)
    pattern: str = Field(default="*", min_length=1, max_length=200)
    extended_sca: bool | None = None
    online_cve: bool = False
    cron: str = Field(default="0 9 * * *", max_length=100)
    enabled: bool = False
    git_events: list[GitEventName] = Field(default_factory=lambda: ["push", "pull_request"], max_length=2)
    predicate: ConditionPredicate = "count_gte"
    value: str = Field(default="1", max_length=160)
    connection: str = Field(default="ollama", max_length=64)
    model: str = Field(default="", max_length=180)
    targets: list[Target] = Field(default_factory=list, max_length=8)
    destination: Destination = "configured"

    def selected_models(self) -> list[Target]:
        return self.targets or [Target(connection=self.connection, model=self.model)]

    @model_validator(mode="after")
    def valid_settings(self):
        if self.kind in ANALYZERS:
            parse_masks(self.pattern)
        if self.online_cve and (self.kind != "sca" or self.extended_sca is False):
            raise ValueError("Онлайн-проверка OSV доступна в расширенном режиме SCA")
        if self.kind == "sca":
            # Older workflows used null for the server default and a separate online switch.
            self.extended_sca = self.extended_sca is not False
            self.online_cve = self.extended_sca
        if len({(t.connection, t.model) for t in self.targets}) != len(self.targets):
            raise ValueError("Такая модель уже выбрана")
        if self.kind == "schedule":
            CronTrigger.from_crontab(self.cron, timezone="Europe/Moscow")
        if self.kind == "git_event" and (not self.git_events or len(set(self.git_events)) != len(self.git_events)):
            raise ValueError("Выберите одно или два разных Git-события")
        if self.kind == "condition":
            predicate, value = self.predicate, self.value
            if predicate in {"count_gte", "count_eq", "count_lte"} and not (value.isascii() and value.isdecimal()):
                raise ValueError("Порог должен быть целым неотрицательным числом")
            if predicate in {"severity_eq", "severity_gte"} and value not in SEVERITY_LEVELS:
                raise ValueError("Выберите уровень важности")
            if predicate == "category_eq" and value not in get_args(FindingCategory):
                raise ValueError("Выберите категорию находок")
            if predicate == "analysis_status_eq" and value not in get_args(AnalysisStatus):
                raise ValueError("Выберите статус анализа")
            if predicate == "path_matches":
                parse_masks(value)
            if predicate == "rule_regex":
                try:
                    regex.compile(value)
                except regex.error as error:
                    raise ValueError("Некорректное регулярное выражение") from error
        return self


class Edge(Model):
    id: Id
    source: Id
    target: Id
    branch: Branch | None = None


class Blueprint(Model):
    name: str = Field(min_length=1, max_length=100)
    nodes: list[Node] = Field(min_length=1, max_length=40)
    edges: list[Edge] = Field(max_length=120)

    def git_triggers(self, event: GitEventName) -> list[str]:
        return [n.id for n in self.nodes if n.kind == "git_event" and event in n.git_events]

    def order(self) -> tuple[str, ...]:
        graph = TopologicalSorter()
        for node in self.nodes:
            graph.add(node.id)
        for edge in self.edges:
            graph.add(edge.target, edge.source)
        return tuple(graph.static_order())

    @model_validator(mode="after")
    def valid_workflow(self):
        nodes = {node.id: node.kind for node in self.nodes}
        if len(nodes) != len(self.nodes) or len({e.id for e in self.edges}) != len(self.edges):
            raise ValueError("Повторяющийся идентификатор в графе")
        if not TRIGGERS.intersection(nodes.values()):
            raise ValueError("Добавьте ручной запуск, расписание или Git-событие")
        targets = set()
        links = set()
        for edge in self.edges:
            if edge.source not in nodes or edge.target not in nodes:
                raise ValueError("Связь указывает на отсутствующий блок")
            if nodes[edge.target] in TRIGGERS:
                raise ValueError("Триггер должен начинать ветку")
            if (nodes[edge.source] == "condition") != (edge.branch is not None):
                raise ValueError("Выберите выход «Да» или «Нет» у условия")
            link = (edge.source, edge.target, edge.branch)
            if link in links:
                raise ValueError("Связь уже существует")
            links.add(link)
            targets.add(edge.target)
        if any(kind not in TRIGGERS and key not in targets for key, kind in nodes.items()):
            raise ValueError("Соедините все рабочие блоки с триггером")
        try:
            self.order()
        except CycleError as error:
            raise ValueError("В сценарии обнаружен цикл") from error
        return self


class Workflow(Blueprint):
    files: list[Source] = Field(max_length=400)

    @model_validator(mode="after")
    def valid_workflow(self):
        super().valid_workflow()
        if not self.files and any(node.kind in ANALYZERS for node in self.nodes):
            raise PydanticCustomError("missing_sources", "В проекте нет исходных файлов для проверки.")
        return self

    @model_validator(mode="after")
    def valid_files(self):
        if sum(len(file.text.encode()) for file in self.files) > 5_000_000:
            raise ValueError("Лимит проекта — 5 МБ")
        if len({file.path for file in self.files}) != len(self.files):
            raise ValueError("Пути файлов должны быть уникальными")
        return self


class Dependency(Model):
    group: str
    artifact: str
    version: str


class Finding(Model):
    id: str
    rule: str
    severity: Severity
    path: str
    line: int
    column: int
    title: str
    fix: str
    advisory: str | None = None
    advisory_url: str | None = None
    severity_estimated: bool = False
    fixed_version: str | None = None
    classification: str | None = None
    dependency: Dependency | None = None

    category: FindingCategory

    @model_validator(mode="before")
    @classmethod
    def fill_category(cls, data):
        # Local runs from the first prototype predate the competition report format.
        if isinstance(data, dict) and "category" not in data:
            category = "SCA" if data.get("advisory") else "SECRET" if data.get("rule", "").startswith("SECRET-") else "SAST"
            return {**data, "category": category}
        return data


class Advice(Model):
    finding_ids: list[str] = Field(min_length=1)
    risk: str = Field(min_length=1, max_length=1200)
    fix: str = Field(min_length=1, max_length=1200)


class Report(Model):
    groups: list[Advice]


class Review(Target):
    label: str
    status: Literal["running", "succeeded", "failed", "skipped"]
    message: str = ""
    report: Report | None = None


class Receipt(Model):
    run_id: Id
    findings: list[Finding]
    reports: list[Report]
    reviews: list[Review] = Field(default_factory=list)
    analysis_status: AnalysisStatus | None = None


class WebhookDelivery(Model):
    state: Literal["pending", "attempted", "delivered", "not_sent", "unknown"]
    payload: Receipt | None = None
    browser_report: bool | None = None


class BrowserReportNotice(Model):
    run_id: Id
    node_id: Id
    name: str
    created_at: str
    project_id: Id | None = None


class BrowserReport(BrowserReportNotice):
    payload: Receipt


class LockAdvisory(Model):
    id: str
    severity: Severity
    advisory_url: str | None = None
    severity_estimated: bool = False


@dataclass(frozen=True)
class PackageCheck:
    path: str
    line: int
    package: str
    version: str | None
    source: str
    status: Literal["checked", "outside-catalog", "unresolved"]
    osv_status: OsvStatus | None = None


class LockedPackage(Model):
    package: str
    version: str
    path: str
    line: int
    configurations: list[str]
    scope: Literal["transitive", "unclassified"]
    status: Literal["checked", "outside-catalog", "unresolved"]
    osv_status: OsvStatus | None = None
    advisories: list[LockAdvisory] = Field(default_factory=list)


class LockReport(Model):
    files: list[str] = Field(default_factory=list)
    packages: list[LockedPackage] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)

    @property
    def checked(self) -> int:
        return sum(p.status == "checked" or p.osv_status == "checked" for p in self.packages)


class Step(Model):
    node_id: str
    kind: Kind
    status: Status = "pending"
    skip_reason: Literal["inactive", "upstream_failure", "interrupted"] | None = None
    message: str = ""
    input_ids: list[str] = Field(default_factory=list)
    output_ids: list[str] = Field(default_factory=list)
    branch: Branch | None = None
    report: Report | None = None
    reviews: list[Review] = Field(default_factory=list)
    packages: list[PackageCheck] = Field(default_factory=list)
    lockfile: LockReport | None = None
    webhook_attempted: bool | None = None


def analysis_status_for(steps: Iterable[Step]) -> AnalysisStatus:
    analyzers = [step for step in steps if step.kind in ANALYZERS and step.skip_reason != "inactive"]
    if not any(step.status in {"running", "succeeded", "warning", "failed"} for step in analyzers):
        return "not_run"
    return "complete" if all(step.status == "succeeded" for step in analyzers) else "partial"


class Run(Model):
    id: str
    name: str
    started: str
    trigger: str
    git_event: GitEvent | None = None
    status: Status = "running"
    steps: list[Step]
    findings: list[Finding] = Field(default_factory=list)
    analysis_status: AnalysisStatus | None = None

    @property
    def ran_analyzer(self) -> bool:
        return any(step.kind in ANALYZERS and step.status in {"succeeded", "warning", "failed"}
                   for step in self.steps)

    @property
    def analysis_complete(self) -> bool:
        if self.analysis_status is None:  # Historical runs only recorded the overall workflow result.
            return self.status == "succeeded" and self.ran_analyzer
        return self.analysis_status == "complete"


class RunSummary(Model):
    id: str
    name: str
    started: str
    status: Status
    git_event: GitEvent | None = None


class ConnectionInfo(Model):
    id: str
    label: str
    model: str


class PublicConnection(ConnectionInfo):
    configured: bool
    local_key_entry: bool = False


def demo() -> Workflow:
    return Workflow(
        name="Проверка учебного проекта",
        nodes=[Node(id="start", kind="manual", x=30, y=75), Node(id="scan", kind="secrets", x=330, y=75)],
        edges=[Edge(id="start-scan", source="start", target="scan")],
        files=[Source(path="src/main/kotlin/Demo.kt", text=(
            'package training\n\nobject Demo {\n    val apiKey = "garden-demo-value"\n}\n'
        ))],
    )
