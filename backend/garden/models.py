from graphlib import CycleError, TopologicalSorter
from pathlib import PurePosixPath
from typing import Annotated, Literal

import regex
from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Kind = Literal["manual", "schedule", "secrets", "sca", "sast", "condition", "explain", "webhook"]
Status = Literal["pending", "running", "succeeded", "warning", "failed", "skipped"]
Severity = Literal["low", "medium", "high", "critical"]
Branch = Literal["yes", "no"]
Id = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
TRIGGERS = {"manual", "schedule"}


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


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
    cron: str = Field(default="0 9 * * *", max_length=100)
    enabled: bool = False
    predicate: Literal["count_gte", "severity_eq", "rule_regex"] = "count_gte"
    value: str = Field(default="1", max_length=160)
    connection: str = Field(default="ollama", max_length=64)
    model: str = Field(default="", max_length=180)
    targets: list[Target] = Field(default_factory=list, max_length=8)
    destination: Literal["configured", "inbox"] = "configured"

    def selected_models(self) -> list[Target]:
        return self.targets or [Target(connection=self.connection, model=self.model)]

    @model_validator(mode="after")
    def valid_settings(self):
        if len({(t.connection, t.model) for t in self.targets}) != len(self.targets):
            raise ValueError("Такая модель уже выбрана")
        if self.kind == "schedule":
            CronTrigger.from_crontab(self.cron, timezone="Europe/Moscow")
        if self.kind == "condition":
            if self.predicate == "count_gte" and not self.value.isascii():
                raise ValueError("Порог должен быть целым числом")
            if self.predicate == "count_gte" and not self.value.isdecimal():
                raise ValueError("Порог должен быть целым неотрицательным числом")
            if self.predicate == "severity_eq" and self.value not in {"low", "medium", "high", "critical"}:
                raise ValueError("Выберите уровень важности")
            if self.predicate == "rule_regex":
                try:
                    regex.compile(self.value)
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
            raise ValueError("Добавьте ручной запуск или расписание")
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
    files: list[Source] = Field(min_length=1, max_length=400)

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
    fixed_version: str | None = None
    classification: str | None = None
    dependency: Dependency | None = None

    category: Literal["SECRET", "SAST", "SCA"]

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


class LockAdvisory(Model):
    id: str
    severity: Severity


class LockedPackage(Model):
    package: str
    version: str
    path: str
    line: int
    configurations: list[str]
    scope: Literal["transitive", "unclassified"]
    status: Literal["checked", "outside-catalog", "unresolved"]
    advisories: list[LockAdvisory] = Field(default_factory=list)


class LockReport(Model):
    files: list[str] = Field(default_factory=list)
    packages: list[LockedPackage] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)

    @property
    def checked(self) -> int:
        return sum(p.status == "checked" for p in self.packages)


class Step(Model):
    node_id: str
    kind: Kind
    status: Status = "pending"
    message: str = ""
    input_ids: list[str] = Field(default_factory=list)
    output_ids: list[str] = Field(default_factory=list)
    branch: Branch | None = None
    report: Report | None = None
    reviews: list[Review] = Field(default_factory=list)
    lockfile: LockReport | None = None


class Run(Model):
    id: str
    name: str
    started: str
    trigger: str
    status: Status = "running"
    steps: list[Step]
    findings: list[Finding] = Field(default_factory=list)


class RunSummary(Model):
    id: str
    name: str
    started: str
    status: Status


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
