from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator

from garden.integrations import Gateway
from garden.models import Blueprint, Edge, Model, Node, Source, Target, Workflow, demo


class Plan(Model):
    name: str = Field(min_length=1, max_length=100)
    checks: list[Literal["secrets", "sast", "sca"]] = Field(min_length=1, max_length=3)
    schedule: str | None
    condition: Literal["always", "any", "critical"]
    explain: bool
    notify: bool

    @field_validator("checks")
    @classmethod
    def unique_checks(cls, value):
        return list(dict.fromkeys(value))


def blueprint(plan: Plan, target: Target | None = None) -> Blueprint:
    nodes = [Node(id="start", kind="manual", x=0, y=0)]
    edges = []

    def link(source: str, target_id: str, branch=None):
        edges.append(Edge(id=f"{source}-{target_id}", source=source, target=target_id, branch=branch))

    if plan.schedule:
        nodes.append(Node(id="schedule", kind="schedule", x=0, y=120, cron=plan.schedule))
    previous = "start"
    for idx, kind in enumerate(plan.checks, 1):
        nodes.append(Node(id=kind, kind=kind, x=240 * idx, y=0))
        link(previous, kind)
        if idx == 1 and plan.schedule:
            link("schedule", kind)
        previous = kind
    x = nodes[-1].x
    port = None
    if plan.condition != "always" and (plan.explain or plan.notify):
        x += 240
        critical = plan.condition == "critical"
        nodes.append(Node(id="condition", kind="condition", x=x, y=0, predicate="severity_eq" if critical
                          else "count_gte", value="critical" if critical else "1"))
        link(previous, "condition")
        previous, port = "condition", "yes"
    if plan.explain:
        x += 240
        nodes.append(Node(id="explain", kind="explain", x=x, y=0, targets=[target] if target else []))
        link(previous, "explain", port)
        previous, port = "explain", None
    if plan.notify:
        nodes.append(Node(id="notify", kind="webhook", x=x + 240, y=0, destination="inbox"))
        link(previous, "notify", port)
    return Blueprint(name=plan.name, nodes=nodes, edges=edges)


def repair_template(gateway: Gateway) -> Blueprint:
    graph = blueprint(Plan(name="Repair Desk", checks=["secrets", "sast", "sca"], schedule="0 9 * * *",
                           condition="any", explain=True, notify=True))
    ai = next(node for node in graph.nodes if node.kind == "explain")
    ai.targets = [Target(connection=p.id, model=p.model) for key in ("ollama", "openai")
                  if (p := gateway.profiles.get(key)) and p.model and p.public().configured]
    return graph


def sources(root: Path) -> list[Source]:
    files = []
    size = 0
    for folder, dirs, names in root.walk():
        dirs[:] = sorted(d for d in dirs if d not in {".git", ".gradle", "build", "node_modules", ".venv"}
                         and not (folder / d).is_symlink() and not (folder / d).is_junction()
                         and not (folder / d / ".git").exists())
        for name in sorted(names):
            path = folder / name
            if path.suffix not in {".kt", ".kts", ".yml", ".yaml", ".properties"} and name not in {"gradle.lockfile", "libs.versions.toml"}:
                continue
            if path.is_symlink() or not path.is_file():
                continue
            size += path.stat().st_size
            if size > 5_000_000 or len(files) >= 400:
                raise ValueError("Лимит проекта — 400 файлов и 5 МБ")
            relative = path.relative_to(root).as_posix()
            try:
                text = path.read_text(encoding="utf-8-sig")
            except UnicodeDecodeError:
                if path.suffix != ".properties":
                    raise ValueError(f"Требуется UTF-8 для файла {relative}") from None
                text = path.read_text(encoding="latin-1")
            files.append(Source(path=relative, text=text))
    if not files:
        raise ValueError("В проекте нет поддерживаемых исходников")
    return files


def repair_demo(gateway: Gateway, allow_sample: bool = False) -> Workflow:
    root = Path(__file__).resolve().parents[2] / "samples/training/training-project"
    graph = repair_template(gateway)
    if root.is_dir():
        return Workflow(**graph.model_dump(), files=sources(root))
    if not allow_sample:
        raise FileNotFoundError("Добавьте набор участников в samples/training")
    graph.name = "Проверка учебного проекта"
    files = [*demo().files, Source(path="build.gradle.kts", text='dependencies { implementation("org.apache.commons:commons-text:1.9") }'),
             Source(path="Security.kt", text="import org.springframework.security.config.annotation.web.builders.HttpSecurity\n"
                    "fun configure() { authorize(anyRequest, permitAll) }")]
    return Workflow(**graph.model_dump(), files=files)


async def generate(gateway: Gateway, description: str, target: Target) -> Blueprint:
    profile = gateway.profiles.get(target.connection)
    if profile is None or not (target.model or profile.model):
        raise ValueError("Выберите подключение и модель")
    schema = Plan.model_json_schema()
    prompt = ("Составь JSON-план проверки исходников по описанию. checks: secrets для секретов, sast для Kotlin, "
              "sca для зависимостей. schedule: cron из пяти полей или null. condition: always, any (есть находки) "
              "или critical. explain: нужны рекомендации модели. notify: нужна доставка. Название на русском. "
              "План будет открыт как черновик. Верни только JSON по схеме: " + str(schema))
    raw = await gateway.complete(profile, target.model or profile.model, prompt, description, schema, 600)
    return blueprint(Plan.model_validate_json(raw), target)
