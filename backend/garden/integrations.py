import json
import os
import re
import time
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import AnyHttpUrl, TypeAdapter

from garden.maven import RELEASE
from garden.models import ConnectionInfo, Finding, PublicConnection, Report, Review


class UngroundedAdvice(ValueError):
    """Prose cites a location or dependency fact outside the structured references."""


class Connection(ConnectionInfo):
    protocol: Literal["chat", "ollama", "anthropic", "gigachat"]
    url: AnyHttpUrl
    key_env: str | None = None
    project_env: str | None = None
    auth_scheme: Literal["Bearer", "Api-Key"] = "Bearer"
    scope: str = "GIGACHAT_API_PERS"
    oauth_url: AnyHttpUrl = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"

    def official_openai(self) -> bool:
        return (self.protocol == "chat" and self.key_env == "OPENAI_API_KEY"
                and str(self.url).rstrip("/") == "https://api.openai.com/v1")

    def key(self) -> str:
        value = os.environ.get(self.key_env, "") if self.key_env else ""
        if not value and self.official_openai() and os.name == "nt":
            from keyring.backends.Windows import WinVaultKeyring
            value = WinVaultKeyring().get_password("Garden Security Workflow", "OpenAI") or ""
        return value

    def public(self) -> PublicConnection:
        return PublicConnection(id=self.id, label=self.label, model=self.model,
                                configured=(not self.key_env or bool(self.key())) and
                                (not self.project_env or bool(os.environ.get(self.project_env))),
                                local_key_entry=self.official_openai() and os.name == "nt"
                                and not os.environ.get("OPENAI_API_KEY"))


class Gateway:
    def __init__(self, client: httpx.AsyncClient, profiles: list[Connection]):
        self.client = client
        self.profiles = {p.id: p for p in profiles}
        self.tokens: dict[str, tuple[str, float]] = {}

    @classmethod
    def configured(cls, client: httpx.AsyncClient):
        custom = os.environ.get("GARDEN_CONNECTIONS")
        file = Path(custom) if custom else Path(__file__).parents[1] / "connections.example.json"
        profiles = TypeAdapter(list[Connection]).validate_json(file.read_bytes())
        if len({p.id for p in profiles}) != len(profiles):
            raise ValueError("Идентификаторы подключений LLM должны быть уникальными")
        return cls(client, profiles)

    async def giga_token(self, profile: Connection, key: str) -> str:
        token, expiry = self.tokens.get(profile.id, ("", 0))
        if expiry > time.time() + 30:
            return token
        response = await self.client.post(str(profile.oauth_url), data={"scope": profile.scope},
                                          headers={"RqUID": str(uuid4()), "Authorization": f"Basic {key}"})
        response.raise_for_status()
        data = response.json()
        token = data["access_token"]
        self.tokens[profile.id] = (token, data["expires_at"] / 1000)
        return token

    async def explain(self, profile_id: str, model: str, findings: list[Finding]) -> Report:
        if not findings:
            return Report(groups=[])
        profile = self.profiles.get(profile_id)
        if not profile:
            raise ValueError("Подключение модели отсутствует")
        model = model.strip() or profile.model
        if not model:
            raise ValueError("Укажите имя модели в настройках AI-ноды")
        by_category = {}
        for finding in findings:
            by_category.setdefault(finding.category, []).append(finding)
        report = Report(groups=[])
        for category_findings in by_category.values():
            part = await self.explain_category(profile, model, category_findings)
            report.groups.extend(part.groups)
        return report

    async def explain_category(self, profile: Connection, model: str, findings: list[Finding]) -> Report:
        system = (
            "Объясни риски разработчику по-русски. На входе наборы родственных находок. Обобщай только внутри одного набора. "
            "Верни только JSON с массивом groups. У каждой группы поля finding_ids, risk и fix. "
            "Используй каждый переданный id ровно один раз. В risk напиши полное предложение на русском: "
            "объясни, какое последствие имеет эта конкретная ошибка для разработчика. "
            "Оценка важности уже известна. В fix опиши что изменить и как проверить результат. "
            "Ссылки на файлы и строки интерфейс добавит по id. Не приводи другие пути, номера строк или CVE."
        )
        if findings[0].category == "SCA":
            system += (" В risk опиши текущее состояние: установленная версия входит в диапазон бюллетеня, "
                       "поэтому использующий её код может быть затронут известной уязвимостью. "
                       "В fix используй пакет и целевую версию из рекомендации анализатора. "
                       "Если версия исправления отсутствует, предложи свериться с бюллетенем.")
        # Short references are easier to copy exactly, especially for small local models.
        references = {f"F{i}": f for i, f in enumerate(findings, 1)}
        public = [f.model_copy(update={"id": key}) for key, f in references.items()]
        fields = {"id", "category", "classification", "rule", "severity", "title", "fix", "advisory"}
        topics = {}
        for f in public:
            topics.setdefault(report_topic(f), []).append(f)
        content = json.dumps([[f.model_dump(include=fields, exclude_none=True) for f in topic]
                              for topic in topics.values()], ensure_ascii=False)
        schema = Report.model_json_schema()
        schema["properties"]["groups"].update(minItems=len(topics), maxItems=len(references))
        fields_schema = schema["$defs"]["Advice"]["properties"]
        fields_schema["finding_ids"] = {"anyOf": [
            {"type": "array", "minItems": 1, "maxItems": len(topic),
             "items": {"type": "string", "enum": [f.id for f in topic]}} for topic in topics.values()
        ]}
        for field in ("risk", "fix"):
            fields_schema[field] = {"type": "string"}
        budget = min(4096, 300 * len(references) + 100)
        raw = await self.complete(profile, model, system, content, schema, budget)
        try:
            report = validate_report(raw, public)
        except UngroundedAdvice as error:
            correction = (f" Предыдущий ответ отклонён. {error}. Перепиши пояснения для тех же id. "
                          "Оставь ссылки на расположение интерфейсу. Сведения об обновлении бери из поля fix.")
            raw = await self.complete(profile, model, system + correction, content, schema, budget)
            report = validate_report(raw, public)
        for group in report.groups:
            group.finding_ids = [references[key].id for key in group.finding_ids]
        return report

    async def complete(self, profile: Connection, model: str, system: str, content: str,
                       schema: dict, tokens: int) -> str:
        key = profile.key()
        if profile.key_env and not key:
            raise ValueError(f"Для подключения задайте {profile.key_env} на сервере")
        messages = [{"role": "system", "content": system}, {"role": "user", "content": content}]
        headers = {}
        base = str(profile.url).rstrip("/")
        if profile.protocol == "anthropic":
            endpoint = base + "/messages"
            headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
            body = {"model": model, "max_tokens": 4096, "system": system, "messages": messages[1:]}
        elif profile.protocol == "ollama":
            endpoint = base + "/api/chat"
            body = {"model": model, "stream": False, "messages": messages, "format": schema,
                    "options": {"temperature": 0, "num_predict": tokens}}
        else:
            endpoint = base + "/chat/completions"
            if profile.protocol == "gigachat":
                key = await self.giga_token(profile, key)
            if key:
                headers["Authorization"] = f"{profile.auth_scheme} {key}"
            if profile.project_env:
                project = os.environ.get(profile.project_env)
                if not project:
                    raise ValueError(f"Для подключения задайте {profile.project_env} на сервере")
                headers["OpenAI-Project"] = project
            body = {"model": model, "messages": messages}
            if profile.official_openai():
                body["response_format"] = {"type": "json_object"}
                if model in {"gpt-6.2-sol", "gpt-6.1-sol"}:
                    body.update(reasoning_effort="low", service_tier="default",
                                max_completion_tokens=min(4096, max(1200, tokens + 400)))
        response = await self.client.post(endpoint, headers=headers, json=body)
        response.raise_for_status()
        result = response.json()
        if profile.protocol == "ollama":
            raw = result["message"]["content"]
        elif profile.protocol == "anthropic":
            raw = "".join(part["text"] for part in result["content"] if part["type"] == "text")
        else:
            raw = result["choices"][0]["message"]["content"]
        return raw


def report_topic(finding: Finding) -> tuple[str, ...]:
    topic = (finding.category, finding.advisory or finding.classification or finding.rule)
    if finding.dependency:
        return (*topic, finding.dependency.group, finding.dependency.artifact)
    return topic


MAVEN_ID = r"[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*"
MAVEN_COORDINATE = re.compile(rf"(?<![\w.-])({MAVEN_ID}:{MAVEN_ID})(?::({RELEASE}))?")
UPGRADE_TARGET = re.compile(
    rf"""\b(?:(?:до|to)\s+(?:(?:версии|version)\s+)?|(?:на|установите)\s+версию\s+)[`'"]?v?({RELEASE})\b""", re.I
)


def validate_sca_advice(text: str, fix: str, findings: list[Finding]):
    packages = {f"{f.dependency.group}:{f.dependency.artifact}" for f in findings if f.dependency}
    installed = {f.dependency.version for f in findings if f.dependency}
    targets = {f.fixed_version for f in findings if f.fixed_version}
    known_versions = installed | targets
    for package, release in MAVEN_COORDINATE.findall(text):
        if package not in packages or (release and release not in known_versions):
            raise UngroundedAdvice("LLM указала Maven-координаты вне находки анализатора")
    if any(v not in targets for v in UPGRADE_TARGET.findall(fix)):
        raise UngroundedAdvice("LLM предложила версию обновления вне рекомендации анализатора")


def validate_report(raw: str, findings: list[Finding]) -> Report:
    report = Report.model_validate_json(raw)
    expected = {f.id: f for f in findings}
    ids = [key for group in report.groups for key in group.finding_ids]
    if sorted(ids) != sorted(expected):
        raise ValueError("Ответ LLM не соответствует идентификаторам находок")
    for group in report.groups:
        if len({report_topic(expected[key]) for key in group.finding_ids}) != 1:
            raise ValueError("LLM объединила находки с разными причинами и исправлениями")
        if len(group.risk.split()) < 3:
            raise ValueError("Модель не объяснила последствие находки")
        text = f"{group.risk} {group.fix}"
        advisories = {expected[key].advisory.upper() for key in group.finding_ids if expected[key].advisory}
        mentioned = re.findall(r"\b(?:CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", text, re.I)
        if any(identifier.upper() not in advisories for identifier in mentioned):
            raise ValueError("Ответ LLM содержит посторонний идентификатор уязвимости")
        if expected[group.finding_ids[0]].category == "SCA":
            validate_sca_advice(text, group.fix, [expected[key] for key in group.finding_ids])
            risk = group.risk.casefold()
            for identifier in advisories:
                risk = risk.replace(identifier.casefold(), "")
            if risk.strip(" .:;()\n") == group.fix.casefold().strip(" .:;()\n"):
                raise ValueError("Вместо объяснения риска LLM повторила инструкцию по обновлению")
        # Locations are rendered from trusted finding IDs, never from generated prose.
        if re.search(r"(?:[\w./\\-]+\.(?:kts?|ya?ml|properties|toml|lockfile)\b|\b(?:lines?|строк(?:ах|ам|ой|[аеуи])?)\s*[:№#]?\s*\d+)", text, re.I):
            raise UngroundedAdvice("LLM указала позицию вне структурированной ссылки")
    return report


async def deliver(client: httpx.AsyncClient, run_id: str, node_id: str, findings: list[Finding],
                  reports: list[Report], reviews: list[Review], destination: str) -> int:
    url = (os.environ.get("GARDEN_INBOX_URL", "http://127.0.0.1:8000/api/inbox") if destination == "inbox"
           else os.environ.get("GARDEN_WEBHOOK_URL"))
    if not url:
        raise ValueError("На сервере не задан GARDEN_WEBHOOK_URL")
    response = await client.post(url, headers={"Idempotency-Key": f"{run_id}/{node_id}"}, json={
        "run_id": run_id, "findings": [f.model_dump() for f in findings],
        "reports": [r.model_dump() for r in reports],
        "reviews": [r.model_dump() for r in reviews],
    }, timeout=10)
    response.raise_for_status()
    return response.status_code
