import asyncio
import ipaddress
import json
import os
import re
import smtplib
import socket
import ssl
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from contextlib import closing
from dataclasses import dataclass
from email.message import EmailMessage
from functools import partial
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from cryptography.fernet import Fernet, InvalidToken
from pydantic import AnyHttpUrl, TypeAdapter

from garden.email_report import build_report_email
from garden.maven import RELEASE
from garden.models import ConnectionInfo, Destination, Finding, PublicConnection, Receipt, Report


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
    rf"""\b(?:(?:до\s+версии|to\s+version|на\s+версию|установите\s+версию)|(?P<bare>до|to))\s+"""
    rf"""[`'"]?(?P<coordinate>{MAVEN_ID}:{MAVEN_ID}:)?v?(?P<release>{RELEASE})\b""", re.I
)
UPGRADE_VERB = re.compile(r"\b(?:обнов\w*|перей\w*|upgrade|update|bump)\s+(?:\w+\s+){0,2}$", re.I)


def validate_sca_advice(text: str, fix: str, findings: list[Finding]):
    packages = {f"{f.dependency.group}:{f.dependency.artifact}" for f in findings if f.dependency}
    installed = {f.dependency.version for f in findings if f.dependency}
    targets = {f.fixed_version for f in findings if f.fixed_version}
    known_versions = installed | targets
    for package, release in MAVEN_COORDINATE.findall(text):
        if not release and re.fullmatch(r"\d+:\d+", package):
            continue  # A time or ratio alone does not identify a dependency.
        if package not in packages or (release and release not in known_versions):
            raise UngroundedAdvice("LLM указала Maven-координаты вне находки анализатора")
    for match in UPGRADE_TARGET.finditer(fix):
        release = match["release"]
        if (match["bare"] and release.isdecimal() and not match["coordinate"]
                and not UPGRADE_VERB.search(fix[:match.start()])):
            continue  # A bare integer can specify the number of attempts.
        if release not in targets:
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
        if not group.fix.strip():
            raise ValueError("Модель не предложила исправление")
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


def required_setting(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"На сервере не задан {name}")
    return value


def webhook_request(client: httpx.AsyncClient, payload: Receipt, node_id: str, destination: Destination) -> httpx.Request:
    url = (os.environ.get("GARDEN_INBOX_URL", "http://127.0.0.1:8000/api/inbox") if destination == "inbox"
           else required_setting("GARDEN_WEBHOOK_URL"))
    if not url:
        raise ValueError("На сервере не задан GARDEN_INBOX_URL")
    return client.build_request("POST", url, headers={"Idempotency-Key": f"{payload.run_id}/{node_id}"},
                                json=payload.model_dump(), timeout=10)


async def send_webhook(client: httpx.AsyncClient, request: httpx.Request) -> str:
    response = await client.send(request)
    response.raise_for_status()
    return f"Отчёт доставлен · HTTP {response.status_code}"


def notification_text(payload: Receipt) -> str:
    counts = Counter(finding.severity for finding in payload.findings)
    analysis = {"complete": "завершена", "partial": "неполная", "not_run": "не запускалась"}
    return (f"Garden · прогон {payload.run_id}\n"
            f"Проверка: {analysis.get(payload.analysis_status, 'статус неизвестен')}\n"
            f"Находок: {len(payload.findings)} · критических: {counts['critical']} · высоких: {counts['high']}")


def post_telegram(token: str, body: bytes) -> None:
    # The Bot API puts the token in the path. HTTPSConnection does not log request URLs.
    try:
        with closing(HTTPSConnection("api.telegram.org", timeout=10)) as connection:
            connection.request("POST", f"/bot{token}/sendMessage", body, {"Content-Type": "application/json"})
            with connection.getresponse() as response:
                if not 200 <= response.status < 300:
                    raise ValueError(f"Telegram вернул HTTP {response.status}")
                result = json.loads(response.read())
    except TimeoutError:
        raise
    except (OSError, HTTPException):
        raise ValueError("Не удалось связаться с Telegram") from None
    except (json.JSONDecodeError, UnicodeError):
        raise ValueError("Некорректный ответ Telegram") from None
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise ValueError("Telegram не подтвердил отправку")


async def send_telegram(token: str, body: bytes) -> str:
    await asyncio.to_thread(post_telegram, token, body)
    return "Уведомление отправлено в Telegram"


@dataclass(frozen=True)
class AccountSMTP:
    sender: str
    host: str
    port: int
    mode: Literal["ssl", "starttls"]
    encrypted_password: bytes


def smtp_credential_cipher() -> Fernet:
    try:
        return Fernet(required_setting("GARDEN_SMTP_CREDENTIAL_KEY"))
    except ValueError:
        raise ValueError("Администратор должен задать ключ GARDEN_SMTP_CREDENTIAL_KEY для личной почты") from None


def prepare_smtp_send(message: EmailMessage, account: AccountSMTP | None = None) -> Callable[[], None]:
    if account is not None:
        try:
            password = smtp_credential_cipher().decrypt(account.encrypted_password).decode()
        except InvalidToken:
            raise ValueError("Не удалось прочитать пароль приложения. Сохраните пароль заново в личном кабинете") from None
        message["From"] = account.sender
        return partial(send_smtp_message, message, account.host, account.port, account.mode, account.sender, password,
                       personal=True)
    host = required_setting("GARDEN_SMTP_HOST")
    message["From"] = required_setting("GARDEN_SMTP_FROM")
    mode = os.getenv("GARDEN_SMTP_MODE", "starttls")
    if mode not in ("ssl", "starttls"):
        raise ValueError("В GARDEN_SMTP_MODE укажите starttls или ssl")
    try:
        port = int(os.getenv("GARDEN_SMTP_PORT", "465" if mode == "ssl" else "587"))
    except ValueError:
        raise ValueError("Укажите корректный порт в GARDEN_SMTP_PORT") from None
    if not 1 <= port <= 65535:
        raise ValueError("Укажите корректный порт в GARDEN_SMTP_PORT")
    user = os.getenv("GARDEN_SMTP_USER")
    password = os.environ.get("GARDEN_SMTP_PASSWORD") if user else None
    if user and password is None:
        raise ValueError("На сервере не задан GARDEN_SMTP_PASSWORD")

    return partial(send_smtp_message, message, host, port, mode, user, password)


def send_smtp_message(message: EmailMessage, host: str, port: int, mode: str,
                      user: str | None, password: str | None, *, personal: bool = False) -> None:
    context = ssl.create_default_context()
    if mode == "ssl":
        smtp_class = PublicSMTPSSL if personal else smtplib.SMTP_SSL
        smtp = smtp_class(host, port, timeout=8, context=context)
    else:
        smtp_class = PublicSMTP if personal else smtplib.SMTP
        smtp = smtp_class(host, port, timeout=8)
    with smtp:
        if mode == "starttls":
            smtp.starttls(context=context)
        if user and password is not None:
            smtp.login(user, password)
        smtp.send_message(message)


async def send_email(send: Callable[[], None]) -> str:
    try:
        await asyncio.to_thread(send)
    except TimeoutError:
        raise
    except smtplib.SMTPResponseException as error:
        raise ValueError(f"SMTP-сервер вернул код {error.smtp_code}") from None
    except smtplib.SMTPRecipientsRefused:
        raise ValueError("SMTP-сервер отклонил получателя") from None
    except OSError:
        raise ValueError("Не удалось отправить письмо через SMTP") from None
    return "Отчёт отправлен по email"


@dataclass(frozen=True)
class Notification:
    receipt: bytes
    send: Callable[[], Awaitable[str]]


@dataclass(frozen=True)
class Recipients:
    email: str | None = None
    telegram: str | None = None
    smtp: AccountSMTP | None = None


def validate_public_host(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # Hostnames are resolved and checked at dispatch.
    require_public_ip(ip)


def require_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv6 transition addresses can route to a different address family.
        if ip.is_site_local or ip.sixtofour or ip.teredo or ip in ipaddress.IPv6Network("64:ff9b::/96"):
            raise ValueError("Сервер должен иметь общедоступный IP-адрес")
        ip = ip.ipv4_mapped or ip
    if not ip.is_global or ip.is_multicast or ip.is_reserved:
        raise ValueError("Сервер должен иметь общедоступный IP-адрес")


def public_addresses(host: str, port: int) -> list[str]:
    addresses = list(dict.fromkeys(info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    for address in addresses:
        require_public_ip(ipaddress.ip_address(address))
    return addresses


def public_smtp_socket(host: str, port: int, timeout: float) -> socket.socket:
    addresses = public_addresses(host, port)
    deadline = time.monotonic() + timeout
    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        try:
            return socket.create_connection((address, port), timeout=remaining)
        except OSError:
            continue
    raise OSError("Не удалось подключиться к SMTP")


class PublicSMTP(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):
        return public_smtp_socket(host, port, timeout)


class PublicSMTPSSL(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        # The connection uses a checked IP but authenticates the configured SMTP hostname.
        with public_smtp_socket(host, port, timeout) as raw:
            return self.context.wrap_socket(raw, server_hostname=self._host)


def prepare_notification(client: httpx.AsyncClient, payload: Receipt, node_id: str,
                         destination: Destination, recipients: Recipients | None = None, *,
                         run_name: str = "Проверка Garden") -> Notification:
    if destination == "telegram":
        token = required_setting("GARDEN_TELEGRAM_BOT_TOKEN")
        if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", token):
            raise ValueError("Укажите корректный GARDEN_TELEGRAM_BOT_TOKEN")
        chat = recipients.telegram if recipients is not None else required_setting("GARDEN_TELEGRAM_CHAT_ID")
        if not chat:
            raise ValueError("Владелец проекта ещё не подключил Telegram в личном кабинете")
        chat_id = int(chat) if re.fullmatch(r"-?[0-9]{1,16}", chat) else chat
        body = json.dumps({"chat_id": chat_id, "text": notification_text(payload)}, ensure_ascii=False).encode()
        return Notification(payload.model_dump_json().encode(), partial(send_telegram, token, body))
    if destination == "email":
        recipient = recipients.email if recipients is not None else required_setting("GARDEN_EMAIL_TO")
        if not recipient:
            raise ValueError("Владелец проекта ещё не указал получателя почты в личном кабинете")
        receipt = payload.model_dump_json().encode()
        message = build_report_email(payload, recipient, run_name)
        return Notification(receipt, partial(send_email, prepare_smtp_send(message, recipients.smtp if recipients else None)))
    request = webhook_request(client, payload, node_id, destination)
    return Notification(request.content, partial(send_webhook, client, request))
