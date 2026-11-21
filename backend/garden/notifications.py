import hmac
import os
import re
import secrets
import sqlite3
import time
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr, field_validator

from garden.accounts import User, check_origin, current_user, digest, normalize_email, rate_limit
from garden.integrations import AccountSMTP, Recipients, smtp_credential_cipher, validate_public_host
from garden.models import Model


router = APIRouter()
PROFILE = "/api/auth/notifications"
CHALLENGE_AGE = 600
Channel = Literal["email", "telegram"]


class NotificationSettings(Model):
    email_recipient: str | None = None
    email_mode: Literal["garden", "personal"] = "garden"
    email_sender: str | None = None
    email_host: str | None = None
    email_port: int | None = None
    email_security: Literal["starttls", "ssl"] | None = None
    email_available: bool
    telegram_linked: bool
    telegram_available: bool


class GardenEmail(Model):
    mode: Literal["garden"]
    recipient: str = Field(max_length=254)

    _recipient = field_validator("recipient")(normalize_email)


class PersonalEmail(GardenEmail):
    mode: Literal["personal"]
    sender: str = Field(max_length=254)
    host: str = Field(max_length=253, pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9]+$")
    port: int | None = Field(default=None, ge=1, le=65535)
    security: Literal["starttls", "ssl"] = "starttls"
    password: SecretStr | None = Field(default=None, min_length=1, max_length=512)

    _sender = field_validator("sender")(normalize_email)


EmailSettings = Annotated[GardenEmail | PersonalEmail, Field(discriminator="mode")]


class TelegramLink(Model):
    url: str


class TelegramChat(BaseModel):
    id: int = Field(gt=0, lt=2**52, strict=True)
    type: Literal["private"]


class TelegramMessage(BaseModel):
    chat: TelegramChat
    text: str = ""


class TelegramUpdate(BaseModel):
    message: TelegramMessage | None = None


def init_notifications(db: sqlite3.Connection) -> None:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS account_notifications (
            account_id TEXT PRIMARY KEY REFERENCES accounts(id),
            verified_email TEXT, telegram_chat TEXT
        );
        CREATE TABLE IF NOT EXISTS notification_challenges (
            account_id TEXT NOT NULL REFERENCES accounts(id), channel TEXT NOT NULL,
            digest BLOB NOT NULL UNIQUE, expires INTEGER NOT NULL,
            PRIMARY KEY (account_id, channel)
        );
        CREATE INDEX IF NOT EXISTS notification_challenge_expiry ON notification_challenges(expires);
        CREATE TABLE IF NOT EXISTS account_email_notifications (
            account_id TEXT PRIMARY KEY REFERENCES accounts(id), recipient TEXT NOT NULL,
            sender TEXT, host TEXT, port INTEGER, security TEXT, encrypted_password BLOB
        );
    """)


def project_recipients(db: sqlite3.Connection, project_id: str) -> Recipients:
    row = db.execute("""
        SELECT COALESCE(e.recipient, CASE WHEN n.verified_email=a.email THEN a.email END),
               n.telegram_chat, e.sender, e.host, e.port, e.security, e.encrypted_password
        FROM projects p JOIN accounts a ON a.id=p.owner_id
        LEFT JOIN account_notifications n ON n.account_id=a.id
        LEFT JOIN account_email_notifications e ON e.account_id=a.id WHERE p.id=?
    """, (project_id,)).fetchone()
    if row is None:
        return Recipients()
    return Recipients(email=row[0], telegram=row[1], smtp=AccountSMTP(*row[2:]) if row[2] else None)


def telegram_username() -> str:
    username = os.getenv("GARDEN_TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
    token = os.getenv("GARDEN_TELEGRAM_BOT_TOKEN", "").strip()
    secret = os.getenv("GARDEN_TELEGRAM_WEBHOOK_SECRET", "").strip()
    if (re.fullmatch(r"[A-Za-z0-9_]{5,32}", username) and re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", token)
            and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", secret)):
        return username
    return ""


def settings(db: sqlite3.Connection, user: User) -> NotificationSettings:
    row = db.execute("SELECT verified_email,telegram_chat FROM account_notifications WHERE account_id=?",
                     (user.id,)).fetchone()
    mail = db.execute("SELECT recipient,sender,host,port,security FROM account_email_notifications WHERE account_id=?",
                      (user.id,)).fetchone()
    return NotificationSettings(
        email_recipient=mail[0] if mail else user.email if row and row[0] == user.email else None,
        email_mode="personal" if mail and mail[1] else "garden",
        email_sender=mail[1] if mail else None, email_host=mail[2] if mail else None,
        email_port=mail[3] if mail else None, email_security=mail[4] if mail else None,
        email_available=bool(os.getenv("GARDEN_SMTP_HOST", "").strip() and os.getenv("GARDEN_SMTP_FROM", "").strip()),
        telegram_linked=bool(row and row[1]), telegram_available=bool(telegram_username()),
    )


def store_challenge(db: sqlite3.Connection, account_id: str, channel: Channel, hashed: bytes) -> None:
    now = int(time.time())
    with db:
        db.execute("DELETE FROM notification_challenges WHERE expires<=?", (now,))
        db.execute("""INSERT INTO notification_challenges VALUES (?,?,?,?) ON CONFLICT(account_id,channel)
                      DO UPDATE SET digest=excluded.digest, expires=excluded.expires""",
                   (account_id, channel, hashed, now + CHALLENGE_AGE))


@router.get(PROFILE)
async def get_settings(request: Request) -> NotificationSettings:
    user = current_user(request)
    return settings(request.app.state.store.db, user)


@router.put(PROFILE + "/email")
async def save_email(body: EmailSettings, request: Request) -> NotificationSettings:
    check_origin(request)
    user = current_user(request)
    db = request.app.state.store.db
    smtp = (None, None, None, None, None)
    if isinstance(body, PersonalEmail):
        port = body.port or (465 if body.security == "ssl" else 587)
        smtp_parameters = (body.sender, body.host.lower(), port, body.security)
        # Check literal addresses while saving. DNS is checked again before each SMTP connection.
        try:
            validate_public_host(body.host)
        except ValueError:
            raise HTTPException(422, "Укажите общедоступный SMTP-сервер") from None
        if body.password is None:
            existing = db.execute("""SELECT sender,host,port,security,encrypted_password
                                       FROM account_email_notifications WHERE account_id=?""", (user.id,)).fetchone()
            if not existing or existing[:4] != smtp_parameters or not existing[4]:
                raise HTTPException(422, "Введите пароль приложения для этого отправителя")
            encrypted = existing[4]
        else:
            try:
                encrypted = smtp_credential_cipher().encrypt(body.password.get_secret_value().encode())
            except ValueError as error:
                raise HTTPException(503, str(error)) from None
        smtp = (*smtp_parameters, encrypted)
    with db:
        db.execute("""INSERT INTO account_email_notifications VALUES (?,?,?,?,?,?,?) ON CONFLICT(account_id)
                      DO UPDATE SET recipient=excluded.recipient,sender=excluded.sender,host=excluded.host,
                      port=excluded.port,security=excluded.security,encrypted_password=excluded.encrypted_password""",
                   (user.id, body.recipient, *smtp))
    return settings(db, user)


@router.post(PROFILE + "/telegram/link")
async def link_telegram(request: Request) -> TelegramLink:
    check_origin(request)
    user = current_user(request)
    username = telegram_username()
    if not username:
        raise HTTPException(503, "Общий Telegram-бот ещё не настроен администратором")
    rate_limit(request, "notification-telegram:" + user.id, 10)
    token = secrets.token_urlsafe(32)
    store_challenge(request.app.state.store.db, user.id, "telegram", digest(token))
    return TelegramLink(url=f"https://t.me/{username}?start={token}")


@router.post("/api/notifications/telegram/callback", status_code=204)
async def telegram_callback(request: Request) -> Response:
    actual = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "").encode()
    expected = os.getenv("GARDEN_TELEGRAM_WEBHOOK_SECRET", "").strip().encode()
    if not telegram_username() or not hmac.compare_digest(actual, expected):
        raise HTTPException(403, "Неизвестный отправитель Telegram")
    try:
        message = TelegramUpdate.model_validate(await request.json()).message
    except ValueError:
        return Response(status_code=204)
    token = re.fullmatch(r"/start ([A-Za-z0-9_-]{43})", message.text) if message else None
    if token and message:
        db = request.app.state.store.db
        with db:
            row = db.execute("""DELETE FROM notification_challenges WHERE channel='telegram' AND digest=? AND expires>?
                                RETURNING account_id""", (digest(token[1]), int(time.time()))).fetchone()
            if row:
                db.execute("""INSERT INTO account_notifications(account_id,telegram_chat) VALUES (?,?)
                              ON CONFLICT(account_id) DO UPDATE SET telegram_chat=excluded.telegram_chat""",
                           (row[0], str(message.chat.id)))
    return Response(status_code=204)


@router.delete(PROFILE + "/{channel}")
async def disable_channel(channel: Channel, request: Request) -> NotificationSettings:
    check_origin(request)
    user = current_user(request)
    db = request.app.state.store.db
    column = "verified_email" if channel == "email" else "telegram_chat"
    with db:
        db.execute(f"UPDATE account_notifications SET {column}=NULL WHERE account_id=?", (user.id,))
        if channel == "email":
            db.execute("DELETE FROM account_email_notifications WHERE account_id=?", (user.id,))
        db.execute("DELETE FROM notification_challenges WHERE account_id=? AND channel=?", (user.id, channel))
    return settings(db, user)
