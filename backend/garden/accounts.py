import asyncio
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr, field_validator

from garden.invitations import InviteToken, find_invitation


router = APIRouter(prefix="/api/auth")
SESSION_COOKIE = "garden_session"
SESSION_AGE = 14 * 24 * 3600


def init_accounts(db: sqlite3.Connection) -> None:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
            salt BLOB, password_hash BLOB
        );
        CREATE TABLE IF NOT EXISTS account_sessions (
            digest BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES accounts(id), expires INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS account_sessions_expiry ON account_sessions(expires);
        CREATE TABLE IF NOT EXISTS account_attempts (
            bucket BLOB PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS account_identities (
            issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES accounts(id),
            PRIMARY KEY (issuer, subject)
        );
        CREATE TABLE IF NOT EXISTS account_oauth_states (
            digest BLOB PRIMARY KEY, browser BLOB NOT NULL, provider TEXT NOT NULL,
            verifier TEXT NOT NULL, expires INTEGER NOT NULL
        );
    """)


def normalize_email(value: str) -> str:
    local, sep, domain = value.strip().lower().rpartition("@")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Проверьте адрес почты") from None
    if (not sep or len(local) + len(domain) > 253 or len(local) > 64
            or not re.fullmatch(r"[a-z0-9!#$%&'*+/=?^_`{|}~.-]+", local)
            or local.startswith(".") or local.endswith(".") or ".." in local
            or "." not in domain or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                            for label in domain.split("."))):
        raise ValueError("Проверьте адрес почты")
    return local + "@" + domain


class User(BaseModel):
    id: str
    email: str
    name: str


class Login(BaseModel):
    email: str = Field(max_length=254)
    password: SecretStr = Field(min_length=1, max_length=128)

    _normalize = field_validator("email")(normalize_email)


class Profile(BaseModel):
    name: str = Field(min_length=1, max_length=100)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        name = value.strip()
        if not name or not name.isprintable():
            raise ValueError("Введите имя")
        return name


class Register(Login, Profile):
    password: SecretStr = Field(min_length=8, max_length=128)
    invitation_token: InviteToken | None = None


class RegisterAndJoin(Register):
    invitation_token: InviteToken = Field(...)


class JoinedProject(BaseModel):
    user: User
    project_id: str


def digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def public_url() -> str:
    value = os.environ.get("GARDEN_PUBLIC_ORIGIN", "").rstrip("/")
    url = urlsplit(value)
    if (not url.hostname or url.username or url.password or url.path or url.query or url.fragment
            or not (url.scheme == "https" or
                    (url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}))):
        return ""
    return value


def check_origin(request: Request, *, include_read: bool = False) -> None:
    if not include_read and request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    origin = request.headers.get("origin")
    expected = public_url() or str(request.base_url).rstrip("/")
    if request.headers.get("sec-fetch-site") == "cross-site" or (origin is not None and origin != expected):
        raise HTTPException(403, "Откройте Garden в том же окне приложения")


def cookie_secure(request: Request) -> bool:
    return request.url.scheme == "https" or public_url().startswith("https://")


def session_user(request: Request) -> User | None:
    # Call on the event loop, which owns the SQLite connection.
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", cookie):
        row = request.app.state.store.db.execute("""
            SELECT a.id, a.email, a.name FROM accounts a
            JOIN account_sessions s ON s.user_id=a.id WHERE s.digest=? AND s.expires>?
        """, (digest(cookie), int(time.time()))).fetchone()
        if row:
            return User(id=row[0], email=row[1], name=row[2])
    return None


def current_user(request: Request) -> User:
    user = session_user(request)
    if user is None:
        raise HTTPException(401, "Войдите в аккаунт")
    return user


def _write_session(request: Request, response: Response, user: User) -> None:
    db = request.app.state.store.db
    raw = secrets.token_urlsafe(32)
    now = int(time.time())
    db.execute("DELETE FROM account_sessions WHERE expires<=? OR digest=?",
               (now, digest(request.cookies.get(SESSION_COOKIE, ""))))
    db.execute("INSERT INTO account_sessions VALUES (?, ?, ?)", (digest(raw), user.id, now + SESSION_AGE))
    response.set_cookie(SESSION_COOKIE, raw, max_age=SESSION_AGE, httponly=True,
                        secure=cookie_secure(request), samesite="lax", path="/")
    response.headers["Cache-Control"] = "no-store"


def start_session(request: Request, response: Response, user: User) -> None:
    with request.app.state.store.db:
        _write_session(request, response, user)


def rate_limit(request: Request, action: str, limit: int) -> None:
    db = request.app.state.store.db
    ip = request.client.host if request.client else ""
    key = digest(action + ":" + ip)
    now = int(time.time())
    with db:
        db.execute("DELETE FROM account_attempts WHERE expires<=?", (now,))
        count, expires = db.execute("""
            INSERT INTO account_attempts VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1
            RETURNING count,expires
        """, (key, now + 600)).fetchone()
    if count > limit:
        raise HTTPException(429, "Слишком много попыток. Попробуйте позже",
                            headers={"Retry-After": str(expires - now)})


async def password_hash(request: Request, password: SecretStr, salt: bytes) -> bytes:
    if not hasattr(request.app.state, "hash_slots"):
        request.app.state.hash_slots = asyncio.Semaphore(2)
    async with request.app.state.hash_slots:
        return await asyncio.to_thread(hashlib.scrypt, password.get_secret_value().encode("utf-8"), salt=salt,
                                       n=32768, r=8, p=3, dklen=32, maxmem=64 * 1024 * 1024)


async def create_account(form: Register, request: Request, response: Response, *, join: bool) -> tuple[User, str | None]:
    check_origin(request)
    rate_limit(request, "register", 15)
    user = User(id=uuid4().hex, email=form.email, name=form.name)
    salt = secrets.token_bytes(16)
    hashed = await password_hash(request, form.password, salt)
    db = request.app.state.store.db
    with db:
        db.execute("BEGIN IMMEDIATE")
        invite = find_invitation(db, form.invitation_token) if form.invitation_token else None
        if invite:
            if invite.email != user.email or (invite.account_id and not join):
                raise HTTPException(422, "Для регистрации по приглашению укажите почту, на которую его отправили")
            if invite.account_id:
                raise HTTPException(409, "Приглашение уже принято. Войдите в аккаунт участника")
        inserted = db.execute("""INSERT INTO accounts(id,email,name,salt,password_hash) VALUES (?,?,?,?,?)
                                 ON CONFLICT(email) DO NOTHING""", (user.id, user.email, user.name, salt, hashed))
        if not inserted.rowcount:
            raise HTTPException(409, "Этот адрес уже зарегистрирован")
        if join and invite:
            db.execute("UPDATE project_members SET account_id=?,expires_at=NULL WHERE id=?", (user.id, invite.member_id))
        _write_session(request, response, user)
    return user, invite.project_id if invite else None


@router.post("/register", status_code=201)
async def register(form: Register, request: Request, response: Response) -> User:
    user, _ = await create_account(form, request, response, join=False)
    return user


@router.post("/register-and-join", status_code=201)
async def register_and_join(form: RegisterAndJoin, request: Request, response: Response) -> JoinedProject:
    user, project_id = await create_account(form, request, response, join=True)
    assert project_id is not None
    return JoinedProject(user=user, project_id=project_id)


@router.post("/login")
async def login(form: Login, request: Request, response: Response) -> User:
    check_origin(request)
    rate_limit(request, "login", 60)
    rate_limit(request, "login:" + form.email, 12)
    row = request.app.state.store.db.execute(
        "SELECT id,email,name,salt,password_hash FROM accounts WHERE email=?", (form.email,)
    ).fetchone()
    hashed = await password_hash(request, form.password, row[3] if row and row[3] else bytes(16))
    if not hmac.compare_digest(hashed, row[4] if row and row[4] else bytes(32)) or not row:
        raise HTTPException(401, "Проверьте адрес и пароль")
    user = User(id=row[0], email=row[1], name=row[2])
    start_session(request, response, user)
    return user


@router.get("/me")
async def profile(request: Request, response: Response) -> User:
    response.headers["Cache-Control"] = "no-store"
    return current_user(request)


@router.patch("/me")
async def update_profile(form: Profile, request: Request) -> User:
    check_origin(request)
    user = current_user(request)
    db = request.app.state.store.db
    with db:
        db.execute("UPDATE accounts SET name=? WHERE id=?", (form.name, user.id))
    return user.model_copy(update={"name": form.name})


@router.post("/logout", status_code=204)
async def logout(request: Request) -> Response:
    check_origin(request)
    db = request.app.state.store.db
    with db:
        db.execute("DELETE FROM account_sessions WHERE digest=?", (digest(request.cookies.get(SESSION_COOKIE, "")),))
    response = Response(status_code=204, headers={"Cache-Control": "no-store"})
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=cookie_secure(request), samesite="lax")
    return response
