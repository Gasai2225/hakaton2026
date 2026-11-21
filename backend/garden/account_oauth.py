import base64
import hmac
import os
import secrets
import sqlite3
import time
from urllib.parse import urlencode
from uuid import uuid4

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from garden.accounts import User, cookie_secure, digest, normalize_email, public_url, rate_limit, start_session


router = APIRouter(prefix="/api/auth")
NAMES = {"google": "Google", "vk": "VK ID", "mailru": "Mail.ru"}
STATE_COOKIE = "garden_oauth"


def config(provider: str) -> tuple[str, str, str] | None:
    origin = public_url()
    if provider not in NAMES or not origin:
        return None
    if provider == "google":
        client = os.environ.get("GARDEN_GOOGLE_CLIENT_ID")
        secret = os.environ.get("GARDEN_GOOGLE_CLIENT_SECRET")
        if not secret:
            return None
    else:
        # VK ID provides both sign-in methods through one registered application.
        client = os.environ.get("GARDEN_VK_CLIENT_ID")
        secret = ""
    if not client:
        return None
    return client, secret, f"{origin}/api/auth/oauth/{provider}/callback"


@router.get("/providers")
async def providers() -> list[dict]:
    return [{"id": key, "name": name, "enabled": bool(config(key))} for key, name in NAMES.items()]


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@router.get("/oauth/{provider}/start")
async def start(provider: str, request: Request) -> RedirectResponse:
    settings = config(provider)
    if not settings:
        raise HTTPException(404, "Этот способ входа пока не настроен")
    rate_limit(request, "oauth", 60)
    client, _, callback = settings
    state = secrets.token_urlsafe(32)
    browser = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(digest(verifier)).rstrip(b"=").decode("ascii")
    db = request.app.state.store.db
    now = int(time.time())
    with db:
        db.execute("DELETE FROM account_oauth_states WHERE expires<=? OR browser=?",
                   (now, digest(request.cookies.get(STATE_COOKIE, ""))))
        db.execute("INSERT INTO account_oauth_states VALUES (?,?,?,?,?)",
                   (digest(state), digest(browser), provider, verifier, now + 600))
    params = {"client_id": client, "redirect_uri": callback, "response_type": "code",
              "code_challenge": challenge, "state": state}
    if provider == "google":
        endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
        params.update(code_challenge_method="S256", scope="openid email profile")
    else:
        endpoint = "https://id.vk.com/authorize"
        params.update(code_challenge_method="s256", scope="email")
        if provider == "mailru":
            params.update(provider="mail_ru", prompt="login")
    response = redirect(endpoint + "?" + urlencode(params))
    response.set_cookie(STATE_COOKIE, browser, httponly=True, secure=cookie_secure(request),
                        max_age=600, samesite="lax", path="/api/auth/oauth/")
    return response


async def identity(provider: str, settings: tuple[str, str, str], code: str, state: str,
                   verifier: str, device: str) -> tuple[str, str, str, str]:
    client_id, secret, callback = settings
    form = {"grant_type": "authorization_code", "client_id": client_id,
            "redirect_uri": callback, "code_verifier": verifier}
    async with httpx.AsyncClient(timeout=10) as client:
        if provider == "google":
            token = await client.post("https://oauth2.googleapis.com/token",
                                      data={**form, "code": code, "client_secret": secret})
            token.raise_for_status()
            access = token.json()["access_token"]
            info = await client.get("https://openidconnect.googleapis.com/v1/userinfo",
                                    headers={"Authorization": "Bearer " + access})
            info.raise_for_status()
            data = info.json()
            if data.get("email_verified") is not True:
                raise ValueError
            subject, email, name = data["sub"], data["email"], data.get("name")
            issuer = "google"
        else:
            if not device:
                raise ValueError
            token = await client.post("https://id.vk.com/oauth2/auth",
                                      params={**form, "device_id": device, "state": state}, data={"code": code})
            token.raise_for_status()
            tokens = token.json()
            if not hmac.compare_digest(state, tokens["state"]):
                raise ValueError
            info = await client.post("https://id.vk.com/oauth2/user_info", params={"client_id": client_id},
                                     data={"access_token": tokens["access_token"]})
            info.raise_for_status()
            data = info.json()["user"]
            subject, email = str(data["user_id"]), data["email"]
            if subject != str(tokens["user_id"]):
                raise ValueError
            name = " ".join(filter(None, (data.get("first_name"), data.get("last_name"))))
            issuer = "vk"
    if not isinstance(subject, str) or not subject or len(subject) > 255 or not isinstance(email, str):
        raise ValueError
    email = normalize_email(email)
    if not isinstance(name, str) or not name.strip() or not name.isprintable():
        name = email.split("@")[0]
    return issuer, subject, email, name.strip()[:100]


def resolve_identity(db: sqlite3.Connection, issuer: str, subject: str, email: str, name: str) -> User:
    # A provider's stable subject identifies returning users. Email alone grants no account access.
    with db:
        row = db.execute("""
            SELECT a.id,a.email,a.name FROM accounts a JOIN account_identities i ON a.id=i.user_id
            WHERE i.issuer=? AND i.subject=?
        """, (issuer, subject)).fetchone()
        if row:
            return User(id=row[0], email=row[1], name=row[2])
        user = User(id=uuid4().hex, email=email, name=name)
        db.execute("INSERT INTO accounts(id,email,name) VALUES (?,?,?)", (user.id, email, name))
        db.execute("INSERT INTO account_identities VALUES (?,?,?)", (issuer, subject, user.id))
    return user


@router.get("/oauth/{provider}/callback")
async def callback(provider: str, request: Request, code: str = "", state: str = "",
                   device_id: str = "") -> RedirectResponse:
    db = request.app.state.store.db
    settings = config(provider)
    with db:
        row = db.execute("""
            DELETE FROM account_oauth_states WHERE digest=? AND browser=? AND provider=? AND expires>?
            RETURNING verifier
        """, (digest(state), digest(request.cookies.get(STATE_COOKIE, "")), provider, int(time.time()))).fetchone()
    error = "Не удалось подтвердить вход. Начните вход заново и разрешите доступ к адресу почты."
    if row and settings and code and len(code) <= 4096 and len(device_id) <= 512:
        try:
            details = await identity(provider, settings, code, state, row[0], device_id)
            user = resolve_identity(db, *details)
        except sqlite3.IntegrityError:
            error = "Этот адрес уже зарегистрирован. Используйте первоначальный способ входа."
        except (ValueError, KeyError, TypeError, httpx.HTTPError):
            pass
        else:
            response = redirect("/")
            start_session(request, response, user)
            response.delete_cookie(STATE_COOKIE, path="/api/auth/oauth/", secure=cookie_secure(request), httponly=True)
            return response
    response = redirect("/?" + urlencode({"auth_error": error}))
    if row:
        response.delete_cookie(STATE_COOKIE, path="/api/auth/oauth/", secure=cookie_secure(request), httponly=True)
    return response
