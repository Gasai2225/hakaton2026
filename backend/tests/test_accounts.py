import base64
import hashlib
import sqlite3
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi import FastAPI

from garden import account_oauth, accounts


class AccountsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.env = self.enterContext(patch.dict("os.environ", {
            "GARDEN_PUBLIC_ORIGIN": "https://garden.test", "GARDEN_GOOGLE_CLIENT_ID": "google-app",
            "GARDEN_GOOGLE_CLIENT_SECRET": "test-secret", "GARDEN_VK_CLIENT_ID": "vk-app",
        }))
        self.app = FastAPI()
        self.app.include_router(accounts.router)
        self.app.include_router(account_oauth.router)
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.app.state.store = SimpleNamespace(db=self.db)
        accounts.init_accounts(self.db)
        self.transport = httpx.ASGITransport(app=self.app)
        self.client = await self.enterAsyncContext(httpx.AsyncClient(transport=self.transport,
                                                    base_url="https://garden.test", follow_redirects=False))
        self.form = {"email": " Someone@Example.COM ", "name": "  Иван ", "password": "garden-test-2026"}

    async def test_registration_login_profile_revocation(self):
        response = await self.client.post("/api/auth/register", json=self.form)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["email"], "someone@example.com")
        self.assertEqual(response.json()["name"], "Иван")
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertIn("Secure", response.headers["set-cookie"])
        self.assertIn("SameSite=lax", response.headers["set-cookie"])
        original = self.client.cookies.get(accounts.SESSION_COOKIE)
        changed = await self.client.patch("/api/auth/me", json={"name": "Alex"})
        self.assertEqual(changed.json()["name"], "Alex")
        login = await self.client.post("/api/auth/login", json=self.form)
        self.assertEqual(login.json()["id"], response.json()["id"])
        self.assertNotEqual(self.client.cookies.get(accounts.SESSION_COOKIE), original)
        denied = await self.client.get("/api/auth/me", headers={"Cookie": f"garden_session={original}"})
        self.assertEqual(denied.status_code, 401)
        seen = await self.client.get("/api/auth/me")
        self.assertEqual(seen.json()["name"], "Alex")
        active = self.client.cookies.get(accounts.SESSION_COOKIE)
        self.assertEqual((await self.client.post("/api/auth/logout")).status_code, 204)
        self.assertEqual((await self.client.get("/api/auth/me", headers={"Cookie": "garden_session="+active})).status_code, 401)
        stored = self.db.execute("SELECT salt,password_hash FROM accounts").fetchone()
        self.assertEqual(tuple(map(len, stored)), (16, 32))

    async def test_invalid_input_and_browser_origin(self):
        for form in ({**self.form, "password": "short"}, {**self.form, "email": "not-an-email"},
                     {**self.form, "name": "   "}):
            self.assertEqual((await self.client.post("/api/auth/register", json=form)).status_code, 422)
        for origin in ("https://other.example", "null", "https://sub.garden.test"):
            response = await self.client.post("/api/auth/register", headers={"Origin": origin}, json=self.form)
            self.assertEqual(response.status_code, 403)
        self.assertEqual((await self.client.post("/api/auth/register", json=self.form,
                                                 headers={"Origin": "https://garden.test"})).status_code, 201)
        self.assertEqual((await self.client.post("/api/auth/register", json=self.form)).status_code, 409)
        self.assertEqual((await self.client.patch("/api/auth/me", headers={"Origin": "null"},
                                                  json={"name": "Mallory"})).status_code, 403)
        self.assertEqual((await self.client.get("/api/auth/me")).json()["name"], "Иван")
        with self.db:
            self.db.execute("UPDATE account_sessions SET expires=0")
        self.assertEqual((await self.client.get("/api/auth/me")).status_code, 401)

    async def test_rate_limit_returns_retry_after_without_issuing_session(self):
        with patch.object(accounts, "password_hash", return_value=b"wrong"):
            for _ in range(12):
                denied = await self.client.post("/api/auth/login", json=self.form)
                self.assertEqual(denied.status_code, 401)
            throttled = await self.client.post("/api/auth/login", json=self.form)
        self.assertEqual(throttled.status_code, 429)
        self.assertGreater(int(throttled.headers["Retry-After"]), 0)
        self.assertFalse(self.client.cookies)

    async def start_oauth(self, provider):
        response = await self.client.get(f"/api/auth/oauth/{provider}/start")
        self.assertEqual(response.status_code, 303)
        return parse_qs(urlsplit(response.headers["location"]).query)

    async def test_oauth_state_is_client_bound_one_time_and_never_links_by_address(self):
        await self.client.post("/api/auth/register", json=self.form)
        await self.client.post("/api/auth/logout")
        params = await self.start_oauth("google")
        self.assertEqual(params["code_challenge_method"], ["S256"])
        callback = "/api/auth/oauth/google/callback"
        query = {"code": "code", "state": params["state"][0]}
        async with httpx.AsyncClient(transport=self.transport, base_url="https://garden.test") as outsider:
            rejected = await outsider.get(callback, params=query)
            self.assertIn("auth_error", rejected.headers["location"])
        claimed = ("google", "123", "someone@example.com", "Google User")
        with patch.object(account_oauth, "identity", return_value=claimed) as exchange:
            rejected = await self.client.get(callback, params=query)
            self.assertIn("первоначальный", parse_qs(urlsplit(rejected.headers["location"]).query)["auth_error"][0])
            self.assertEqual((await self.client.get("/api/auth/me")).status_code, 401)
            replay = await self.client.get(callback, params=query)
            exchange.assert_awaited_once()
            self.assertIn("auth_error", replay.headers["location"])

    async def test_google_registration_pkce_and_returning_subject(self):
        subject = "subject-123"
        for email in ("first@example.com", "changed@example.com"):
            query = await self.start_oauth("google")

            def exchange(req):
                if str(req.url) == "https://oauth2.googleapis.com/token":
                    body = parse_qs(req.content.decode())
                    verifier = body["code_verifier"][0].encode("ascii")
                    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).rstrip(b"=").decode()
                    self.assertEqual(challenge, query["code_challenge"][0])
                    return httpx.Response(200, json={"access_token": "short-lived-token"})
                self.assertEqual(req.headers["Authorization"], "Bearer short-lived-token")
                self.assertEqual(str(req.url), "https://openidconnect.googleapis.com/v1/userinfo")
                return httpx.Response(200, json={"sub": subject, "email": email, "email_verified": True, "name": "Anna"})

            external = httpx.AsyncClient(transport=httpx.MockTransport(exchange))
            with patch.object(account_oauth.httpx, "AsyncClient", return_value=external):
                callback = await self.client.get("/api/auth/oauth/google/callback",
                                                 params={"code": "abc", "state": query["state"][0]})
            self.assertEqual(callback.headers["location"], "/?auth_complete=1")
            self.assertEqual((await self.client.get("/api/auth/me")).json()["email"], "first@example.com")
            await self.client.post("/api/auth/logout")
        self.assertEqual(self.db.execute("SELECT count(*) FROM accounts").fetchone()[0], 1)

    async def test_vk_and_mail_share_issuer_and_validate_device_and_token_state(self):
        for provider in ("vk", "mailru"):
            query = await self.start_oauth(provider)
            if provider == "mailru":
                self.assertEqual(query["provider"], ["mail_ru"])
            state = query["state"][0]

            def exchange(req):
                if req.url.path.endswith("/auth"):
                    self.assertEqual(req.url.params["device_id"], "device")
                    self.assertEqual(req.url.params["state"], state)
                    self.assertEqual(parse_qs(req.content.decode())["code"], ["code"])
                    return httpx.Response(200, json={"state": state, "user_id": 17, "access_token": "one-use"})
                self.assertEqual(req.url.path, "/oauth2/user_info")
                return httpx.Response(200, json={"user": {"user_id": "17", "email": "vk@mail.ru", "first_name": "Анна"}})

            external = httpx.AsyncClient(transport=httpx.MockTransport(exchange))
            with patch.object(account_oauth.httpx, "AsyncClient", return_value=external):
                result = await self.client.get(f"/api/auth/oauth/{provider}/callback",
                                               params={"code": "code", "state": state, "device_id": "device"})
            self.assertEqual(result.headers["location"], "/?auth_complete=1")
            self.assertEqual((await self.client.get("/api/auth/me")).json()["name"], "Анна")
        self.assertEqual(self.db.execute("SELECT count(*) FROM accounts").fetchone()[0], 1)

    async def test_providers_disabled_until_configured(self):
        with patch.dict("os.environ", {"GARDEN_GOOGLE_CLIENT_SECRET": "", "GARDEN_VK_CLIENT_ID": ""}):
            providers = (await self.client.get("/api/auth/providers")).json()
            self.assertTrue(all(not item["enabled"] for item in providers))
            self.assertEqual((await self.client.get("/api/auth/oauth/mailru/start")).status_code, 404)
