import asyncio
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi import FastAPI

from garden import accounts, projects


JOIN = "/api/auth/register-and-join"


class InvitedRegistrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.enterContext(patch.dict("os.environ", {"GARDEN_SMTP_HOST": "", "GARDEN_PUBLIC_ORIGIN": ""}))
        self.db = sqlite3.connect(Path(self.enterContext(TemporaryDirectory())) / "test.db")
        self.addCleanup(self.db.close)
        accounts.init_accounts(self.db)
        projects.init_projects(self.db)
        app = FastAPI()
        app.include_router(accounts.router)
        app.include_router(projects.router)
        app.state.store = SimpleNamespace(db=self.db)
        transport = httpx.ASGITransport(app, raise_app_exceptions=False)
        self.owner, self.guest, self.other = [
            await self.enterAsyncContext(httpx.AsyncClient(transport=transport, base_url="http://test"))
            for _ in range(3)]
        owner = await self.owner.post("/api/auth/register", json={
            "name": "Owner", "email": "owner@example.org", "password": "original-password"})
        self.assertEqual(owner.status_code, 201, owner.text)
        self.project = (await self.owner.post("/api/projects", json={"name": "Общий граф"})).json()
        self.path = "/api/projects/" + self.project["id"]
        invite = await self.invite()
        self.form = {"invitation_token": invite["token"], "email": "Editor@Example.org",
                     "name": "Editor", "password": "invited-password"}

    async def invite(self):
        response = await self.owner.post(self.path + "/members", json={"email": "editor@example.org"})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    async def test_simultaneous_signups_grant_one_editor_session_and_reopen_the_project(self):
        guests = [self.guest, self.other]
        results = await asyncio.gather(*(client.post(JOIN, json=self.form) for client in guests))
        statuses = [response.status_code for response in results]
        self.assertCountEqual(statuses, [201, 409])
        active = statuses.index(201)
        joined = results[active].json()
        member, anonymous = guests[active], guests[1 - active]
        self.assertEqual(joined["user"]["email"], "editor@example.org")
        self.assertEqual(joined["project_id"], self.project["id"])
        self.assertEqual((await member.get("/api/auth/me")).json(), joined["user"])
        self.assertEqual((await anonymous.get(self.path)).status_code, 401)
        self.assertEqual((await member.get(self.path)).json()["role"], "editor")
        preview = await member.post("/api/project-invitations/preview", json={"token": self.form["invitation_token"]})
        self.assertEqual(preview.json(), {"status": "accepted", "project_id": joined["project_id"],
                                          "project_name": self.project["name"]})

    async def test_existing_account_must_sign_in_and_accept(self):
        registered = await self.other.post("/api/auth/register", json={**self.form, "password": "existing-password"})
        self.assertEqual(registered.status_code, 201)
        duplicate = await self.guest.post(JOIN, json=self.form)
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual((await self.guest.get("/api/auth/me")).status_code, 401)
        self.assertEqual((await self.other.get(self.path)).status_code, 404)
        login = await self.guest.post("/api/auth/login", json={"email": self.form["email"], "password": "existing-password"})
        self.assertEqual(login.json(), registered.json())
        accept = await self.guest.post("/api/project-invitations/accept", json={"token": self.form["invitation_token"]})
        self.assertEqual(accept.json()["id"], self.project["id"])

    async def test_validation_and_stale_links_leave_registration_available(self):
        missing_token = {key: value for key, value in self.form.items() if key != "invitation_token"}
        self.assertEqual((await self.guest.post(JOIN, json=missing_token)).status_code, 422)
        wrong_email = await self.guest.post(JOIN, json={**self.form, "email": "typo@example.org"})
        self.assertEqual(wrong_email.status_code, 422)
        foreign = await self.guest.post(JOIN, json=self.form, headers={"Origin": "https://elsewhere.example"})
        self.assertEqual(foreign.status_code, 403)
        rotated = await self.invite()
        self.assertEqual((await self.guest.post(JOIN, json=self.form)).status_code, 404)
        with self.db:
            self.db.execute("UPDATE project_members SET expires_at=0 WHERE id=?", (rotated["id"],))
        expired = await self.guest.post(JOIN, json={**self.form, "invitation_token": rotated["token"]})
        self.assertEqual(expired.status_code, 404)
        fresh = await self.invite()
        revoked = await self.owner.delete(self.path + "/members/" + fresh["id"])
        self.assertEqual(revoked.status_code, 204)
        stale = await self.guest.post(JOIN, json={**self.form, "invitation_token": fresh["token"]})
        self.assertEqual(stale.status_code, 404)
        self.assertEqual(self.db.execute("SELECT count(*) FROM accounts").fetchone()[0], 1)
        self.assertEqual((await self.guest.get("/api/auth/me")).status_code, 401)

    async def test_session_write_failure_rolls_back_account_membership_and_previous_login(self):
        before = (await self.owner.get("/api/auth/me")).json()
        self.db.execute("""CREATE TRIGGER fail_session BEFORE INSERT ON account_sessions
                           BEGIN SELECT RAISE(ABORT, 'session write failed'); END""")
        self.assertEqual((await self.owner.post(JOIN, json=self.form)).status_code, 500)
        self.assertEqual((await self.owner.get("/api/auth/me")).json(), before)
        self.assertEqual(self.db.execute("SELECT count(*) FROM accounts").fetchone()[0], 1)
        self.assertIsNone(self.db.execute("SELECT account_id FROM project_members").fetchone()[0])
        self.db.execute("DROP TRIGGER fail_session")
        retry = await self.guest.post(JOIN, json=self.form)
        self.assertEqual(retry.status_code, 201, retry.text)
