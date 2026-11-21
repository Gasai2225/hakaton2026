import asyncio
import sqlite3
import unittest
from contextlib import aclosing
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi import FastAPI, Request

from garden import accounts, projects


class MemberPermissions(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.enterContext(patch.dict("os.environ", {"GARDEN_SMTP_HOST": "", "GARDEN_PUBLIC_ORIGIN": ""}))
        self.app = FastAPI()
        self.app.include_router(accounts.router)
        self.app.include_router(projects.router)
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        accounts.init_accounts(self.db)
        projects.init_projects(self.db)
        self.app.state.store = SimpleNamespace(db=self.db)
        self.owner, self.member = [await self.enterAsyncContext(httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test")) for _ in range(2)]
        self.form = {"email": "guest@example.org", "name": "Guest", "password": "guest-password"}
        await self.owner.post("/api/auth/register", json={**self.form, "email": "owner@example.org"})
        self.project = (await self.owner.post("/api/projects", json={"name": "Shared"})).json()
        self.path = "/api/projects/" + self.project["id"]

    async def invite(self, **rights):
        response = await self.owner.post(self.path + "/members", json={"email": self.form["email"], **rights})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    async def test_stale_reissue_keeps_current_grants_and_cannot_restore_or_rotate_a_replacement(self):
        first = await self.invite(role="editor", can_run=True)
        path = self.path + "/members"
        # A duplicate submitted through the invite form must not send an editor link when the owner asked for reports only.
        with patch.object(projects, "send_invitation") as send:
            duplicate = await self.owner.post(path, json={"email": self.form["email"], "role": "reporter", "can_run": False})
            self.assertEqual(duplicate.status_code, 409)
            send.assert_not_called()
        stale = {"email": self.form["email"], "reissue_id": first["id"], "role": "editor", "can_run": True}
        member_path = path + "/" + first["id"]
        await self.owner.patch(member_path, json={"role": "reporter", "can_run": False})
        renewed = await self.owner.post(path, json=stale)
        self.assertEqual(renewed.status_code, 201, renewed.text)
        self.assertEqual((renewed.json()["role"], renewed.json()["can_run"]), ("reporter", False))
        self.assertNotEqual(renewed.json()["token"], first["token"])
        await self.owner.delete(member_path)
        self.assertEqual((await self.owner.post(path, json=stale)).status_code, 404)
        self.assertEqual(len((await self.owner.get(path)).json()), 1)
        replacement = await self.invite(role="viewer", can_run=False)
        self.assertEqual((await self.owner.post(path, json=stale)).status_code, 404)
        replacement_row = (await self.owner.get(path)).json()[1]
        self.assertEqual(replacement_row["invite_version"], replacement["invite_version"])
        await self.member.post("/api/auth/register-and-join", json={**self.form, "invitation_token": replacement["token"]})
        self.assertEqual((await self.owner.post(path, json={**stale, "reissue_id": replacement["id"]})).status_code, 409)

    async def test_invitation_rights_are_preserved_across_reissue_and_reporting_access(self):
        first = await self.invite()
        member = self.path + "/members/" + first["id"]
        self.assertEqual((await self.owner.patch(member, json={"role": "reporter", "can_run": False})).status_code, 204)
        current = await self.invite()
        roster = (await self.owner.get(self.path + "/members")).json()
        self.assertEqual((roster[1]["role"], roster[1]["can_run"]), ("reporter", False))
        self.assertNotEqual(current["token"], first["token"])
        registered = await self.member.post("/api/auth/register-and-join", json={**self.form, "invitation_token": current["token"]})
        self.assertEqual(registered.status_code, 201, registered.text)
        brief = (await self.member.get(self.path + "/access")).json()
        self.assertEqual((brief["role"], brief["can_run"]), ("reporter", False))
        self.assertNotIn("workflow", brief)
        self.assertEqual((await self.member.get("/api/projects")).json(), [brief])
        accepted = await self.member.post("/api/project-invitations/accept", json={"token": current["token"]})
        self.assertEqual(accepted.json(), brief)
        self.assertEqual((await self.member.get(self.path)).status_code, 403)
        self.assertEqual((await self.member.get(self.path + "/members")).status_code, 403)
        self.assertEqual((await self.member.post(self.path + "/presence")).status_code, 403)
        self.assertEqual((await self.member.patch(member, json={"role": "editor", "can_run": True})).status_code, 403)
        self.assertEqual((await self.owner.patch(member, json={"role": "reporter", "can_run": True})).status_code, 422)
        self.assertEqual((await self.owner.patch(member, json={"role": "owner", "can_run": True})).status_code, 422)
        self.assertEqual((await self.owner.delete(member)).status_code, 204)
        self.assertEqual((await self.member.get(self.path + "/access")).status_code, 404)

    async def test_downgrade_releases_node_and_checks_even_unchanged_put_or_conditional_get(self):
        invitation = await self.invite(role="editor", can_run=False)
        await self.member.post("/api/auth/register", json=self.form)
        await self.member.post("/api/project-invitations/accept", json={"token": invitation["token"]})
        member = self.path + "/members/" + invitation["id"]
        cookie = accounts.SESSION_COOKIE + "=" + self.member.cookies.get(accounts.SESSION_COOKIE)
        request = Request({"type": "http", "app": self.app, "method": "GET", "scheme": "http", "path": self.path,
                           "root_path": "", "query_string": b"", "headers": [(b"host", b"test"), (b"cookie", cookie.encode())]})
        client_id = "a" * 32
        stream = await projects.presence_stream(request, self.project["id"], client_id)
        events = await self.enterAsyncContext(aclosing(stream.body_iterator))
        await anext(events)
        lock = {"client_id": client_id, "node_id": "start"}
        self.assertEqual((await self.member.post(self.path + "/presence/lock", json=lock)).status_code, 204)
        tag = (await self.member.get(self.path)).headers["etag"]
        save = {"base_revision": 1, "workflow": self.project["workflow"]}
        self.assertEqual((await self.owner.patch(member, json={"role": "viewer", "can_run": True})).status_code, 204)
        with self.assertRaises(StopAsyncIteration):
            await asyncio.wait_for(anext(events), timeout=1)
        self.assertEqual((await self.member.post(self.path + "/presence/lock", json=lock)).status_code, 403)
        self.assertEqual((await self.member.put(self.path, json=save)).status_code, 403)
        self.assertEqual((await self.member.get(self.path + "/members")).status_code, 403)
        changed = await self.member.get(self.path, headers={"If-None-Match": tag})
        self.assertEqual(changed.status_code, 200)
        self.assertNotEqual(changed.headers["etag"], tag)
        graph = changed.json()
        self.assertEqual((graph["role"], graph["can_run"]), ("viewer", True))
        await self.owner.patch(member, json={"role": "reporter", "can_run": False})
        self.assertEqual((await self.member.get(self.path, headers={"If-None-Match": tag})).status_code, 403)

    async def test_editor_without_run_permission_cannot_create_an_active_schedule(self):
        invitation = await self.invite(role="editor", can_run=False)
        await self.member.post("/api/auth/register-and-join", json={**self.form, "invitation_token": invitation["token"]})
        draft = deepcopy(self.project["workflow"])
        draft["nodes"][0].update(kind="schedule", enabled=True)
        draft["nodes"].append({"id": "scan", "kind": "sast", "x": 200, "y": 0})
        draft["edges"].append({"id": "start-scan", "source": "start", "target": "scan"})
        save = {"base_revision": 1, "workflow": draft}
        self.assertEqual((await self.member.put(self.path, json=save)).status_code, 403)
        draft["nodes"][0]["enabled"] = False
        allowed = await self.member.put(self.path, json=save)
        self.assertEqual(allowed.status_code, 200, allowed.text)
        draft["nodes"][0]["enabled"] = True
        owner_save = await self.owner.put(self.path, json={"base_revision": 2, "workflow": draft})
        self.assertEqual(owner_save.status_code, 200, owner_save.text)
        draft["files"] = [{"path": "Demo.kt", "text": "class Demo"}]
        self.assertEqual((await self.member.put(self.path, json={"base_revision": 3, "workflow": draft})).status_code, 403)
        verified = await self.owner.put(self.path, json={"base_revision": 3, "workflow": draft})
        self.assertEqual(verified.status_code, 200, verified.text)
        draft["name"] = "Независимая правка"
        self.assertEqual((await self.member.put(self.path, json={"base_revision": 4, "workflow": draft})).status_code, 200)
        draft["nodes"][0]["cron"] = "* * * * *"
        self.assertEqual((await self.member.put(self.path, json={"base_revision": 5, "workflow": draft})).status_code, 403)


class PermissionMigration(unittest.TestCase):
    def test_active_and_pending_members_keep_their_original_rights(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute("""CREATE TABLE project_members (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, email TEXT NOT NULL,
            account_id TEXT, token_hash TEXT UNIQUE, expires_at INTEGER, UNIQUE(project_id,email))""")
        db.executemany("INSERT INTO project_members VALUES (?,?,?,?,?,?)", [
            ("m1", "p", "a@example.org", "a", "token1", None), ("m2", "p", "b@example.org", None, "token2", 123)])
        projects.init_projects(db)
        projects.init_projects(db)
        self.assertEqual(db.execute("SELECT role,can_run FROM project_members ORDER BY id").fetchall(),
                         [("editor", 1), ("editor", 1)])
