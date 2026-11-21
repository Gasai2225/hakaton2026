import os
import sqlite3
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi import FastAPI

from garden import accounts, projects


class ProjectTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        app = FastAPI()
        app.include_router(accounts.router)
        app.include_router(projects.router)
        path = Path(self.enterContext(TemporaryDirectory())) / "test.db"
        self.db = sqlite3.connect(path)
        self.addCleanup(self.db.close)
        accounts.init_accounts(self.db)
        projects.init_projects(self.db)
        app.state.store = SimpleNamespace(db=self.db)
        self.owner, self.editor, self.outsider = [
            await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test"))
            for _ in range(3)]
        self.enterContext(patch.dict("os.environ", {"GARDEN_SMTP_HOST": ""}))
        self.counter = 0
        await self.register(self.owner, "owner")

    async def register(self, client, name):
        response = await client.post("/api/auth/register", json={
            "name": name, "email": name+"@example.org", "password": "project-draft-test"})
        self.assertEqual(response.status_code, 201, response.text)

    async def create(self, client):
        self.counter += 1
        response = await client.post("/api/projects", json={"name": "Черновик " + str(self.counter)})
        self.assertEqual(response.status_code, 201, response.text)
        return "/api/projects/" + response.json()["id"], response.json()

    async def grant(self, path):
        invite = await self.owner.post(path+"/members", json={"email": "editor@example.org"})
        self.assertEqual(invite.status_code, 201, invite.text)
        self.assertEqual(invite.json()["delivery"], "link")
        accepted = await self.editor.post("/api/project-invitations/accept", json={"token": invite.json()["token"]})
        self.assertEqual(accepted.status_code, 200, accepted.text)
        return invite.json()["id"]

    async def test_pending_link_binds_account_and_revocation_covers_cached_project(self):
        path, project = await self.create(self.owner)
        invite = (await self.owner.post(path+"/members", json={"email": "Editor@example.org"})).json()
        self.assertEqual((await self.editor.get(path)).status_code, 401)
        await self.register(self.outsider, "someone")
        body = {"token": invite["token"]}
        self.assertEqual((await self.outsider.post("/api/project-invitations/accept", json=body)).status_code, 403)
        await self.register(self.editor, "editor")
        self.assertEqual((await self.editor.get("/api/projects")).json(), [])
        self.assertEqual((await self.editor.get(path)).status_code, 404)
        rotated = (await self.owner.post(path+"/members", json={"email": "editor@example.org"})).json()
        self.assertEqual((await self.editor.post("/api/project-invitations/accept", json=body)).status_code, 404)
        token = {"token": rotated["token"]}
        accepted = await self.editor.post("/api/project-invitations/accept", json=token)
        self.assertEqual(accepted.json()["role"], "editor")
        self.assertEqual((await self.editor.post("/api/project-invitations/accept", json=token)).status_code, 404)
        self.assertEqual((await self.editor.post(path+"/members", json={"email": "someone@example.org"})).status_code, 403)
        self.assertEqual((await self.editor.delete(path+"/members/"+invite["id"])).status_code, 403)
        self.assertEqual((await self.owner.get(path+"/members")).json()[1]["status"], "active")
        tag = (await self.editor.get(path)).headers["etag"]
        self.assertEqual((await self.editor.get(path, headers={"If-None-Match": tag})).status_code, 304)
        self.assertEqual((await self.owner.delete(path+"/members/"+invite["id"])).status_code, 204)
        self.assertEqual((await self.editor.get(path, headers={"If-None-Match": tag})).status_code, 404)
        self.assertEqual((await self.editor.put(path, json={"base_revision": 1, "workflow": project["workflow"]})).status_code, 404)
        self.assertEqual((await self.editor.get(path+"/members")).status_code, 404)
        self.assertEqual((await self.editor.get("/api/projects")).json(), [])

    async def test_two_editors_merge_independent_changes_and_reject_overwrites(self):
        await self.register(self.editor, "editor")
        path, base = await self.create(self.owner)
        await self.grant(path)
        async def save(client, n, graph):
            return await client.put(path, json={"base_revision": n, "workflow": graph})
        # Temporarily disconnected nodes and empty sources are valid drafts.
        ours = deepcopy(base["workflow"])
        ours["nodes"].append({"id": "scan", "kind": "secrets", "x": 30, "y": 20})
        response = await save(self.owner, 1, ours)
        self.assertEqual(response.status_code, 200, response.text)
        theirs = deepcopy(base["workflow"])
        theirs["nodes"][0]["x"] = 30
        theirs["files"] = [{"path": "Demo.kt", "text": "fun demo() = 1"}]
        merged = await save(self.editor, 1, theirs)
        self.assertEqual(merged.json()["revision"], 3)
        graph = merged.json()["workflow"]
        self.assertEqual([n["id"] for n in graph["nodes"]], ["start", "scan"])
        self.assertEqual((graph["nodes"][0]["x"], graph["files"]), (30, theirs["files"]))
        retry = await save(self.editor, 1, theirs)
        self.assertEqual(retry.json()["revision"], 3)
        a, b = deepcopy(graph), deepcopy(graph)
        a["nodes"][0]["x"], b["nodes"][0]["y"] = 70, 55
        self.assertEqual((await save(self.owner, 3, a)).status_code, 200)
        self.assertEqual((await save(self.editor, 3, b)).json()["workflow"]["nodes"][0]["x"], 70)
        b["nodes"][0]["x"] = 90
        self.assertEqual((await save(self.editor, 3, b)).status_code, 409)
        actual = (await self.editor.get(path)).json()
        self.assertEqual((actual["revision"], actual["workflow"]["nodes"][0]["x"]), (5, 70))

    async def test_new_edge_and_concurrent_node_removal_remain_consistent(self):
        path, base = await self.create(self.owner)
        graph = base["workflow"]
        graph["nodes"].append({"id": "c", "kind": "secrets", "x": 0, "y": 0})
        response = await self.owner.put(path, json={"base_revision": 1, "workflow": graph})
        self.assertEqual(response.status_code, 200)
        deleted = deepcopy(graph)
        deleted["nodes"].pop()
        self.assertEqual((await self.owner.put(path, json={"base_revision": 2, "workflow": deleted})).status_code, 200)
        graph["edges"].append({"id": "a-b", "source": "start", "target": "c"})
        conflict = await self.owner.put(path, json={"base_revision": 2, "workflow": graph})
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual((await self.owner.get(path)).json()["workflow"]["edges"], [])

    async def test_edits_typed_in_flight_rebase_over_remote_changes_in_acknowledgement(self):
        path, base = await self.create(self.owner)
        graph = base["workflow"]
        sent, remote = deepcopy(graph), deepcopy(graph)
        sent["name"] = "Про"
        remote["nodes"][0]["x"] = 100
        await self.owner.put(path, json={"base_revision": 1, "workflow": remote})
        ack = (await self.owner.put(path, json={"base_revision": 1, "workflow": sent})).json()
        self.assertEqual(ack["workflow"]["nodes"][0]["x"], 100)
        typed = deepcopy(sent)
        typed["name"] = "Проект"
        response = await self.owner.put(path, json={"base_revision": ack["revision"], "edit_base": sent,
                                                     "workflow": typed})
        self.assertEqual(response.status_code, 200, response.text)
        saved = response.json()["workflow"]
        self.assertEqual((saved["name"], saved["nodes"][0]["x"]), ("Проект", 100))
        typed["nodes"][0]["x"] = 50
        response = await self.owner.put(path, json={"base_revision": ack["revision"], "edit_base": sent, "workflow": typed})
        self.assertEqual(response.status_code, 409)

    async def test_projects_are_isolated_and_foreign_origin_cannot_invite(self):
        await self.register(self.editor, "editor")
        first, _ = await self.create(self.owner)
        second, _ = await self.create(self.owner)
        foreign, _ = await self.create(self.editor)
        await self.grant(first)
        self.assertEqual(len((await self.owner.get("/api/projects")).json()), 2)
        self.assertEqual(len((await self.editor.get("/api/projects")).json()), 2)
        self.assertEqual((await self.owner.get(foreign)).status_code, 404)
        self.assertEqual((await self.editor.get(second)).status_code, 404)
        response = await self.owner.post(first+"/members", json={"email": "other@example.org"},
                                         headers={"origin":"https://elsewhere.example"})
        self.assertEqual(response.status_code, 403)

    async def test_presence_is_scoped_unique_expires_and_responds_to_revocation(self):
        await self.register(self.editor, "editor")
        path, _ = await self.create(self.owner)
        other, _ = await self.create(self.owner)
        presence = path + "/presence"
        self.assertEqual((await self.editor.post(presence)).status_code, 404)
        self.assertEqual((await self.outsider.post(presence)).status_code, 401)
        member_id = await self.grant(path)
        self.assertEqual((await self.owner.post(presence)).json(), {"peers": []})
        for _ in range(2):
            editor_peers = (await self.editor.post(presence)).json()["peers"]
            self.assertEqual([p["name"] for p in editor_peers], ["owner"])
            self.assertEqual(set(editor_peers[0]), {"id", "name"})
        self.assertEqual([p["name"] for p in (await self.owner.post(presence)).json()["peers"]], ["editor"])
        self.assertEqual((await self.owner.post(other+"/presence")).json(), {"peers": []})
        now = projects.time.time()
        with patch("garden.projects.time.time", return_value=now + projects.PRESENCE_SECONDS + 1):
            self.assertEqual((await self.owner.post(presence)).json(), {"peers": []})
            self.assertEqual(self.db.execute("SELECT COUNT(*) FROM project_presence").fetchone()[0], 1)
        await self.editor.post(presence)
        self.assertEqual((await self.owner.delete(path+"/members/"+member_id)).status_code, 204)
        self.assertEqual((await self.owner.post(presence)).json(), {"peers": []})
        self.assertEqual((await self.editor.post(presence)).status_code, 404)


class InvitationMailTests(unittest.TestCase):
    def test_configured_tls_mail_contains_fragment_token_and_bound_recipient(self):
        with patch.dict(os.environ, {"GARDEN_SMTP_HOST":"smtp.example.org", "GARDEN_SMTP_FROM":"garden@example.org",
                                     "GARDEN_PUBLIC_ORIGIN":"https://garden.example.org", "GARDEN_SMTP_MODE":"starttls",
                                     "GARDEN_SMTP_USER":"", "GARDEN_SMTP_PORT":"587"}), patch("garden.projects.smtplib.SMTP") as smtp:
            status = projects.send_invitation("member@example.org", "Аудит", "inviteToken")
        self.assertEqual(status, "sent")
        smtp.return_value.starttls.assert_called_once()
        message = smtp.return_value.send_message.call_args.args[0]
        self.assertEqual(message["To"], "member@example.org")
        self.assertIn("https://garden.example.org/#invite=inviteToken", message.get_content())

    def test_mail_failure_preserves_the_copyable_link(self):
        with patch.dict(os.environ, {"GARDEN_SMTP_HOST":"smtp.example.org", "GARDEN_SMTP_FROM":"garden@example.org",
                                     "GARDEN_PUBLIC_ORIGIN":"https://garden.example.org", "GARDEN_SMTP_MODE":"ssl",
                                     "GARDEN_SMTP_PORT":"465"}), patch("garden.projects.smtplib.SMTP_SSL", side_effect=OSError):
            self.assertEqual(projects.send_invitation("member@example.org", "Аудит", "inviteToken"), "failed")
