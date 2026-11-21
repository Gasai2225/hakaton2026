import asyncio
import json
import os
import sqlite3
import unittest
from contextlib import aclosing
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi import FastAPI, Request

from garden import accounts, board_presence, projects


class ProjectTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        app = FastAPI()
        self.app = app
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
        preview = "/api/project-invitations/preview"
        self.assertEqual((await self.editor.get(path)).status_code, 401)
        await self.register(self.outsider, "someone")
        body = {"token": invite["token"]}
        guest = await self.editor.post(preview, json=body)
        self.assertEqual(guest.json(), {"status": "pending", "project_name": project["name"], "email_hint": "e•••@example.org"})
        self.assertEqual((await self.outsider.post(preview, json=body)).json()["status"], "wrong_account")
        self.assertEqual((await self.outsider.post("/api/project-invitations/accept", json=body)).status_code, 403)
        await self.register(self.editor, "editor")
        self.assertEqual((await self.editor.get("/api/projects")).json(), [])
        self.assertEqual((await self.editor.get(path)).status_code, 404)
        rotated = (await self.owner.post(path+"/members", json={"email": "editor@example.org"})).json()
        self.assertEqual((await self.editor.post(preview, json=body)).status_code, 404)
        self.assertEqual((await self.editor.post("/api/project-invitations/accept", json=body)).status_code, 404)
        token = {"token": rotated["token"]}
        accepted = await self.editor.post("/api/project-invitations/accept", json=token)
        self.assertEqual(accepted.json()["role"], "editor")
        self.assertEqual((await self.editor.post(preview, json=token)).json(),
                         {"status": "accepted", "project_name": project["name"], "project_id": project["id"]})
        retry = await self.editor.post("/api/project-invitations/accept", json=token)
        self.assertEqual(retry.json()["id"], project["id"])
        self.assertEqual((await self.outsider.post("/api/project-invitations/accept", json=token)).status_code, 404)
        self.assertEqual((await self.outsider.post(preview, json=token)).json(), {"status": "wrong_account"})
        await self.outsider.post("/api/auth/logout")
        self.assertEqual((await self.outsider.post(preview, json=token)).json(), {"status": "sign_in"})
        self.assertEqual((await self.editor.post(path+"/members", json={"email": "someone@example.org"})).status_code, 403)
        self.assertEqual((await self.editor.delete(path+"/members/"+invite["id"])).status_code, 403)
        self.assertEqual((await self.owner.get(path+"/members")).json()[1]["status"], "active")
        tag = (await self.editor.get(path)).headers["etag"]
        self.assertEqual((await self.editor.get(path, headers={"If-None-Match": tag})).status_code, 304)
        self.assertEqual((await self.owner.delete(path+"/members/"+invite["id"])).status_code, 204)
        self.assertEqual((await self.editor.post(preview, json=token)).status_code, 404)
        self.assertEqual((await self.editor.post("/api/project-invitations/accept", json=token)).status_code, 404)
        self.assertEqual((await self.editor.get(path, headers={"If-None-Match": tag})).status_code, 404)
        self.assertEqual((await self.editor.put(path, json={"base_revision": 1, "workflow": project["workflow"]})).status_code, 404)
        self.assertEqual((await self.editor.get(path+"/members")).status_code, 404)
        self.assertEqual((await self.editor.get("/api/projects")).json(), [])

    async def test_expired_invitation_cannot_preview_project_or_grant_access(self):
        path, _ = await self.create(self.owner)
        token = (await self.owner.post(path+"/members", json={"email": "editor@example.org"})).json()["token"]
        await self.register(self.editor, "editor")
        with patch("garden.projects.time.time", return_value=projects.time.time() + 8 * 86400):
            for operation in ("preview", "accept"):
                response = await self.editor.post("/api/project-invitations/"+operation, json={"token": token})
                self.assertEqual(response.status_code, 404)
        self.assertEqual((await self.editor.get(path)).status_code, 404)

    async def test_invited_registration_catches_a_typo_before_creating_an_account(self):
        path, _ = await self.create(self.owner)
        token = (await self.owner.post(path+"/members", json={"email": "editor@example.org"})).json()["token"]
        form = {"name": "Editor", "email": "edtor@example.org", "password": "project-draft-test", "invitation_token": token}
        response = await self.editor.post("/api/auth/register", json=form)
        self.assertEqual(response.status_code, 422)
        self.assertEqual((await self.editor.get("/api/auth/me")).status_code, 401)
        self.assertIsNone(self.db.execute("SELECT id FROM accounts WHERE email=?", (form["email"],)).fetchone())
        form["email"] = "Editor@example.org"
        self.assertEqual((await self.editor.post("/api/auth/register", json=form)).status_code, 201)
        self.assertEqual((await self.editor.get(path)).status_code, 404)
        accepted = await self.editor.post("/api/project-invitations/accept", json={"token": token})
        self.assertEqual(accepted.status_code, 200)

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


    async def open_board_tab(self, path, client, tab_id):
        cookie = accounts.SESSION_COOKIE + "=" + client.cookies.get(accounts.SESSION_COOKIE)
        request = Request({"type": "http", "app": self.app, "method": "GET", "scheme": "http",
                           "path": path, "root_path": "", "query_string": b"",
                           "headers": [(b"host", b"test"), (b"cookie", cookie.encode())]})
        response = await projects.presence_stream(request, path.rsplit("/", 1)[1], tab_id)
        self.assertEqual(response.headers["x-accel-buffering"], "no")
        return await self.enterAsyncContext(aclosing(response.body_iterator))

    async def peers(self, stream):
        event = await asyncio.wait_for(anext(stream), timeout=1)
        return json.loads(event.removeprefix("data: "))["peers"]

    async def test_board_stream_cursors_and_tabs_are_ephemeral_and_account_scoped(self):
        await self.register(self.editor, "editor")
        path, project = await self.create(self.owner)
        await self.grant(path)
        owner_id, tab1, tab2 = "a" * 32, "b" * 32, "c" * 32
        endpoint = path + "/presence/cursor"
        owner = await self.open_board_tab(path, self.owner, owner_id)
        self.assertEqual(await self.peers(owner), [])
        editor = await self.open_board_tab(path, self.editor, tab1)
        self.assertEqual([p["name"] for p in await self.peers(editor)], ["owner"])
        peer, = await self.peers(owner)
        self.assertEqual(peer["name"], "editor")
        self.assertIsNone(peer["cursor"])
        one, two = {"x": -123.5, "y": 89}, {"x": 0, "y": -2}
        send = {"client_id": tab1, "cursor": one}
        self.assertEqual((await self.owner.post(endpoint, json=send)).status_code, 409)
        self.assertEqual((await self.editor.post(endpoint, json=send)).status_code, 204)
        self.assertEqual(await self.peers(owner), [{**peer, "cursor": one}])
        another = await self.open_board_tab(path, self.editor, tab2)
        self.assertEqual([p["name"] for p in await self.peers(another)], ["owner"])
        self.assertEqual((await self.editor.post(endpoint, json={"client_id": tab2, "cursor": two})).status_code, 204)
        self.assertEqual(await self.peers(owner), [{**peer, "cursor": two}])
        self.assertEqual((await self.editor.post(endpoint, json={"client_id": tab2, "cursor": None})).status_code, 204)
        self.assertEqual(await self.peers(owner), [{**peer, "cursor": one}])
        await another.aclose()
        reopened = await self.open_board_tab(path, self.editor, tab1)
        await self.peers(reopened)
        await editor.aclose()
        self.assertEqual(await self.peers(owner), [peer])
        self.assertEqual((await self.editor.post(endpoint, json=send)).status_code, 204)
        self.assertEqual(await self.peers(owner), [{**peer, "cursor": one}])
        await reopened.aclose()
        self.assertEqual(await self.peers(owner), [])
        await owner.aclose()
        self.assertFalse(self.app.state.board_rooms)
        self.assertEqual((await self.owner.get(path)).json(), project)

    async def test_board_rechecks_session_membership_origin_and_expired_tabs(self):
        await self.register(self.editor, "editor")
        path, _ = await self.create(self.owner)
        tab_id = "d" * 32
        stream_url = path + "/presence/stream?client_id=" + tab_id
        endpoint = path + "/presence/cursor"
        send = {"client_id": tab_id, "cursor": None}
        self.assertEqual((await self.outsider.get(stream_url)).status_code, 401)
        self.assertEqual((await self.editor.get(stream_url)).status_code, 404)
        self.assertEqual((await self.editor.post(endpoint, json=send)).status_code, 404)
        foreign = {"Origin": "https://other.example"}
        self.assertEqual((await self.owner.get(stream_url, headers=foreign)).status_code, 403)
        self.assertEqual((await self.owner.post(endpoint, headers=foreign, json=send)).status_code, 403)
        invalid = {**send, "cursor": {"x": 0, "y": 1e30}}
        self.assertEqual((await self.owner.post(endpoint, json=invalid)).status_code, 422)
        member_id = await self.grant(path)
        editor = await self.open_board_tab(path, self.editor, tab_id)
        self.assertEqual(await self.peers(editor), [])
        self.assertEqual((await self.owner.delete(path + "/members/" + member_id)).status_code, 204)
        with self.assertRaises(StopAsyncIteration):
            await asyncio.wait_for(anext(editor), timeout=1)
        self.assertEqual((await self.editor.post(endpoint, json=send)).status_code, 404)
        await self.grant(path)
        with patch.object(board_presence, "HEARTBEAT_SECONDS", 0.01):
            editor = await self.open_board_tab(path, self.editor, tab_id)
            await self.peers(editor)
            await self.editor.post("/api/auth/logout")
            with self.assertRaises(StopAsyncIteration):
                await asyncio.wait_for(anext(editor), timeout=1)
        owner = await self.open_board_tab(path, self.owner, tab_id)
        self.assertEqual(await self.peers(owner), [])
        with patch.object(board_presence, "monotonic", return_value=board_presence.monotonic() + 40):
            self.assertEqual((await self.owner.post(endpoint, json=send)).status_code, 409)
            fresh = await self.open_board_tab(path, self.owner, "e" * 32)
            self.assertEqual(await self.peers(fresh), [])
            with self.assertRaises(StopAsyncIteration):
                await asyncio.wait_for(anext(owner), timeout=1)
            await fresh.aclose()
        self.assertFalse(self.app.state.board_rooms)


    async def test_lock_has_one_winner_and_only_the_owning_tab_can_use_or_release_it(self):
        path, base = await self.create(self.owner)
        left_id, right_id = "1" * 32, "2" * 32
        left = await self.open_board_tab(path, self.owner, left_id)
        right = await self.open_board_tab(path, self.owner, right_id)
        await self.peers(left)
        await self.peers(right)
        url = path + "/presence/lock"

        async def lock(tab_id, node):
            return await self.owner.post(url, json={"client_id": tab_id, "node_id": node})

        claims = await asyncio.gather(lock(left_id, "start"), lock(right_id, "start"))
        self.assertCountEqual([c.status_code for c in claims], [204, 423])
        self.assertIn("owner", next(c for c in claims if c.status_code == 423).json()["detail"])
        winner, loser = ((left_id, right_id) if claims[0].status_code == 204 else (right_id, left_id))
        streams = {left_id: left, right_id: right}
        for tab_id, stream in streams.items():
            snapshot = json.loads((await anext(stream)).removeprefix("data: "))
            self.assertEqual(snapshot["peers"], [])
            [held] = snapshot["locks"]
            self.assertEqual((held["node_id"], held["name"], held["mine"]), ("start", "owner", tab_id == winner))

        self.assertEqual((await lock(winner, "missing")).status_code, 404)
        self.assertEqual((await lock(loser, None)).status_code, 204)
        graph = deepcopy(base["workflow"])
        graph["nodes"][0]["x"] = 70
        body = {"base_revision": 1, "workflow": graph}
        self.assertEqual((await self.owner.put(path, json={**body, "client_id": loser})).status_code, 423)
        self.assertEqual((await self.owner.put(path, json=body)).status_code, 423)
        self.assertEqual((await self.owner.put(path, json={**body, "client_id": winner})).status_code, 200)
        await streams[winner].aclose()
        graph["nodes"][0]["y"] = 10
        body.update(base_revision=2)
        self.assertEqual((await self.owner.put(path, json={**body, "client_id": winner})).status_code, 423)
        self.assertEqual((await self.owner.put(path, json={**body, "client_id": loser})).status_code, 423)
        self.assertEqual((await lock(loser, "start")).status_code, 204)
        self.assertEqual((await self.owner.put(path, json={**body, "client_id": loser})).status_code, 200)
        self.assertEqual((await lock(loser, None)).status_code, 204)
        self.assertEqual(json.loads((await anext(streams[loser])).removeprefix("data: "))["locks"], [])

    async def test_locked_nodes_and_incident_edges_are_protected_after_merging(self):
        await self.register(self.editor, "editor")
        path, base = await self.create(self.owner)
        await self.grant(path)
        graph = base["workflow"]
        graph["nodes"].extend({"id": ident, "kind": "secrets", "x": 10, "y": 0} for ident in ("scan", "other"))
        graph["edges"].append({"id": "e", "source": "start", "target": "scan"})
        setup = await self.owner.put(path, json={"base_revision": 1, "workflow": graph})
        initial = setup.json()["workflow"]
        owner_id, editor_id = "a" * 32, "b" * 32
        owner_stream = await self.open_board_tab(path, self.owner, owner_id)
        editor_stream = await self.open_board_tab(path, self.editor, editor_id)
        await self.peers(owner_stream)
        await self.peers(editor_stream)
        lock_url = path + "/presence/lock"
        for client, tab, node in [(self.owner, owner_id, "scan"), (self.editor, editor_id, "other")]:
            taken = await client.post(lock_url, json={"client_id": tab, "node_id": node})
            self.assertEqual(taken.status_code, 204, taken.text)

        async def save(client, tab_id, graph, version):
            return await client.put(path, json={"base_revision": version, "workflow": graph, "client_id": tab_id})

        ours, theirs = deepcopy(initial), deepcopy(initial)
        ours["nodes"][1]["x"] = 57
        theirs["nodes"][2]["x"] = 99
        self.assertEqual((await save(self.owner, owner_id, ours, 2)).status_code, 200)
        busy = await self.editor.post(lock_url, json={"client_id": editor_id, "node_id": "scan"})
        self.assertEqual(busy.status_code, 423)
        merged = await save(self.editor, editor_id, theirs, 2)
        self.assertEqual(merged.status_code, 200, merged.text)
        self.assertEqual([n["x"] for n in merged.json()["workflow"]["nodes"]], [0, 57, 99])
        current = merged.json()["workflow"]
        for action in ("edit", "remove", "unlink", "rewire", "connect"):
            attempt = deepcopy(current)
            if action == "edit":
                attempt["nodes"][1]["x"] += 5
            elif action == "remove":
                attempt["nodes"].pop(1)
                attempt["edges"].clear()
            elif action == "unlink":
                attempt["edges"].clear()
            elif action == "rewire":
                attempt["edges"][0]["target"] = "other"
            else:
                attempt["edges"].append({"id": "new", "source": "scan", "target": "other"})
            denied = await save(self.editor, editor_id, attempt, 4)
            self.assertEqual(denied.status_code, 423, (action, denied.text))
        self.assertEqual((await self.owner.get(path)).json()["revision"], 4)
        deleted = deepcopy(current)
        deleted["nodes"].pop(1)
        deleted["edges"].clear()
        self.assertEqual((await save(self.owner, owner_id, deleted, 4)).status_code, 200)
        snapshot = json.loads((await asyncio.wait_for(anext(owner_stream), 1)).removeprefix("data: "))
        self.assertEqual([lock["node_id"] for lock in snapshot["locks"]], ["other"])

    async def test_lock_expires_and_revocation_releases_it(self):
        await self.register(self.editor, "editor")
        path, _ = await self.create(self.owner)
        tab_id = "d" * 32
        body = {"client_id": tab_id, "node_id": "start"}
        url = path + "/presence/lock"
        self.assertEqual((await self.outsider.post(url, json=body)).status_code, 401)
        self.assertEqual((await self.editor.post(url, json=body)).status_code, 404)
        self.assertEqual((await self.owner.post(url, headers={"Origin": "https://other.example"}, json=body)).status_code, 403)
        member = await self.grant(path)
        await self.peers(await self.open_board_tab(path, self.editor, tab_id))
        self.assertEqual((await self.editor.post(url, json=body)).status_code, 204)
        other_path, _ = await self.create(self.owner)
        await self.peers(await self.open_board_tab(other_path, self.owner, tab_id))
        self.assertEqual((await self.owner.post(other_path + "/presence/lock", json=body)).status_code, 204)
        with patch.object(board_presence, "monotonic", return_value=board_presence.monotonic() + 40):
            await self.peers(await self.open_board_tab(path, self.owner, tab_id))
            self.assertEqual((await self.owner.post(url, json=body)).status_code, 204)
            self.assertEqual((await self.editor.post(url, json=body)).status_code, 409)
            self.assertEqual((await self.owner.post(url, json={**body, "node_id": None})).status_code, 204)
            await self.peers(await self.open_board_tab(path, self.editor, tab_id))
            self.assertEqual((await self.editor.post(url, json=body)).status_code, 204)
            await self.owner.delete(path + "/members/" + member)
            self.assertEqual((await self.editor.post(url, json=body)).status_code, 404)
            self.assertEqual((await self.owner.post(url, json=body)).status_code, 204)


    async def test_quiet_board_publishes_expiry_without_cursor_or_heartbeat_event(self):
        await self.register(self.editor, "editor")
        path, _ = await self.create(self.owner)
        await self.grant(path)
        mine, other = "a" * 32, "b" * 32
        owner = await self.open_board_tab(path, self.owner, mine)
        observer = await self.open_board_tab(path, self.editor, other)
        await self.peers(owner)
        await self.peers(observer)
        url = path + "/presence/lock"
        with patch.object(board_presence, "NODE_IDLE_SECONDS", 0.3):
            claim = await self.owner.post(url, json={"node_id": "start", "client_id": mine, "return_lease": True})
            self.assertEqual(claim.status_code, 200)
            snapshot = json.loads((await anext(observer)).removeprefix("data: "))
            held, = snapshot["locks"]
            self.assertEqual(held["lease_id"], claim.json()["lease_id"])
            self.assertLessEqual(held["expires_at"] - snapshot["server_time"], 300)
            self.assertFalse(held["mine"])
            other_activity = {"client_id": other, "node_id": "start", "lease_id": held["lease_id"]}
            self.assertEqual((await self.editor.post(url + "/activity", json=other_activity)).status_code, 423)
            released = json.loads((await asyncio.wait_for(anext(observer), 1)).removeprefix("data: "))
        self.assertEqual(released["locks"], [])
        self.assertEqual([peer["name"] for peer in released["peers"]], ["owner"])
        claim = await self.editor.post(url, json={"node_id": "start", "client_id": other})
        self.assertEqual(claim.status_code, 204)

    async def test_only_node_work_renews_lease_and_old_actions_cannot_touch_next_lease(self):
        path, project = await self.create(self.owner)
        client_id = "a" * 32
        stream = await self.open_board_tab(path, self.owner, client_id)
        url = path + "/presence/lock"
        body = {"client_id": client_id, "node_id": "start"}
        claim = {**body, "return_lease": True, "previous_lease_id": None}
        graph = project["workflow"]

        async def save(revision, lease_id):
            return await self.owner.put(path, json={"client_id": client_id, "lease_id": lease_id,
                                                    "base_revision": revision, "workflow": graph})

        # Simulate a board tab that stays connected longer than its node-editing session.
        with (patch.object(board_presence, "monotonic", return_value=0) as clock,
              patch.object(board_presence, "time", side_effect=lambda: 1000 + clock.return_value)):
            await self.peers(stream)
            first = (await self.owner.post(url, json=claim)).json()["lease_id"]
            activity = {**body, "lease_id": first}
            invalid = await self.owner.post(url + "/activity", json={**activity, "node_id": "other"})
            self.assertEqual(invalid.status_code, 423)
            cross_origin = await self.owner.post(url + "/activity", json=activity, headers={"Origin": "https://other.example"})
            self.assertEqual(cross_origin.status_code, 403)
            clock.return_value = 20
            self.assertEqual((await self.owner.post(url + "/activity", json=activity)).status_code, 204)
            snapshot = json.loads((await anext(stream)).removeprefix("data: "))
            self.assertEqual(snapshot["locks"][0]["expires_at"], 1200000)

            clock.return_value = 25
            graph["nodes"][0]["x"] = 65
            self.assertEqual((await save(1, first)).status_code, 200)
            clock.return_value = 27
            graph["nodes"].append({"id": "scan", "kind": "secrets", "x": 10, "y": 0})
            graph["edges"].append({"id": "edge", "source": "start", "target": "scan"})
            self.assertEqual((await save(2, first)).status_code, 200)
            snapshot = json.loads((await anext(stream)).removeprefix("data: "))
            self.assertEqual(snapshot["locks"][0]["expires_at"], 1207000)

            for second in range(30, 207, 20):
                clock.return_value = second
                cursor = {"client_id": client_id, "cursor": {"x": second, "y": 1}}
                self.assertEqual((await self.owner.post(path + "/presence/cursor", json=cursor)).status_code, 204)
            graph["name"] = "Переименованный проект"
            self.assertEqual((await save(3, first)).status_code, 200)
            self.assertEqual((await save(4, first)).status_code, 200)
            self.assertEqual((await self.owner.post(url, json=body)).status_code, 204)
            clock.return_value = 207
            self.assertEqual((await self.owner.post(url + "/activity", json=activity)).status_code, 423)
            second = (await self.owner.post(url, json=claim)).json()["lease_id"]
            self.assertNotEqual(first, second)
            self.assertEqual((await self.owner.post(url, json=claim)).status_code, 423)
            self.assertEqual((await self.owner.post(url + "/activity", json=activity)).status_code, 423)
            release = {**claim, "node_id": None, "previous_lease_id": first}
            self.assertEqual((await self.owner.post(url, json=release)).status_code, 423)
            graph["nodes"][0]["y"] = 30
            self.assertEqual((await save(4, first)).status_code, 423)
            self.assertEqual((await save(4, second)).status_code, 200)
            release["previous_lease_id"] = second
            self.assertEqual((await self.owner.post(url, json=release)).json(), {"lease_id": None})


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
