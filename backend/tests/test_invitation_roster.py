import sqlite3
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from fastapi import FastAPI

from garden import accounts, projects


class InvitationRoster(unittest.IsolatedAsyncioTestCase):
    async def test_owner_sees_expiration_rotation_and_acceptance(self):
        app = FastAPI()
        app.include_router(accounts.router)
        app.include_router(projects.router)
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        accounts.init_accounts(db)
        projects.init_projects(db)
        app.state.store = SimpleNamespace(db=db)
        self.enterContext(patch.dict("os.environ", {"GARDEN_SMTP_HOST": "", "GARDEN_PUBLIC_ORIGIN": ""}))
        owner, editor = [await self.enterAsyncContext(httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://localhost")) for _ in range(2)]
        for client, name in ((owner, "owner"), (editor, "editor")):
            created = await client.post("/api/auth/register", json={
                "name": name, "email": name + "@example.org", "password": "roster-test-password"})
            self.assertEqual(created.status_code, 201)
        project = (await owner.post("/api/projects", json={"name": "Example"})).json()["id"]
        path = f"/api/projects/{project}/members"
        email = {"email": "editor@example.org"}
        first = (await owner.post(path, json=email)).json()
        original = (await owner.get(path)).json()[1]
        self.assertEqual((original["status"], original["invite_version"]), ("pending", first["invite_version"]))
        self.assertNotIn("token", original)
        self.assertNotEqual(first["token"], original["invite_version"])

        with db:
            db.execute("UPDATE project_members SET expires_at=unixepoch() WHERE id=?", (first["id"],))
        expired = (await owner.get(path)).json()[1]
        self.assertEqual(expired["status"], "expired")
        self.assertNotIn("invite_version", expired)
        new = (await owner.post(path, json=email)).json()
        self.assertEqual(first["id"], new["id"])
        self.assertNotEqual(first["invite_version"], new["invite_version"])
        self.assertEqual((await owner.get(path)).json()[1]["invite_version"], new["invite_version"])

        accepted = await editor.post("/api/project-invitations/accept", json={"token": new["token"]})
        self.assertEqual(accepted.status_code, 200)
        active = (await owner.get(path)).json()[1]
        self.assertEqual(active["status"], "active")
        self.assertNotIn("invite_version", active)
        await owner.post(path, json={"email": "later@example.org"})
        self.assertTrue(all("invite_version" not in row for row in (await editor.get(path)).json()))
        self.assertEqual((await owner.delete(path + "/" + new["id"])).status_code, 204)
        self.assertEqual((await editor.get(path)).status_code, 404)
