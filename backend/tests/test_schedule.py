import asyncio
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import httpx
from apscheduler.events import EVENT_JOB_EXECUTED

from garden.api import app, lifespan
from garden.models import Node, demo


class SchedulePersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_restart_restores_one_job_and_disabling_stops_it(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {"GARDEN_DB": str(Path(temp) / "test.sqlite")}))
        api = await self.enterAsyncContext(httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                                             base_url="http://local"))
        graph = demo()
        minute = (datetime.now(UTC).minute + 30) % 60
        trigger = Node(id="start", kind="schedule", x=0, y=0, enabled=True, cron=f"{minute} * * * *")
        graph.nodes[0] = trigger
        async with lifespan(app):
            for _ in range(2):
                (await api.put("/api/workflow", json=graph.model_dump())).raise_for_status()
            self.assertEqual([job.id for job in app.state.scheduler.get_jobs()], ["start"])

        async with lifespan(app):
            scheduler = app.state.scheduler
            job, = scheduler.get_jobs()
            self.assertEqual(job.id, "start")
            saved_trigger = (await api.get("/api/workflow")).json()["nodes"][0]
            self.assertEqual((saved_trigger["enabled"], saved_trigger["cron"]), (True, trigger.cron))
            executed = asyncio.Event()
            scheduler.add_listener(lambda event: executed.set(), EVENT_JOB_EXECUTED)
            scheduler.modify_job("start", next_run_time=datetime.now(UTC))
            await asyncio.wait_for(executed.wait(), timeout=5)
            await asyncio.gather(*app.state.engine.tasks)
            history = (await api.get("/api/runs")).json()
            self.assertEqual(len(history), 1)
            run = (await api.get("/api/runs/" + history[0]["id"])).json()
            self.assertEqual((run["trigger"], run["status"]), ("start", "succeeded"))

            trigger.enabled = False
            (await api.put("/api/workflow", json=graph.model_dump())).raise_for_status()
            self.assertEqual(scheduler.get_jobs(), [])
            await job.func(*job.args)  # Even an already queued callback must respect the saved switch.
            self.assertEqual((await api.get("/api/runs")).json(), history)
