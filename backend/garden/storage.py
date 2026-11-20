import sqlite3
from collections.abc import Callable
from pathlib import Path

from garden.models import Run, RunSummary, Workflow


class Store:
    def __init__(self, path: Path, initial: Callable[[], Workflow]):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS workspace (id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS receipts (key TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS templates (id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, started TEXT NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL,
            snapshot TEXT NOT NULL, body TEXT NOT NULL)""")
        if not self.db.execute("SELECT 1 FROM workspace WHERE id=1").fetchone():
            self.db.execute("INSERT INTO workspace VALUES (1, ?)", (initial().model_dump_json(),))
        for (body,) in self.db.execute("SELECT body FROM runs WHERE status='running'").fetchall():
            run = Run.model_validate_json(body)
            run.status = "failed"
            for step in run.steps:
                if step.status in {"pending", "running"}:
                    for review in step.reviews:
                        if review.status == "running":
                            review.status = "failed"
                            review.message = "Сервер остановлен во время прогона"
                    step.status = "failed" if step.status == "running" else "skipped"
                    step.message = "Сервер остановлен во время прогона"
            self.update(run)
        self.db.commit()

    def workflow(self) -> Workflow:
        return Workflow.model_validate_json(self.db.execute("SELECT body FROM workspace WHERE id=1").fetchone()[0])

    def save(self, workflow: Workflow) -> None:
        with self.db:
            self.db.execute("UPDATE workspace SET body=? WHERE id=1", (workflow.model_dump_json(),))

    def insert(self, run: Run, workflow: Workflow) -> None:
        with self.db:
            self.db.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)", (
                run.id, run.started, run.name, run.status, workflow.model_dump_json(), run.model_dump_json()))

    def update(self, run: Run) -> None:
        with self.db:
            self.db.execute("UPDATE runs SET status=?,body=? WHERE id=?", (run.status, run.model_dump_json(), run.id))

    def run(self, key: str) -> Run | None:
        row = self.db.execute("SELECT body FROM runs WHERE id=?", (key,)).fetchone()
        return Run.model_validate_json(row[0]) if row else None

    def recent(self) -> list[RunSummary]:
        rows = self.db.execute("SELECT id,started,name,status FROM runs ORDER BY started DESC LIMIT 30")
        return [RunSummary(id=key, started=started, name=name, status=status) for key, started, name, status in rows]
