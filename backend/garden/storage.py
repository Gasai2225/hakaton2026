import sqlite3
from collections.abc import Callable
from pathlib import Path

from garden.models import BrowserReport, BrowserReportNotice, GitEvent, Receipt, Run, RunSummary, Workflow, analysis_status_for


class Store:
    def __init__(self, path: Path, initial: Callable[[], Workflow]):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS workspace (id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS receipts (key TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS outgoing_webhooks (
            run_id TEXT NOT NULL, node_id TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY (run_id, node_id))""")
        self.db.execute("CREATE TABLE IF NOT EXISTS templates (id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, started TEXT NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL,
            snapshot TEXT NOT NULL, body TEXT NOT NULL)""")
        self.db.execute("CREATE TABLE IF NOT EXISTS project_runs (run_id TEXT PRIMARY KEY, project_id TEXT NOT NULL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS runs_by_project ON project_runs(project_id)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS browser_reports (
            run_id TEXT NOT NULL, node_id TEXT NOT NULL, created_at TEXT NOT NULL,
            dismissed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (run_id, node_id))""")
        self.db.execute("CREATE INDEX IF NOT EXISTS browser_reports_pending ON browser_reports(created_at) WHERE dismissed=0")
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
                    if step.status == "skipped":
                        step.skip_reason = "interrupted"
                    step.message = "Сервер остановлен во время прогона"
            run.analysis_status = analysis_status_for(run.steps)
            self.update(run)
        self.db.commit()

    def workflow(self) -> Workflow:
        return Workflow.model_validate_json(self.db.execute("SELECT body FROM workspace WHERE id=1").fetchone()[0])

    def save(self, workflow: Workflow) -> None:
        with self.db:
            self.db.execute("UPDATE workspace SET body=? WHERE id=1", (workflow.model_dump_json(),))

    def insert(self, run: Run, workflow: Workflow, project_id: str | None = None) -> None:
        with self.db:
            self.db.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)", (
                run.id, run.started, run.name, run.status, workflow.model_dump_json(), run.model_dump_json()))
            if project_id is not None:
                self.db.execute("INSERT INTO project_runs VALUES (?, ?)", (run.id, project_id))

    def update(self, run: Run) -> None:
        with self.db:
            self.db.execute("UPDATE runs SET status=?,body=? WHERE id=?", (run.status, run.model_dump_json(), run.id))

    def run(self, key: str) -> Run | None:
        row = self.db.execute("SELECT body FROM runs WHERE id=?", (key,)).fetchone()
        return Run.model_validate_json(row[0]) if row else None

    def record_webhook(self, run_id: str, node_id: str, body: bytes) -> None:
        with self.db:
            self.db.execute("INSERT INTO outgoing_webhooks VALUES (?, ?, ?)", (run_id, node_id, body))

    def record_browser_report(self, payload: Receipt, node_id: str, created_at: str) -> None:
        with self.db:
            self.db.execute("INSERT INTO outgoing_webhooks VALUES (?, ?, ?)",
                            (payload.run_id, node_id, payload.model_dump_json().encode()))
            self.db.execute("INSERT INTO browser_reports(run_id,node_id,created_at) VALUES (?,?,?)",
                            (payload.run_id, node_id, created_at))

    def next_browser_report(self, owner_id: str | None) -> BrowserReportNotice | None:
        row = self.db.execute("""
            SELECT b.run_id,b.node_id,r.name,b.created_at,pr.project_id FROM browser_reports b
            JOIN runs r ON r.id=b.run_id LEFT JOIN project_runs pr ON pr.run_id=b.run_id
            LEFT JOIN projects p ON p.id=pr.project_id
            WHERE b.dismissed=0 AND (p.owner_id=? OR (? IS NULL AND pr.run_id IS NULL))
            ORDER BY b.created_at,b.run_id,b.node_id LIMIT 1
        """, (owner_id, owner_id)).fetchone()
        if row:
            return BrowserReportNotice(run_id=row[0], node_id=row[1], name=row[2], created_at=row[3], project_id=row[4])
        return None

    def browser_report(self, run_id: str, node_id: str) -> BrowserReport | None:
        row = self.db.execute("""
            SELECT r.name,b.created_at,pr.project_id,o.body FROM browser_reports b
            JOIN runs r ON r.id=b.run_id JOIN outgoing_webhooks o USING (run_id,node_id)
            LEFT JOIN project_runs pr ON pr.run_id=b.run_id WHERE b.run_id=? AND b.node_id=?
        """, (run_id, node_id)).fetchone()
        if row:
            return BrowserReport(run_id=run_id, node_id=node_id, name=row[0], created_at=row[1], project_id=row[2],
                                 payload=Receipt.model_validate_json(row[3]))
        return None

    def dismiss_browser_report(self, run_id: str, node_id: str, owner_id: str | None) -> bool:
        with self.db:
            result = self.db.execute("""
                UPDATE browser_reports SET dismissed=1 WHERE run_id=? AND node_id=? AND (
                    EXISTS (SELECT 1 FROM project_runs pr JOIN projects p ON p.id=pr.project_id
                            WHERE pr.run_id=browser_reports.run_id AND p.owner_id=?)
                    OR (? IS NULL AND NOT EXISTS (SELECT 1 FROM project_runs pr WHERE pr.run_id=browser_reports.run_id)))
            """, (run_id, node_id, owner_id, owner_id))
            return bool(result.rowcount)

    def recent(self, project_id: str | None = None) -> list[RunSummary]:
        rows = self.db.execute("""SELECT id, started, name, status, json_extract(body, '$.git_event')
                                  FROM runs LEFT JOIN project_runs ON run_id=id WHERE project_id IS ?
                                  ORDER BY started DESC LIMIT 30""", (project_id,))
        return [RunSummary(id=key, started=started, name=name, status=status,
                           git_event=GitEvent.model_validate_json(event) if event else None)
                for key, started, name, status, event in rows]
