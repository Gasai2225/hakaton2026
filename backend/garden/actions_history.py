import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import Lock, Timer
from time import monotonic

import httpx

from garden.actions_reports import MAX_ARCHIVE_BYTES, read_archive, read_directory


WORKFLOW = ".github/workflows/garden.yml"
ARTIFACT = "saved-workflow-findings"


def configured_repository() -> str | None:
    repo = os.environ.get("GARDEN_GITHUB_REPOSITORY")
    if repo is None:
        try:
            origin = subprocess.check_output(["git", "-C", str(Path(__file__).resolve().parents[2]),
                                              "remote", "get-url", "origin"], stderr=subprocess.DEVNULL,
                                             timeout=3, text=True).strip()
        except (OSError, subprocess.SubprocessError, UnicodeError):
            return None
        match = re.fullmatch(r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([^/]+/[^/]+)/?", origin, re.I)
        repo = match[1].removesuffix(".git") if match else ""
    repo = repo.strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", repo) and repo.split("/")[1] not in {".", ".."}:
        return repo
    return None


def save_cache(path: Path, data: bytes) -> None:
    temp_path = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(dir=path.parent, delete=False) as temp:
            temp_path = Path(temp.name)
            temp.write(data)
        temp_path.replace(path)
    except OSError:
        pass  # Read-only deployments still serve the live response.
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)


class ActionsHistory:
    def __init__(self, reports_dir: Path):
        self.repository = configured_repository()
        self.reports_dir = reports_dir.resolve()
        self.cache = self.reports_dir / ("github-actions-" + (self.repository or "").lower().replace("/", "_"))
        self.lock = Lock()
        self.expires = 0.0
        self.error = None
        try:
            rows = json.loads((self.cache / "history.json").read_bytes())
            self.runs = [self._run(row) for row in rows]
        except (OSError, ValueError, KeyError, TypeError):
            self.runs = []

    def _get(self, path: str, limit: int = 2_000_000) -> bytes:
        endpoint = f"repos/{self.repository}/actions/{path}"
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
        try:
            with httpx.stream("GET", "https://api.github.com/" + endpoint, headers=headers,
                              timeout=6, follow_redirects=True) as response:
                response.raise_for_status()
                data = bytearray()
                for chunk in response.iter_bytes(65_536):
                    if len(data) + len(chunk) > limit:
                        raise ValueError("Ответ GitHub превышает допустимый размер.")
                    data.extend(chunk)
                return bytes(data)
        except httpx.HTTPError:
            pass
        # gh uses its own credential store; credentials never enter command arguments or log output.
        try:
            with subprocess.Popen(["gh", "api", "--hostname", "github.com", endpoint], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  env={**os.environ, "GH_TOKEN": token} if token else None) as process:
                deadline = Timer(12, process.kill)
                deadline.start()
                try:
                    payload = process.stdout.read(limit + 1)
                    if len(payload) > limit:
                        raise ValueError("Ответ GitHub превышает допустимый размер.")
                    if process.wait():
                        raise OSError
                    return payload
                finally:
                    deadline.cancel()
                    process.kill()
        except OSError:
            raise ValueError("Не удалось получить данные GitHub. Проверьте подключение и доступ на чтение Actions.") from None

    def _run(self, row: dict) -> dict:
        if row["path"].split("@", 1)[0] != WORKFLOW:
            raise ValueError("Неизвестный сценарий GitHub Actions.")
        run_id, attempt = int(row["id"]), int(row["run_attempt"])
        url = f"https://github.com/{self.repository}/actions/runs/{run_id}"
        return {"id": run_id, "number": int(row["run_number"]), "attempt": attempt, "event": row["event"],
                "sha": row["head_sha"], "branch": row["head_branch"] or "", "started": row["run_started_at"] or row["created_at"],
                "status": row["status"], "conclusion": row["conclusion"], "url": url if attempt == 1 else f"{url}/attempts/{attempt}",
                "updated_at": row["updated_at"]}

    def history(self) -> dict:
        if not self.repository:
            return {"runs": [], "error": "Укажите GARDEN_GITHUB_REPOSITORY в формате владелец/репозиторий."}
        with self.lock:
            if monotonic() >= self.expires:
                try:
                    raw = [row for row in json.loads(self._get("workflows/garden.yml/runs?per_page=30"))["workflow_runs"]
                           if row["event"] in {"push", "pull_request"}]
                    self.runs = [self._run(row) for row in raw]
                    keys = ("path", "id", "run_number", "run_attempt", "event", "head_sha", "head_branch", "run_started_at",
                            "created_at", "updated_at", "status", "conclusion")
                    save_cache(self.cache / "history.json", json.dumps([{k: row[k] for k in keys} for row in raw]).encode())
                    self.error = None
                except (ValueError, KeyError, TypeError):
                    self.error = "Не удалось обновить историю GitHub. Проверьте подключение и доступ на чтение Actions."
                self.expires = monotonic() + 60
            return {"runs": [{k: v for k, v in row.items() if k != "updated_at"} for row in self.runs], "error": self.error}

    def reports(self, run_id: int, attempt: int) -> dict:
        result = {"reports": [], "artifact_url": None, "error": None}
        self.history()
        run = next((item for item in self.runs if item["id"] == run_id and item["attempt"] == attempt), None)
        if not run:
            result["error"] = "Запуск этой версии сценария отсутствует в истории GitHub."
            return result
        archive_path = self.cache / f"{run_id}-{attempt}.zip"
        try:
            legacy = self.reports_dir / f"github-{run_id}"
            if attempt == 1 and legacy.is_dir():
                reports = read_directory(legacy)
                if reports:
                    return {**result, "reports": reports}
            if archive_path.is_file() and archive_path.stat().st_size <= MAX_ARCHIVE_BYTES:
                return {**result, "reports": read_archive(archive_path.read_bytes())}
            if run["status"] != "completed":
                return {**result, "error": "Проверка ещё выполняется. Отчёт появится после её завершения."}
            artifacts = json.loads(self._get(f"runs/{run_id}/artifacts?name={ARTIFACT}&per_page=100"))["artifacts"]
            start = datetime.fromisoformat(run["started"])
            end = datetime.fromisoformat(run["updated_at"])
            matches = [item for item in artifacts if item["name"] == ARTIFACT
                       and start <= datetime.fromisoformat(item["created_at"]) <= end]
            if not matches:
                return {**result, "error": "Для этой попытки нет артефакта с отчётом учебного проекта."}
            if len(matches) != 1:
                raise ValueError("Для этой попытки найдено несколько артефактов с одним именем.")
            artifact = matches[0]
            artifact_id = int(artifact["id"])
            result["artifact_url"] = f"https://github.com/{self.repository}/actions/runs/{run_id}/artifacts/{artifact_id}"
            if artifact["expired"]:
                raise ValueError("Срок хранения артефакта на GitHub истёк.")
            if artifact["size_in_bytes"] > MAX_ARCHIVE_BYTES:
                raise ValueError("Архив отчёта превышает допустимый размер.")
            payload = self._get(f"artifacts/{artifact_id}/zip", MAX_ARCHIVE_BYTES)
            result["reports"] = read_archive(payload)
            save_cache(archive_path, payload)
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            result["error"] = "Не удалось прочитать отчёт GitHub Actions."
        except ValueError as exc:
            result["error"] = str(exc)
        return result
