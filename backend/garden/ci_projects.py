"""Run the saved workflow on changed practice projects in a GitHub Actions checkout."""
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from garden.ci import run_workflow
from garden.models import GitEvent
from garden.scenarios import IGNORED_SOURCE_DIRS, source_file


PRACTICE = "samples/practice"
ZERO_SHA = "0" * 40


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=repo)


def sha(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("Expected a full commit SHA in the GitHub event")
    return value


def practice_source(path: PurePosixPath) -> bool:
    return (len(path.parts) >= 4 and not IGNORED_SOURCE_DIRS.intersection(path.parts[2:-1])
            and source_file(path))


def projects(repo: Path, event: str, data: dict, head: str) -> list[str]:
    if event == "push" and data.get("deleted"):
        return []
    head = sha(head)
    if git(repo, "rev-parse", "HEAD").decode().strip() != head:
        raise ValueError("The checked-out commit differs from the requested head")
    directories, present = set(), set()
    for entry in git(repo, "ls-tree", "-rtz", head, "--", PRACTICE).split(b"\0"):
        if not entry:
            continue
        info, raw = entry.split(b"\t", 1)
        path = PurePosixPath(os.fsdecode(raw))
        if info.startswith(b"040000 ") and len(path.parts) == 3 and path.name not in IGNORED_SOURCE_DIRS:
            directories.add(path.name)
        elif info.startswith((b"100644 ", b"100755 ")) and practice_source(path):
            present.add(path.parts[2])
    if event == "workflow_dispatch":
        selected = data["inputs"]["project"]
        if selected not in present:
            raise ValueError("Select an existing project under samples/practice")
        return [selected]
    if event == "pull_request":
        pr = data["pull_request"]
        if head != sha(pr["head"]["sha"]):
            raise ValueError("Pull request head does not match the checkout")
        revisions = [sha(pr["base"]["sha"]) + "..." + head]
    elif event == "push":
        if head != sha(data["after"]):
            raise ValueError("Push head does not match the checkout")
        before = sha(data["before"])
        if before == ZERO_SHA:
            default = data["repository"]["default_branch"]
            if data["ref"] == "refs/heads/" + default:
                return sorted(present)
            ancestor = subprocess.run(["git", "merge-base", "refs/remotes/origin/" + default, head],
                                      cwd=repo, capture_output=True)
            if ancestor.returncode:
                print("No common default branch history. Checking every practice project.")
                return sorted(present)
            before = ancestor.stdout.decode().strip()
        if subprocess.run(["git", "cat-file", "-e", before + "^{commit}"], cwd=repo,
                          stderr=subprocess.DEVNULL).returncode:
            print("Previous push commit unavailable. Checking every practice project.")
            return sorted(present)
        revisions = [before, head]
    else:
        raise ValueError("Unsupported GitHub event")
    changed = git(repo, "diff", "--raw", "--no-renames", "-z", *revisions, "--", PRACTICE).split(b"\0")
    touched = set()
    for info, raw in zip(changed[::2], changed[1::2]):
        path = PurePosixPath(os.fsdecode(raw))
        if len(path.parts) >= 4:
            name = path.parts[2]
            touched.add(name)
            # A surviving project that lost its last source must report an incomplete check.
            if info.startswith((b":100644 ", b":100755 ")) and practice_source(path):
                present.add(name)
    return sorted(directories & present & touched)


async def run_projects(repo: Path, names: list[str], reports: Path, *, git_event: GitEvent | None = None,
                       trigger: str | None = None) -> int:
    workflow = repo / "samples/ci-workflow.json"
    if workflow.resolve() != workflow:
        raise ValueError("The saved practice workflow must be a regular file in the checkout")
    status = 0
    for index, name in enumerate(names, 1):
        project = repo / PRACTICE / name
        label = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]
        output = reports / f"{index:03d}-{label}.json"
        print(f"Checking {ascii(name)} -> {output.name}", flush=True)
        try:
            if project.resolve() != project:
                raise ValueError("Project directory must be inside the practice checkout")
            result = await run_workflow(workflow, project, output, trigger, True, read_parent_catalog=False,
                                        git_event=git_event, require_analyzer=True, html_output=output.with_suffix(".html"))
        except ValidationError as error:
            print(error.errors(include_input=False, include_context=False), file=sys.stderr)
            result = 2
        except (OSError, ValueError) as error:
            print(str(error), file=sys.stderr)
            result = 2
        status = max(status, result)
    return status


def main() -> int:
    repo = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    data = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    name = os.environ["GITHUB_EVENT_NAME"]
    head = os.environ["CHECKED_SHA"]
    names = projects(repo, name, data, head)
    if not names:
        print("No changed practice projects with supported source files.")
        return 0
    reports = Path(tempfile.mkdtemp(prefix="garden-workflow-reports-", dir=os.environ["RUNNER_TEMP"]))
    event = GitEvent(name=name, sha=head) if name in {"push", "pull_request"} else None
    trigger = (data["inputs"].get("trigger") or None) if name == "workflow_dispatch" else None
    status = asyncio.run(run_projects(repo, names, reports, git_event=event, trigger=trigger))
    if any(reports.glob("*.json")):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
            print(f"report_dir={reports}", file=stream)
    return status


if __name__ == "__main__":
    sys.exit(main())
