"""Verify the scanner's in-memory inputs against the selected Git commit."""
import os
import posixpath
import subprocess
from collections import defaultdict
from io import BytesIO
from pathlib import Path, PurePosixPath

from garden.gradle_catalog import parent_catalog_references
from garden.models import Source
from garden.scenarios import IGNORED_SOURCE_DIRS, source_file, source_text


def verify_sources(root: Path, sha: str, files: list[Source], *, read_parent_catalog: bool) -> None:
    root = root.resolve()

    def git(*args: str, stdin: bytes | None = None) -> bytes:
        result = subprocess.run(["git", "-C", str(root), "--literal-pathspecs", *args], input=stdin, capture_output=True)
        if result.returncode:
            raise ValueError("Не удалось прочитать выбранный коммит Git")
        return result.stdout

    repo = Path(os.fsdecode(git("rev-parse", "--show-toplevel").rstrip(b"\r\n"))).resolve()
    project = PurePosixPath(root.relative_to(repo).as_posix())
    parents = defaultdict(list)
    if read_parent_catalog:
        for alias, reference in parent_catalog_references(files):
            path = PurePosixPath(posixpath.normpath((project / reference).as_posix()))
            if ".." not in path.parts and not path.is_relative_to(project):
                parents[path].append(alias)

    # ls-tree paths are relative to the checkout root with --full-tree.
    pathspecs = [root, *(repo / path for path in parents)]
    tree = git("ls-tree", "-rlz", "--full-tree", sha, "--", *(str(path) for path in pathspecs))
    expected = {}
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        info, raw_path = entry.split(b"\t", 1)
        mode, _, oid, size = info.split()
        if mode not in {b"100644", b"100755"}:
            continue
        path = PurePosixPath(os.fsdecode(raw_path))
        if path in parents:
            names = parents[path]
        elif path.is_relative_to(project):
            relative = path.relative_to(project)
            if not source_file(relative) or IGNORED_SOURCE_DIRS.intersection(relative.parts[:-1]):
                continue
            names = [relative.as_posix()]
        else:
            continue
        for name in names:
            expected[name] = (oid, int(size))

    current = {file.path: file.text for file in files}
    changed = sorted(expected.keys() ^ current.keys())
    if changed:
        raise ValueError(f"Набор исходников отличается от коммита Git: {changed[0]}")
    if sum(size for _, size in expected.values()) > 5_000_000:
        raise ValueError("Размер исходников коммита Git превышает 5 МБ")
    batch = BytesIO(git("cat-file", "--batch", stdin=b"".join(oid + b"\n" for oid, _ in expected.values())))
    for name, (oid, size) in expected.items():
        if batch.readline().split() != [oid, b"blob", str(size).encode()]:
            raise ValueError("Не удалось прочитать исходники из коммита Git")
        raw = batch.read(size)
        if batch.read(1) != b"\n" or source_text(raw, name) != current[name]:
            raise ValueError(f"Содержимое исходника отличается от коммита Git: {name}")
