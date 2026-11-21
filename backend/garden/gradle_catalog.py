"""Locate the libs catalog declared in Gradle settings without evaluating a build."""
import posixpath
import re
from pathlib import Path, PurePosixPath

from garden.models import Source


DEFAULT_CATALOG = "gradle/libs.versions.toml"
ATTACHED_CATALOG = "gradle/imported-libs.versions.toml"
SETTINGS = ("settings.gradle", "settings.gradle.kts")
PARENT_CATALOG = re.compile(r"(?:\.\./)+gradle/libs\.versions\.toml")
TOKEN = re.compile(
    r'//[^\n]*|/\*|"""[\s\S]*?"""'
    r"|'''[\s\S]*?'''|"
    r""""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\w+|[^\s]"""
)


COMMENT_MARK = re.compile(r"/\*|\*/")


def version_catalog_name(name: str) -> bool:
    return name.endswith(".versions.toml") and name != PurePosixPath(ATTACHED_CATALOG).name


def settings_tokens(settings: str, kotlin: bool):
    pos = 0
    while match := TOKEN.search(settings, pos):
        token = match[0]
        pos = match.end()
        if token == "/*":
            depth = 1
            for mark in COMMENT_MARK.finditer(settings, pos):
                if mark[0] == "*/":
                    depth -= 1
                elif kotlin:
                    depth += 1
                if depth == 0:
                    pos = mark.end()
                    break
            else:
                return
        elif not token.startswith("//"):
            yield token


def imported_catalog(settings: str, kotlin: bool = True) -> str | None:
    """None uses Gradle's default, an empty result means unsupported or ambiguous."""
    tokens = list(settings_tokens(settings, kotlin))
    scopes = []
    found = None
    catalog_scope = ["dependencyResolutionManagement", "versionCatalogs", "libs"]
    for i, token in enumerate(tokens):
        if token == "{":
            name = tokens[i - 1] if i else ""
            if i >= 4 and tokens[i - 4:i] in (["create", "(", '"libs"', ")"], ["create", "(", "'libs'", ")"]):
                name = "libs"
            scopes.append(name)
            if name == "libs" and "versionCatalogs" in scopes:
                if found is not None or scopes != catalog_scope:
                    return ""
                # Only accept one unconditional file import. Settings can also programmatically override versions.
                if tokens[i + 1:i + 5] != ["from", "(", "files", "("] or tokens[i + 6:i + 8] != [")", ")"]:
                    return ""
                if tokens[i + 8:i + 9] != ["}"] and tokens[i + 8:i + 10] != [";", "}"]:
                    return ""
                literal = tokens[i + 5]
                if not re.fullmatch(r"""["'][\w./-]+["']""", literal):
                    return ""
                found = literal[1:-1]
                if found.startswith("/") or not version_catalog_name(PurePosixPath(found).name):
                    return ""
        elif token == "}" and scopes:
            scopes.pop()
    return found


def catalog_source(files: list[Source], build_path: str) -> Source | None:
    by_path = {f.path: f for f in files}
    parents = PurePosixPath(build_path).parents
    for directory in parents:
        settings = [by_path[p] for name in SETTINGS if (p := (directory / name).as_posix()) in by_path]
        if settings:
            if len(settings) != 1:
                return None
            reference = imported_catalog(settings[0].text, settings[0].path.endswith(".kts"))
            if reference == "":
                return None
            path = posixpath.normpath((directory / (reference or DEFAULT_CATALOG)).as_posix())
            if path.startswith("../"):
                if reference and PARENT_CATALOG.fullmatch(reference):
                    return by_path.get((directory / ATTACHED_CATALOG).as_posix())
                return None
            return by_path.get(path)
    return next((by_path[p] for directory in parents if (p := (directory / DEFAULT_CATALOG).as_posix()) in by_path), None)


def parent_catalog_references(files: list[Source]):
    settings = [f for f in files if PurePosixPath(f.path).name in SETTINGS]
    paths = {f.path for f in settings}
    for file in settings:
        folder = PurePosixPath(file.path).parent
        if all((folder / name).as_posix() in paths for name in SETTINGS):
            continue
        reference = imported_catalog(file.text, file.path.endswith(".kts"))
        if not reference or not PARENT_CATALOG.fullmatch(reference):
            continue
        yield (folder / ATTACHED_CATALOG).as_posix(), folder / reference


def external_catalogs(root: Path, files: list[Source]):
    """Include an explicitly referenced parent catalog only inside the same checkout."""
    root = root.resolve()
    boundary = next((directory for directory in (root, *root.parents) if (directory / ".git").exists()), None)
    if boundary is None:
        return
    for relative, reference in parent_catalog_references(files):
        target = (root / reference).resolve()
        if target.is_relative_to(root) or not target.is_relative_to(boundary) or not target.is_file():
            continue
        original = Path(posixpath.normpath((root / reference).as_posix()))
        if original == target:
            yield relative, target
