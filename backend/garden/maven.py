"""Resolve declared and locked Gradle dependencies against offline Maven advisories."""

import json
import os
import re
import tomllib
from dataclasses import dataclass
from functools import cache, lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, TypeAdapter
from tree_sitter import Node
from univers.maven import Version

from garden.models import Dependency, LockAdvisory, LockedPackage, LockReport, Model, Severity, Source
from garden.kotlin_checks import owner, words
from garden.properties import property_entries


NUMBER = r"[0-9]+(?:\.[0-9]+)*"
RELEASE = rf"{NUMBER}(?:[.-]?[A-Za-z][A-Za-z0-9]*(?:[.-][A-Za-z0-9]+)*)?"
SCOPES = {"implementation", "api", "runtimeOnly", "compileOnly", "testImplementation", "testRuntimeOnly",
          "testCompileOnly", "annotationProcessor", "kapt", "classpath", "developmentOnly", "testAndDevelopmentOnly"}
LOCAL_INPUTS = {"project", "projects", "files", "fileTree", "localGroovy", "gradleApi"}
CLASSPATHS = {
    "api": {"compileClasspath", "runtimeClasspath"},
    "implementation": {"compileClasspath", "runtimeClasspath"},
    "compileOnly": {"compileClasspath"}, "runtimeOnly": {"runtimeClasspath"},
    "testImplementation": {"testCompileClasspath", "testRuntimeClasspath"},
    "testCompileOnly": {"testCompileClasspath"}, "testRuntimeOnly": {"testRuntimeClasspath"},
    "developmentOnly": {"runtimeClasspath"}, "testAndDevelopmentOnly": {"runtimeClasspath", "testRuntimeClasspath"},
}


@lru_cache(maxsize=4096)
def version(value: str) -> Version:
    # Maven also treats a trailing RELEASE qualifier as the unqualified release.
    return Version(re.sub(r"[.-]release$", "", value, flags=re.I))


class Interval(Model):
    lower: str | None = Field(pattern=rf"^{RELEASE}$")
    upper: str = Field(pattern=rf"^{RELEASE}$")
    lowerInclusive: bool
    upperInclusive: bool

    def contains(self, value: str) -> bool:
        current = version(value)
        if self.lower is not None:
            lower = version(self.lower)
            if current < lower or (current == lower and not self.lowerInclusive):
                return False
        upper = version(self.upper)
        return current < upper or (self.upperInclusive and current == upper)


class Entry(BaseModel):
    id: str
    aliases: list[str]
    group: str
    artifact: str
    ranges: list[Interval]
    fixedVersions: list[str]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    @property
    def identifier(self) -> str:
        return next((name for name in self.aliases if name.startswith("CVE-")), self.id)


class Snapshot(BaseModel):
    formatVersion: Literal[1]
    ecosystem: Literal["Maven"]
    versionFormat: Literal["numeric-dot-separated", "numeric-with-milestones", "maven"]
    packages: list[str] = Field(default_factory=list)
    vulnerabilities: list[Entry]


class LegacyEntry(Model):
    package: str
    advisory: str
    introduced: str = Field(pattern=rf"^{NUMBER}$")
    fixed: str = Field(pattern=rf"^{NUMBER}$")
    severity: Severity

    def convert(self) -> Entry:
        group, artifact = self.package.split(":")
        interval = Interval(lower=self.introduced, upper=self.fixed, lowerInclusive=True, upperInclusive=False)
        return Entry(id=self.advisory, aliases=[], group=group, artifact=artifact, ranges=[interval],
                     fixedVersions=[self.fixed], severity=self.severity.upper())


def load_catalog(extended: bool = False) -> dict[str, list[Entry]]:
    custom = os.environ.get("GARDEN_CATALOG")
    names = ["maven-advisories.json"]
    if extended:
        names.extend(["catalog.json", "maven-osv.json", "maven-lock-advisories.json"])
    paths = [Path(custom)] if custom else [Path(__file__).with_name(name) for name in names]
    result: dict[str, list[Entry]] = {}
    try:
        for path in paths:
            raw = json.loads(path.read_bytes())
            if isinstance(raw, list):
                entries = [e.convert() for e in TypeAdapter(list[LegacyEntry]).validate_python(raw)]
            else:
                snapshot = Snapshot.model_validate(raw)
                entries = snapshot.vulnerabilities
                for package in snapshot.packages:
                    result.setdefault(package, [])
            for entry in entries:
                result.setdefault(f"{entry.group}:{entry.artifact}", []).append(entry)
    except (ValueError, OSError) as error:
        raise ValueError("Не удалось прочитать справочник SCA") from error
    return result


def lock_rows(text: str, path: str, issues: list[str]):
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "empty=")):
            continue
        match = re.fullmatch(r"([\w.-]+:[\w.-]+):([^:=\s]+)=([^=\s,]+(?:\s*,\s*[^=\s,]+)*)", line)
        if match:
            yield number, match[1], match[2], [c.strip() for c in match[3].split(",")]
        else:
            issues.append(f"Некорректная запись {path}, строка {number}")


def check_lock(file: Source, direct: set[str], classified: bool, known: dict[str, list[Entry]], report: LockReport):
    report.files.append(file.path)
    unique = {}
    for line, package, ver, configs in lock_rows(file.text, file.path, report.issues):
        if package in direct:
            continue
        key = (package, ver)
        if key in unique:
            previous = unique[key]
            previous.configurations = sorted(set(previous.configurations).union(configs))
            continue
        status = "checked"
        matches = {}
        if package not in known:
            status = "outside-catalog"
        elif not re.fullmatch(RELEASE, ver):
            status = "unresolved"
        else:
            for entry in known[package]:
                if any(r.contains(ver) for r in entry.ranges):
                    matches[entry.identifier] = LockAdvisory(id=entry.identifier, severity=entry.severity.lower())
        unique[key] = LockedPackage(package=package, version=ver, path=file.path, line=line,
                                    configurations=sorted(set(configs)), scope="transitive" if classified else "unclassified",
                                    status=status, advisories=[matches[k] for k in sorted(matches)])
    report.packages.extend(unique.values())


def gradle_inputs(files: list[Source], build_path: str) -> tuple[dict[str, str], dict[str, dict[str, set[str]]]]:
    base = build_path.removesuffix("build.gradle.kts")
    properties = {}
    locks: dict[str, dict[str, set[str]]] = {}
    by_path = {f.path: f.text for f in files}
    for path in dict.fromkeys(["gradle.properties", base + "gradle.properties"]):
        properties.update((name, value) for name, value, _, _ in property_entries(by_path.get(path, "")))
    path = base + "gradle.lockfile"
    for _, package, ver, configs in lock_rows(by_path.get(path, ""), path, []):
        locks.setdefault(package, {}).setdefault(ver, set()).update(configs)
    return properties, locks


def version_catalog(files: list[Source]) -> dict[str, list[tuple[str, str]]]:
    source = next((f for f in files if f.path == "gradle/libs.versions.toml"), None)
    if source is None:
        return {}
    try:
        catalog = tomllib.loads(source.text)
        versions = catalog.get("versions", {})
        aliases = {}
        for name, spec in catalog.get("libraries", {}).items():
            if isinstance(spec, str):
                group, artifact, ver = spec.split(":")
                module = f"{group}:{artifact}"
            else:
                module = spec["module"] if "module" in spec else f"{spec['group']}:{spec['name']}"
                ver = spec.get("version", "")
                if isinstance(ver, dict) and "ref" in ver:
                    ver = versions[ver["ref"]]
                if isinstance(ver, dict):
                    ver = ver.get("strictly") or ver.get("require") or ""
            aliases[name] = [(module, ver)]
        accessors = {"libs." + re.sub(r"[-_]", ".", k): v for k, v in aliases.items()}
        for name, members in catalog.get("bundles", {}).items():
            accessors["libs.bundles." + re.sub(r"[-_]", ".", name)] = [dep for k in members for dep in aliases[k]]
        return accessors
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Некорректный каталог Gradle в {source.path}") from error


def string_value(expr: list[str], variables: dict[str, str]) -> str:
    if not expr or len(expr) % 2 == 0 or any(op != "+" for op in expr[1::2]):
        return ""
    values = []
    for term in expr[::2]:
        if term.startswith('"') and term.endswith('"'):
            # An unresolved reference stays visible and fails numeric version validation.
            values.append(re.sub(r"\$(?:\{(\w+)\}|(\w+))",
                                 lambda m: variables.get(m[1] or m[2], m[0]), term[1:-1]))
        else:
            values.append(variables.get(term, "$" + term))
    return "".join(values)


def declaration_value(expr: list[str], variables: dict[str, str], props: dict[str, str]) -> str:
    if expr[:3] in (["project", ".", "findProperty"], ["project", ".", "property"]):
        if len(expr) < 6 or expr[3] != "(" or expr[5] != ")" or not re.fullmatch(r'"[\w.-]+"', expr[4]):
            return ""
        key, suffix = expr[4][1:-1], expr[6:]
        if suffix in ([], ["as", "String"], ["as?", "String"]):
            return props.get(key, "")
        if expr[2] == "findProperty" and suffix[:3] == ["as?", "String", "?:"]:
            return props.get(key, string_value(suffix[3:], variables))
        return ""
    if expr[:4] != ["providers", ".", "gradleProperty", "("]:
        return string_value(expr, variables)
    if len(expr) < 7 or not re.fullmatch(r'"[\w.-]+"', expr[4]) or expr[5:7] != [")", "."]:
        return ""
    key, accessor = expr[4][1:-1], expr[7:]
    if accessor in (["get", "(", ")"], ["orNull"]):
        return props.get(key, "")
    if accessor[:2] == ["getOrElse", "("] and accessor[-1:] == [")"]:
        fallback = accessor[2:-1]
    elif accessor[:2] == ["orElse", "("] and accessor[-5:] == [")", ".", "get", "(", ")"]:
        fallback = accessor[2:-5]
    else:
        return ""
    if not fallback or any(not (t.startswith('"') or t.isidentifier()) for t in fallback[::2]):
        return ""
    default = string_value(fallback, variables)
    return props.get(key, default) if default else ""


def coordinates(args: list[list[str]], variables: dict[str, str], aliases: dict):
    if not args:
        return []
    expr = args[0]
    if expr[:2] == ["libs", "."]:
        return aliases.get("".join(expr), [])
    if all(arg[1:2] == ["="] for arg in args):
        named = {arg[0]: string_value(arg[2:], variables) for arg in args}
        if "group" in named and "name" in named:
            return [(named["group"] + ":" + named["name"], named.get("version", ""))]
        return []
    value = string_value(expr, variables)
    parts = value.split(":", 2)
    if len(parts) < 2:
        return []
    return [(":".join(parts[:2]), parts[2] if len(parts) == 3 else "")]


def scoped_calls(root: Node, props: dict[str, str]):
    pending = [(root, props.copy())]
    while pending:
        node, variables = pending.pop()
        if node.type in {"lambda_literal", "block", "class_body", "function_declaration"}:
            variables = variables.copy()
        if node.type == "property_declaration":
            names = words(node)
            if "val" in names and "=" in names:
                name = names[names.index("val") + 1]
                expr = names[names.index("=") + 1:]
                variables[name] = declaration_value(expr, variables, props) or "$" + name
        if node.type == "call_expression":
            yield node, variables
        pending.extend((child, variables) for child in reversed(node.named_children))


@dataclass(frozen=True)
class PackageCheck:
    path: str
    line: int
    package: str
    version: str | None
    source: str
    status: Literal["checked", "outside-catalog", "unresolved"]


@cache
def boot_boms() -> dict:
    return json.loads(Path(__file__).with_name("spring-boot-boms.json").read_bytes())


def managed_versions(root: Node, properties: dict[str, str]) -> dict[str, tuple[str, str]]:
    plugins = {}
    overrides = properties.copy()
    for item in root.named_children:
        if item.type in {"assignment", "call_expression"} and item.text.startswith((b"extra", b"project.extra")):
            expr = words(item)
            if expr[:2] == ["project", "."]:
                expr = expr[2:]
            if expr[:2] == ["extra", "["] and expr[3:5] == ["]", "="]:
                overrides[expr[2].strip('"')] = string_value(expr[5:], properties)
            if expr[:4] == ["extra", ".", "set", "("] and expr[5:6] == [","]:
                overrides[expr[4].strip('"')] = string_value(expr[6:-1], properties)
        if item.type != "call_expression" or words(item.named_children[0]) != ["plugins"]:
            continue
        block = next((child for child in item.named_children if child.type == "annotated_lambda"), None)
        if block is None:
            continue
        variables = properties.copy()
        for statement in block.named_children[-1].named_children:
            expr = words(statement)
            if expr[:1] == ["val"] and expr[2:3] == ["="]:
                variables[expr[1]] = string_value(expr[3:], variables)
            if expr[:2] not in (["id", "("], ["kotlin", "("]) or expr[3:4] != [")"]:
                continue
            if expr[-2:] == ["apply", "false"]:
                continue
            name = expr[2].strip('"')
            plugin = "org.jetbrains.kotlin." + name if expr[0] == "kotlin" else name
            plugins[plugin] = string_value(expr[5:6], variables) if expr[4:5] == ["version"] else ""
    boot = plugins.get("org.springframework.boot")
    if not boot or "io.spring.dependency-management" not in plugins:
        return {}
    managed = {}
    for package, spec in boot_boms().get(boot, {}).get("packages", {}).items():
        prop = spec.get("property") or spec.get("importProperty")
        source = f"spring-boot-dependencies:{boot}"
        value = spec["version"]
        if prop == "kotlin.version" and "org.jetbrains.kotlin.jvm" in plugins:
            value, source = plugins["org.jetbrains.kotlin.jvm"], "org.jetbrains.kotlin.jvm"
        if prop in overrides:
            value, source = overrides[prop], prop
            if prop == spec.get("importProperty") and prop != "kotlin.version":
                value = spec["version"] if value == spec["importVersion"] else ""
        managed[package] = value, source
    return managed


def declared(root: Node, known: dict[str, list[Entry]], files: list[Source], build_path: str,
             issues: list[str], inventory: list[PackageCheck], extended: bool):
    props, locked = gradle_inputs(files, build_path)
    managed = managed_versions(root, props)
    aliases = None
    for call, variables in scoped_calls(root, props):
        callee = words(call.named_children[0])
        if not callee or callee[-1] not in SCOPES | {"add"}:
            continue
        if callee[:-1] != ["dependencies", "."]:
            scope = owner(call, "lambda_literal")
            host = owner(scope, "call_expression") if scope else None
            if not host or words(host.named_children[0])[-1:] != ["dependencies"] or len(callee) != 1:
                continue
        arguments = next((c for c in call.named_children if c.type == "value_arguments"), None)
        if not arguments:
            continue
        nodes = [c for c in arguments.named_children if c.type == "value_argument"]
        args = [words(arg) for arg in nodes]
        configuration = callee[-1]
        if configuration == "add":
            if not args or len(args[0]) != 1 or args[0][0].strip('"') not in SCOPES:
                continue
            configuration = args[0][0].strip('"')
            args, nodes = args[1:], nodes[1:]
        expr = args[0] if args else []
        if len(expr) > 3 and expr[0] in {"platform", "enforcedPlatform", "testFixtures"} and expr[1] == "(" and expr[-1] == ")":
            args = [expr[2:-1], *args[1:]]
        if args and args[0][:2] == ["libs", "."] and aliases is None:
            try:
                aliases = version_catalog(files)
            except ValueError as error:
                issues.append(str(error))
                aliases = {}
        if args and args[0][:2] == ["libs", "."] and "".join(args[0]) not in (aliases or {}):
            issues.append(f"Не удалось разрешить ссылку libs в {build_path}, строка {nodes[0].start_point.row + 1}")
            continue
        resolved = coordinates(args, variables, aliases or {})
        if not resolved and args and args[0] and args[0][0] not in LOCAL_INPUTS:
            issues.append(f"Не удалось определить Maven-координаты в {build_path}, строка {nodes[0].start_point.row + 1}")
        for package, ver in resolved:
            locks = locked.get(package, {})
            classpaths = CLASSPATHS.get(configuration, set())
            versions = {ver for ver, configs in locks.items()
                        if configuration in configs or classpaths & configs}
            source = "declaration"
            if versions:
                source = "gradle.lockfile"
                ver = next(iter(versions)) if len(versions) == 1 else ""
            elif not ver:
                ver, source = managed.get(package, ("", "unknown"))
            supported = isinstance(ver, str) and re.fullmatch(RELEASE if extended else NUMBER, ver)
            status = "checked" if supported else "unresolved"
            if package not in known:
                status = "outside-catalog"
            inventory.append(PackageCheck(build_path, nodes[0].start_point.row + 1, package, ver or None, source, status))
            if status == "unresolved":
                issues.append(f"Не удалось определить поддерживаемую версию {package} для {configuration} "
                              f"в {build_path}, строка {nodes[0].start_point.row + 1}")
            if status != "checked":
                continue
            group, artifact = package.split(":")
            dependency = Dependency(group=group, artifact=artifact, version=ver)
            for entry in known[package]:
                if any(r.contains(ver) for r in entry.ranges):
                    yield nodes[0], dependency, entry


