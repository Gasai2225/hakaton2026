"""Resolve declared and locked Gradle dependencies against offline Maven advisories."""

import json
import os
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache, lru_cache
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, Field, TypeAdapter
from tree_sitter import Node
from univers.maven import Version

from garden.gradle_catalog import SETTINGS, catalog_source
from garden.models import Dependency, LockAdvisory, LockedPackage, LockReport, Model, PackageCheck, Severity, Source
from garden.kotlin_checks import kotlin_imports, owner, plain_literal, walk, words
from garden.properties import property_entries


NUMBER = r"[0-9]+(?:\.[0-9]+)*"
RELEASE = rf"{NUMBER}(?:[.-]?[A-Za-z][A-Za-z0-9]*(?:[.-][A-Za-z0-9]+)*)?"
DATED_SNAPSHOT = re.compile(rf"({NUMBER})-\d{{8}}\.\d{{6}}-\d+")
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
    if match := DATED_SNAPSHOT.fullmatch(value):
        # A unique snapshot artifact's POM still declares its base -SNAPSHOT version.
        value = match[1] + "-SNAPSHOT"
    return Version(re.sub(r"[.-]release$", "", value, flags=re.I))


def supported_version(value: str | None, extended: bool) -> bool:
    if not isinstance(value, str):
        return False
    if not extended:
        return bool(re.fullmatch(NUMBER, value))
    return not value.upper().endswith("-SNAPSHOT") and bool(re.fullmatch(RELEASE, value) or DATED_SNAPSHOT.fullmatch(value))


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
        elif not supported_version(ver, True):
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
    parents = PurePosixPath(build_path).parents
    root = next((p for p in parents if any((p / name).as_posix() in by_path for name in SETTINGS)), PurePosixPath("."))
    for path in dict.fromkeys([(root / "gradle.properties").as_posix(), base + "gradle.properties"]):
        properties.update((name, value) for name, value, _, _ in property_entries(by_path.get(path, "")))
    path = base + "gradle.lockfile"
    for _, package, ver, configs in lock_rows(by_path.get(path, ""), path, []):
        locks.setdefault(package, {}).setdefault(ver, set()).update(configs)
    return properties, locks


def may_reject_version(selected: str | None, rejected: list[str]) -> bool:
    return any(not re.fullmatch(RELEASE, v) or v == selected for v in rejected)


def conflicts_with_strict_version(selector: str, locked: str) -> bool:
    if re.fullmatch(RELEASE, selector):
        return selector != locked
    interval = re.fullmatch(rf"(\[|\(|\])\s*({NUMBER})?\s*,\s*({NUMBER})?\s*(\]|\)|\[)", selector)
    if not interval or not re.fullmatch(NUMBER, locked):
        return False

    # Gradle orders numeric parts individually, including trailing parts.
    def parts(value: str):
        normalized = [part.lstrip("0") for part in value.split(".")]
        return tuple((len(part), part) for part in normalized)

    current = parts(locked)
    if interval[2]:
        lower = parts(interval[2])
        if current < lower or (current == lower and interval[1] != "["):
            return True
    if interval[3]:
        upper = parts(interval[3])
        if current > upper or (current == upper and interval[4] != "]"):
            return True
    return False


def version_catalog(catalog: dict, path: str) -> dict[str, list[tuple[str, str | None]]]:
    try:
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
                    selected = ver.get("strictly") or ver.get("require")
                    if ver.get("rejectAll") or may_reject_version(selected, ver.get("reject", [])):
                        ver = None
                    else:
                        ver = selected + "!!" if ver.get("strictly") and isinstance(selected, str) else selected
            if ver is not None and not isinstance(ver, str):
                raise ValueError("Maven version must be a string")
            aliases[name] = [(module, ver)]
        accessors = {"libs." + re.sub(r"[-_]", ".", k): v for k, v in aliases.items()}
        for name, members in catalog.get("bundles", {}).items():
            accessors["libs.bundles." + re.sub(r"[-_]", ".", name)] = [dep for k in members for dep in aliases[k]]
        return accessors
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Некорректный каталог Gradle в {path}") from error


@dataclass(frozen=True)
class CatalogRef:
    accessor: str


@dataclass
class Bindings:
    names: dict[str, str | CatalogRef]
    versions: dict[str, str]

    def copy(self) -> "Bindings":
        return Bindings(self.names.copy(), self.versions)


def catalog_ref(expr: list[str], variables: Bindings) -> CatalogRef | None:
    if expr[-4:] == [".", "get", "(", ")"]:
        expr = expr[:-4]
    if len(expr) == 1:
        value = variables.names.get(expr[0])
        return value if isinstance(value, CatalogRef) else None
    if (expr[:2] == ["libs", "."] and "libs" not in variables.names and len(expr) % 2 == 1
            and all(p == "." for p in expr[1::2]) and all(p.isidentifier() for p in expr[::2])):
        return CatalogRef("".join(expr))
    return None


def provider_string(accessor: str, variables: Bindings) -> str | None:
    if not accessor.endswith(".get()"):
        return None
    receiver = accessor[:-6]
    if receiver.isidentifier():
        ref = variables.names.get(receiver)
        if not isinstance(ref, CatalogRef):
            return None
        receiver = ref.accessor
    elif "libs" in variables.names:
        return None
    if receiver.startswith("libs.versions."):
        return variables.versions.get(receiver, "$" + receiver)
    return None


def string_value(expr: list[str], variables: Bindings) -> str:
    realized = provider_string("".join(expr), variables)
    if realized is not None:
        return realized
    if not expr or len(expr) % 2 == 0 or any(op != "+" for op in expr[1::2]):
        return ""
    def lookup(name: str, fallback: str) -> str:
        value = provider_string(name, variables) or variables.names.get(name)
        return value if isinstance(value, str) else fallback

    values = []
    for term in expr[::2]:
        if term.startswith('"') and term.endswith('"'):
            # An unresolved reference stays visible and fails numeric version validation.
            values.append(re.sub(r"\$(?:\{(\w+|(?:\w+\.)+get\(\))\}|(\w+))",
                                 lambda m: lookup(m[1] or m[2], m[0]), term[1:-1]))
        else:
            values.append(lookup(term, "$" + term))
    return "".join(values)


def declaration_value(expr: list[str], variables: Bindings, props: dict[str, str]) -> str:
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


def coordinates(args: list[list[str]], variables: Bindings):
    if not args:
        return []
    expr = args[0]
    if all(arg[1:2] == ["="] for arg in args):
        named = {arg[0]: string_value(arg[2:], variables) for arg in args}
        if "group" in named and "name" in named:
            # An explicit, unreadable version expression cannot inherit a BOM default.
            ver = (named["version"] or None) if "version" in named else ""
            return [(named["group"] + ":" + named["name"], ver)]
        return []
    # Gradle's classifier and extension select an artifact of the same module.
    notation = re.fullmatch(r"([^:@\s$]+:[^:@\s$]+)(?::([^:@]*))?(?::[^:@\s]+)?(?:@[^:@\s]+)?",
                            string_value(expr, variables))
    return [(notation[1], notation[2] or "")] if notation else []


def bind_property(node: Node, variables: Bindings, props: dict[str, str]) -> None:
    decl = next((c for c in node.named_children if c.type == "variable_declaration"), None)
    if decl is None:
        return
    name = decl.named_children[0].text.decode()
    parts = words(node)
    value: str | CatalogRef = ""
    if any(c.type == "val" for c in node.children):
        if "=" in parts:
            expr = parts[parts.index("=") + 1:]
            value = (provider_string("".join(expr), variables) or catalog_ref(expr, variables)
                     or declaration_value(expr, variables, props))
        elif parts[-2:] == ["by", "project"]:
            value = props.get(name, "")
    variables.names[name] = value or "$" + name


def dependency_handler(expr: list[str], variables: Bindings) -> bool:
    if not expr or expr[0] in variables.names:
        return False
    if expr == ["dependencies"]:
        return True
    if expr[-2:] != [".", "dependencies"]:
        return False
    receiver = expr[:-2]
    return (receiver in (["project"], ["rootProject"], ["buildscript"], ["this"])
            or (receiver[:2] == ["project", "("] and receiver[-1:] == [")"]))


def reachable_children(node: Node):
    children = node.named_children
    if node.type == "if_expression":
        condition = node.child_by_field_name("condition")
        if condition is not None:
            tokens = words(condition)
            while tokens[:1] == ["("] and tokens[-1:] == [")"]:
                tokens = tokens[1:-1]
            if tokens in (["true"], ["false"]):
                branches = [c for c in children if c != condition and "comment" not in c.type]
                return branches[:1] if tokens == ["true"] else branches[1:]
    return children


def scoped_calls(root: Node, props: dict[str, str], versions: dict[str, str]):
    # Gradle's project members take precedence over same-named external properties.
    names = {k: v for k, v in props.items() if k not in {"dependencies", "project", "rootProject", "buildscript", "this"}}
    pending = [(root, Bindings(names, versions), False)]
    while pending:
        node, variables, in_dependencies = pending.pop()
        if node.type in {"lambda_literal", "block", "class_body", "function_declaration"}:
            variables = variables.copy()
        if node.type == "lambda_literal":
            host = owner(node, "call_expression")
            in_dependencies = host is not None and dependency_handler(words(host.named_children[0]), variables)
        if node.type == "property_declaration":
            bind_property(node, variables, props)
        if node.type == "call_expression":
            yield node, variables, in_dependencies
        pending.extend((child, variables, in_dependencies) for child in reversed(reachable_children(node)))


def trailing_block(call: Node) -> Node | None:
    annotated = next((c for c in call.named_children if c.type == "annotated_lambda"), None)
    if annotated is not None:
        return next((c for c in annotated.named_children if c.type == "lambda_literal"), None)
    return None


def variant_library(argument: Node, variables: Bindings) -> CatalogRef | None:
    call = argument.named_children[0]
    block = trailing_block(call)
    if block is None or "variantOf" in variables.names:
        return None
    invocation = words(call.named_children[0])
    if invocation[:4] != ["variantOf", "(", "libs", "."] or invocation[-1:] != [")"]:
        return None
    provider = invocation[2:-1]
    if "(" in provider:  # variantOf requires a provider, not a value unwrapped with get().
        return None
    for statement in block.named_children:
        if "comment" in statement.type:
            continue
        selector = words(statement)
        if (len(selector) != 4 or selector[0] not in {"classifier", "artifactType"} or
                selector[1] != "(" or selector[3] != ")" or not plain_literal(selector[2])):
            return None
    ref = catalog_ref(provider, variables)
    if ref and not ref.accessor.startswith(("libs.bundles.", "libs.plugins.", "libs.versions.")):
        return ref
    return None


def configured_version(call: Node, initial: str, variables: Bindings, props: dict[str, str]) -> str | None:
    # A call with arguments and a trailing lambda is parsed as an outer call
    # whose callee is the original invocation.
    parent = call.parent
    if parent is None or parent.type != "call_expression" or parent.named_children[0] != call:
        return None
    block = trailing_block(parent)
    if block is None:
        return None
    outer = variables.copy()
    selected, strict, _ = initial.partition("!!")
    rejected, configured = False, False
    for statement in block.named_children:
        if statement.type == "property_declaration":
            bind_property(statement, outer, props)
            continue
        if statement.type != "call_expression" or statement.named_children[0].text != b"version":
            if any(words(c.named_children[0])[-1:] == ["version"] for c in walk(statement, "call_expression")):
                return ""
            continue
        constraint = trailing_block(statement)
        if constraint is None:
            return ""
        local = outer.copy()
        for rule in constraint.named_children:
            if "comment" in rule.type:
                continue
            if rule.type == "property_declaration":
                bind_property(rule, local, props)
                continue
            if rule.type != "call_expression":
                return ""
            method = rule.named_children[0].text.decode()
            args = next((c for c in rule.named_children if c.type == "value_arguments"), None)
            if args is None:
                return ""
            values = [declaration_value(words(a), local, props) for a in args.named_children if a.type == "value_argument"]
            configured = True
            if method in {"strictly", "require"} and len(values) == 1:
                selected, strict, rejected = values[0], ("!!" if method == "strictly" else ""), False
            elif method == "prefer" and len(values) == 1:
                rejected = False
            elif method == "reject":
                rejected |= may_reject_version(selected, values)
            elif method == "rejectAll":
                selected, rejected = "", True
            else:
                return ""
    if configured:
        return "" if rejected or not selected else selected + strict
    return None


@cache
def boot_boms() -> dict:
    return json.loads(Path(__file__).with_name("spring-boot-boms.json").read_bytes())


def plugin_catalog(raw: dict, path: str) -> dict[str, tuple[str, str]]:
    try:
        plugins = {}
        for name, spec in raw.get("plugins", {}).items():
            if isinstance(spec, str):
                plugin, ver = spec.split(":")
            else:
                plugin, ver = spec["id"], spec.get("version", "")
                if isinstance(ver, dict) and "ref" in ver:
                    ver = raw["versions"][ver["ref"]]
                if isinstance(ver, dict):
                    ver = ver.get("strictly") or ver.get("require") or ""
            if not isinstance(plugin, str) or not isinstance(ver, str):
                raise ValueError("Gradle plugin coordinates must be strings")
            plugins["libs.plugins." + re.sub(r"[-_]", ".", name)] = plugin, ver
        return plugins
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Некорректный каталог Gradle в {path}") from error


def extra_assignment(item: Node, bindings: Bindings) -> tuple[Node, Node] | None:
    if item.type == "assignment":
        left, right = item.child_by_field_name("left"), item.child_by_field_name("right")
        if left is None or right is None or left.type != "index_expression" or len(left.named_children) != 2:
            return None
        receiver, key = left.named_children
        if not any(c.type == "=" for c in item.children):
            return None
    elif item.type == "call_expression":
        receiver = item.named_children[0]
        if receiver.type != "navigation_expression" or receiver.named_children[-1].text != b"set":
            return None
        receiver = receiver.named_children[0]
        args = next((c for c in item.named_children if c.type == "value_arguments"), None)
        if args is None:
            return None
        values = [c for c in args.named_children if c.type == "value_argument"]
        if len(values) != 2:
            return None
        key, right = values
    else:
        return None
    path = words(receiver)
    if path in (["extra"], ["project", ".", "extra"]) and path[0] not in bindings.names:
        return key, right
    return None


def managed_versions(root: Node, properties: dict[str, str], catalog: dict,
                     catalog_path: str, versions: dict[str, str]) -> dict[str, tuple[str, str]]:
    plugins = {}
    aliases = None
    overrides = properties.copy()
    unknown_key = False
    bindings = Bindings({}, versions)
    for item in root.named_children:
        if item.type == "property_declaration":
            bind_property(item, bindings, properties)
        if assignment := extra_assignment(item, bindings):
            key, value = assignment
            name = declaration_value(words(key), bindings, properties)
            if name and "$" not in name:
                overrides[name] = declaration_value(words(value), bindings, properties)
            else:
                overrides.clear()
                unknown_key = True
        if item.type != "call_expression" or words(item.named_children[0]) != ["plugins"]:
            continue
        block = trailing_block(item)
        if block is None:
            continue
        variables = Bindings(properties.copy(), versions)
        for statement in block.named_children:
            expr = words(statement)
            if expr[:1] == ["val"] and expr[2:3] == ["="]:
                variables.names[expr[1]] = string_value(expr[3:], variables)
            if expr[-2:] == ["apply", "false"] or expr[-4:] == ["apply", "(", "false", ")"]:
                continue
            if expr[:2] == ["alias", "("] and expr[-1:] == [")"]:
                if aliases is None:
                    aliases = plugin_catalog(catalog, catalog_path)
                alias = aliases.get("".join(expr[2:-1]))
                if alias:
                    plugins[alias[0]] = alias[1]
                continue
            if expr[:2] not in (["id", "("], ["kotlin", "("]) or expr[3:4] != [")"]:
                continue
            name = expr[2].strip('"')
            plugin = "org.jetbrains.kotlin." + name if expr[0] == "kotlin" else name
            plugins[plugin] = string_value(expr[5:6], variables) if expr[4:5] == ["version"] else ""
    boot = plugins.get("org.springframework.boot")
    if not boot or "io.spring.dependency-management" not in plugins:
        return {}
    managed = {}
    bom = boot_boms().get(boot, {})
    for package, spec in bom.get("packages", {}).items():
        prop = spec.get("property") or spec.get("importProperty")
        source = "spring-boot-dependencies:" + bom.get("revision", boot)
        if date := bom.get("date"):
            source += f" (снимок {date})"
        pinned = spec.get("revision", spec["version"])
        value = pinned
        if prop == "kotlin.version" and "org.jetbrains.kotlin.jvm" in plugins:
            value, source = plugins["org.jetbrains.kotlin.jvm"], "org.jetbrains.kotlin.jvm"
        if prop in overrides:
            value, source = overrides[prop], prop
            if prop == spec.get("importProperty") and prop != "kotlin.version":
                value = pinned if value == spec["importVersion"] else ""
        elif prop and unknown_key:
            value, source = "", prop
        managed[package] = value, source
    return managed


def declared(root: Node, known: dict[str, list[Entry]], files: list[Source], build_path: str,
             issues: list[str], inventory: list[PackageCheck], extended: bool,
             online_version: Callable[[str, str | None], bool] | None = None):
    props, locked = gradle_inputs(files, build_path)
    catalog = catalog_source(files, build_path)
    catalog_path = catalog.path if catalog else ""
    try:
        raw_catalog = tomllib.loads(catalog.text) if catalog else {}
    except ValueError:
        issues.append(f"Некорректный каталог Gradle в {catalog_path}")
        raw_catalog = {}
    versions = {}
    entries = raw_catalog.get("versions", {})
    if isinstance(entries, dict):
        versions = {"libs.versions." + re.sub(r"[-_]", ".", name): value for name, value in entries.items()
                    if isinstance(value, str)}
    try:
        managed = managed_versions(root, props, raw_catalog, catalog_path, versions)
    except ValueError as error:
        issues.append(str(error))
        managed = {}
    aliases = None
    standard_variant = (b"variantOf" in root.text and not any(name == "variantOf" for _, name in kotlin_imports(root))
                        and not any(name.text == b"variantOf" for declaration in walk(root, "function_declaration")
                                    if (name := declaration.child_by_field_name("name"))))
    for call, variables, in_dependencies in scoped_calls(root, props, versions):
        callee = words(call.named_children[0])
        if not callee or callee[-1] not in SCOPES | {"add"}:
            continue
        if len(callee) == 1:
            if not in_dependencies:
                continue
        elif callee[-2] != "." or not dependency_handler(callee[:-2], variables):
            continue
        arguments = next((c for c in call.named_children if c.type == "value_arguments"), None)
        if not arguments:
            continue
        nodes = [c for c in arguments.named_children if c.type == "value_argument"]
        args = [words(arg) for arg in nodes]
        configuration = callee[-1]
        if configuration == "add":
            if len(args) < 2:
                continue
            configuration = declaration_value(args[0], variables, props)
            if not configuration or "$" in configuration:
                issues.append(f"Не удалось определить конфигурацию Gradle в {build_path}, строка {nodes[0].start_point.row + 1}")
                continue
            args, nodes = args[1:], nodes[1:]
        expr = args[0] if args else []
        if len(expr) > 3 and expr[0] in {"platform", "enforcedPlatform", "testFixtures"} and expr[1] == "(" and expr[-1] == ")":
            args = [expr[2:-1], *args[1:]]
        reference = catalog_ref(args[0], variables) if args else None
        if standard_variant and in_dependencies and expr[:2] == ["variantOf", "("]:
            reference = variant_library(nodes[0], variables)
        if reference is not None:
            if aliases is None:
                try:
                    aliases = version_catalog(raw_catalog, catalog_path)
                except ValueError as error:
                    issues.append(str(error))
                    aliases = {}
            if reference.accessor not in aliases:
                issues.append(f"Не удалось разрешить ссылку libs в {build_path}, строка {nodes[0].start_point.row + 1}")
                continue
            resolved = aliases[reference.accessor]
        else:
            resolved = coordinates(args, variables)
        if not resolved and args and args[0] and args[0][0] not in LOCAL_INPUTS:
            issues.append(f"Не удалось определить Maven-координаты в {build_path}, строка {nodes[0].start_point.row + 1}")
        for package, ver in resolved:
            override = configured_version(call, ver or "", variables, props)
            if override is not None:
                ver = override
            required, strict, _ = (ver or "").partition("!!")
            locks = locked.get(package, {})
            classpaths = CLASSPATHS.get(configuration, set())
            versions = {ver for ver, configs in locks.items()
                        if configuration in configs or classpaths & configs}
            source = "declaration"
            if versions:
                source = "gradle.lockfile"
                ver = next(iter(versions)) if len(versions) == 1 else ""
                if ver and strict and conflicts_with_strict_version(required, ver):
                    ver = ""
            elif strict:
                ver = required
            elif ver == "" and override is None:
                ver, source = managed.get(package, ("", "unknown"))
            supported = supported_version(ver, extended)
            status = "checked" if supported else "unresolved"
            if package not in known:
                status = "outside-catalog"
            inventory.append(PackageCheck(build_path, nodes[0].start_point.row + 1, package, ver or None, source, status))
            if status == "unresolved" and not (online_version and online_version(package, ver)):
                issues.append(f"Не удалось определить поддерживаемую версию {package} для {configuration} "
                              f"в {build_path}, строка {nodes[0].start_point.row + 1}")
            if status != "checked":
                continue
            group, artifact = package.split(":")
            dependency = Dependency(group=group, artifact=artifact, version=ver)
            for entry in known[package]:
                if any(r.contains(ver) for r in entry.ranges):
                    bundle = reference is not None and reference.accessor.startswith("libs.bundles.")
                    yield nodes[0], dependency, entry, bundle


