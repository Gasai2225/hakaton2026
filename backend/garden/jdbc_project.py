"""Resolve Kotlin SQL helpers within a Gradle module and source set."""
from collections import defaultdict, deque
from pathlib import PurePosixPath
from typing import NamedTuple

from tree_sitter import Node

from garden.jdbc import UNKNOWN, Functions, SqlMethod, calls_with_scope, collapse_forwarders, method_contexts, scoped_functions, sql_argument, value_of
from garden.jdbc_format import static_string
from garden.kotlin_checks import call_arguments, kotlin_imports, owner, walk, words
from garden.kotlin_types import KotlinTypes, package, top_level_names


def compilation(path: str, builds: set[PurePosixPath]) -> tuple[PurePosixPath, str]:
    file = PurePosixPath(path)
    if file.suffix == ".kts":
        return file, "script"
    for folder in file.parents:
        if folder.parent.name == "src" and file.relative_to(folder).parts[0] in {"kotlin", "java"}:
            return folder.parent.parent, folder.name
        if folder in builds:
            return folder, "main"
    return PurePosixPath("."), "main"


def source_groups(roots: dict[str, Node], paths: list[str]):
    builds = {PurePosixPath(p).parent for p in paths if PurePosixPath(p).name in {"build.gradle.kts", "build.gradle"}}
    groups = defaultdict(dict)
    for path, root in roots.items():
        groups[compilation(path, builds)][path] = root
    for (module, _), group in groups.items():
        yield group, roots.get((module / "build.gradle.kts").as_posix())


def gradle_block(node: Node, name: str):
    for call in node.named_children:
        if call.type == "call_expression" and "".join(words(call.named_children[0])) == name:
            lam = next((c for c in call.named_children if c.type == "annotated_lambda"), None)
            if lam:
                yield from (c for c in lam.named_children if c.type == "lambda_literal")


def constructor_names_available(build: Node | None) -> bool:
    if build is None or build.has_error:
        return False
    for block in gradle_block(build, "dependencies"):
        for call in block.named_children:
            if call.type != "call_expression" or call.named_children[0].text not in {b"implementation", b"api", b"runtimeOnly"}:
                continue
            args = call_arguments(call)
            if args == [["kotlin", "(", '"reflect"', ")"]]:
                return True
            if len(args) == 1 and len(args[0]) == 1:
                dep = args[0][0]
                if dep.startswith('"') and dep.endswith('"') and dep[1:-1].split(":")[:2] == ["org.jetbrains.kotlin", "kotlin-reflect"]:
                    return True
    settings = [n for n in walk(build, "identifier") if n.text == b"javaParameters"]
    if len(settings) != 1:
        return False
    blocks = list(gradle_block(build, "kotlin.compilerOptions"))
    for kotlin in gradle_block(build, "kotlin"):
        blocks.extend(gradle_block(kotlin, "compilerOptions"))
    return any(words(call) == ["javaParameters", ".", "set", "(", "true", ")"] for block in blocks for call in block.named_children)


def project_functions(group: dict[str, Node]) -> Functions:
    helpers = Functions()
    packages = {root: package(root) for root in group.values()}
    exports = {}
    local_names = {}
    for root, pkg in packages.items():
        helpers.update(scoped_functions(root))
        local = local_names[root] = set()
        for name, private in top_level_names(root):
            local.add(name)
            helpers.setdefault((root, name), None)
            if not private:
                path = (pkg, name)
                exports[path] = None if path in exports else (root, name)

    links = {}
    for root, pkg in packages.items():
        imports = list(kotlin_imports(root))
        named = {alias.encode(): path for path, alias in imports if alias != "*"}
        stars = {path[:-2] for path, alias in imports if alias == "*"}
        names = set()
        for call in walk(root, "call_expression"):
            callee = call.named_children[0]
            if callee.type in {"identifier", "navigation_expression"} and callee.end_byte - callee.start_byte < 512:
                names.add(callee.text)
        for name in names:
            local = (root, name)
            if b"." in name and name.split(b".", 1)[0] in local_names[root]:
                continue
            if name in local_names[root]:
                if (pkg, name) in exports and exports[pkg, name] is None:
                    helpers[local] = None
                continue
            if b"." in name or name in named:
                path = named.get(name) or name.decode()
                source, _, short = path.rpartition(".")
                candidates = [(source, short.encode())]
            elif (pkg, name) in exports:
                candidates = [(pkg, name)]
            else:
                candidates = [(source, name) for source in stars if (source, name) in exports]
            if len(candidates) == 1 and (target := exports.get(candidates[0])) is not None:
                helpers[local] = None
                links[local] = target
            elif candidates and any(candidate in exports for candidate in candidates):
                helpers[local] = None
    collapse_forwarders(helpers, links)
    return helpers


class CallTarget(NamedTuple):
    function: Node
    parameters: tuple[tuple[str, Node | None], ...]


def call_target(signature: Node, function: Node) -> CallTarget:
    params = next(c for c in signature.named_children if c.type == "function_value_parameters")
    children = [c for c in params.children if "comment" not in c.type]
    parameters = []
    for index, param in enumerate(children):
        if param.type == "parameter":
            default = children[index + 2] if children[index + 1].type == "=" else None
            parameters.append((param.named_children[0].text.decode(), default))
    return CallTarget(function, tuple(parameters))


def argument_values(arguments: list[Node], target: CallTarget, callee: SqlMethod, scope, helpers: Functions):
    if len(arguments) > len(target.parameters):
        return
    supplied = {}
    for index, arg in enumerate(arguments):
        parts = [c for c in arg.named_children if "comment" not in c.type]
        if len(parts) == 1:
            name = target.parameters[index][0]
        elif len(parts) == 2 and parts[0].type == "identifier" and any(c.type == "=" for c in arg.children):
            name = parts[0].text.decode()
        else:
            return
        if name in supplied:
            return
        supplied[name] = value_of(parts[-1], scope, helpers)
    defaults = dict(target.parameters)
    if supplied.keys() - defaults.keys() or any(name not in supplied and expr is None for name, expr in target.parameters):
        return
    bound = {}
    for (name, default), actual in zip(target.parameters, callee.parameters, strict=True):
        value = supplied[name] if name in supplied else value_of(default, bound, helpers)
        bound[name] = value if actual in callee.text_parameters else UNKNOWN
        if bound[name].external:
            yield actual, value


def project_classes(packages: dict[Node, str]):
    classes = {}
    for root, pkg in packages.items():
        for cls in root.named_children:
            if cls.type != "class_declaration":
                continue
            name = cls.child_by_field_name("name")
            if name is None:
                continue
            qualified = ".".join(filter(None, (pkg, name.text.decode())))
            classes[qualified] = cls if qualified not in classes else None
    concrete = {}
    by_package = defaultdict(dict)
    for name, cls in classes.items():
        if cls is None:
            continue
        modifiers = next((c for c in cls.named_children if c.type == "modifiers"), None)
        if modifiers is not None and {"private", "abstract", "open", "sealed", "expect"}.intersection(words(modifiers)):
            continue
        concrete[cls] = name
        pkg, _, simple = name.rpartition(".")
        by_package[pkg][simple] = name
    return concrete, by_package


STEREOTYPES = {"org.springframework.stereotype." + name for name in ("Component", "Service", "Repository")}
CONTEXT = "org.springframework.context.annotation."
BEAN, PRIMARY, PROFILE, CONDITIONAL = (CONTEXT + name for name in ("Bean", "Primary", "Profile", "Conditional"))
FALLBACK = CONTEXT + "Fallback"
PRIORITY = {"jakarta.annotation.Priority", "javax.annotation.Priority"}
CONSUMERS = STEREOTYPES | {CONTEXT + "Configuration", "org.springframework.stereotype.Controller",
                           "org.springframework.web.bind.annotation.RestController"}
QUALIFIER = "org.springframework.beans.factory.annotation.Qualifier"
AUTOWIRED = "org.springframework.beans.factory.annotation.Autowired"
BOOT_CONDITIONS = "org.springframework.boot.autoconfigure.condition.ConditionalOn"
INJECTION_ANNOTATIONS = {AUTOWIRED, QUALIFIER, CONTEXT + "Lazy", "org.springframework.lang.Nullable",
                         "org.jetbrains.annotations.NotNull", "org.jetbrains.annotations.Nullable",
                         "org.jspecify.annotations.Nullable"}


def annotations(declaration: Node, types: KotlinTypes, site: bytes = b"") -> dict[str, Node]:
    found = {}
    modifiers = next((c for c in declaration.named_children if c.type == "modifiers"), None)
    if modifiers:
        for annotation in modifiers.named_children:
            if annotation.type == "annotation":
                target = next((c for c in annotation.named_children if c.type == "use_site_target"), None)
                if target is not None and target.text != site:
                    continue
                name = next(walk(annotation, "user_type"), None)
                if name is not None:
                    found[types.resolve("".join(words(name)), annotation)] = annotation
    return found


def bean_labels(annotation: Node | None, *, factory: bool = False) -> list[str] | None:
    """Read literal names, preserving the distinction between omitted and unknown."""
    if annotation is None:
        return []
    arguments = next(walk(annotation, "value_arguments"), None)
    labels = []
    for arg in arguments.named_children if arguments else ():
        if arg.type != "value_argument":
            continue
        children = [n for n in arg.named_children if "comment" not in n.type]
        if len(children) == 2 and children[0].text not in {b"value", b"name"}:
            if factory:
                continue
            return None
        value = children[-1]
        for item in value.named_children if value.type == "collection_literal" else [value]:
            label = static_string(item) if item.type in {"string_literal", "multiline_string_literal"} else None
            if not label or "${" in label:
                return None
            labels.append(label)
    return labels


def conditional(tags: dict[str, Node]) -> bool:
    return PROFILE in tags or CONDITIONAL in tags or any(name.startswith(BOOT_CONDITIONS) for name in tags)


class Candidate(NamedTuple):
    implementation: str | None
    names: set[str] | None
    qualifiers: set[str] | None
    primary: bool
    conditional: bool
    default: bool
    fallback: bool
    priority: int | None
    unknown_priority: bool


def bean_candidate(implementation, default_name, declaration, tags, conditional_owner=False, default=True):
    names, qualifiers = bean_labels(declaration, factory=BEAN in tags), bean_labels(tags.get(QUALIFIER))
    priority = None
    ranked = PRIORITY.intersection(tags)
    if len(ranked) == 1:
        arg = next(walk(tags[next(iter(ranked))], "value_argument"), None)
        value = "".join(words(arg)).removeprefix("value=") if arg else ""
        if len(value) <= 11 and value.isascii() and value.removeprefix("-").isdigit():
            priority = int(value)
    return Candidate(implementation, set(names or [default_name]) if names is not None else None,
                     set(qualifiers) if qualifiers is not None else None, PRIMARY in tags,
                     conditional(tags) or conditional_owner, default, FALLBACK in tags, priority, bool(ranked) and priority is None)


def select_candidate(candidates: list[Candidate], qualifier: Node | None, injection_name: str, known_name: bool) -> str | None:
    wanted = bean_labels(qualifier)
    if qualifier is not None and (wanted is None or len(wanted) != 1):
        return None
    seen = set()
    for bean in candidates:
        if bean.names is None or seen.intersection(bean.names):
            return None
        seen.update(bean.names)
    if wanted and any(bean.qualifiers is None for bean in candidates):
        return None
    matches = ([b for b in candidates if wanted[0] in b.names or wanted[0] in b.qualifiers] if wanted
               else [b for b in candidates if b.default])
    primary = [b for b in matches if b.primary]
    if primary:
        return primary[0].implementation if len(primary) == 1 and not primary[0].conditional else None
    if any(bean.conditional for bean in matches):
        # A change of active profile may change uniqueness, name matching or priority.
        return None
    if len(matches) == 1:
        return matches[0].implementation
    regular = [bean for bean in matches if not bean.fallback]
    if len(regular) == 1:
        return regular[0].implementation
    for bean in matches:
        if injection_name in bean.names:
            return bean.implementation if known_name else None
    if wanted:
        for bean in matches:
            if wanted[0] in bean.names:
                return bean.implementation
    ranked = [b for b in matches if b.priority is not None]
    if ranked and not any(b.unknown_priority for b in matches):
        minimum = min(b.priority for b in ranked)
        first = [b for b in ranked if b.priority == minimum]
        if len(first) == 1:
            return first[0].implementation
    return None


def port_methods(port: Node, implementation: str, methods):
    dispatch = {}
    members = next((c for c in port.named_children if c.type == "class_body"), None)
    for signature in members.named_children if members else ():
        if signature.type != "function_declaration":
            continue
        name = signature.child_by_field_name("name").text.decode()
        target = methods.get((implementation, name))
        if name in dispatch or target is None:
            dispatch[name] = None
            continue
        modifiers = next((c for c in target.function.named_children if c.type == "modifiers"), None)
        mapped = call_target(signature, target.function)
        dispatch[name] = mapped if len(mapped.parameters) == len(target.parameters) and modifiers and "override" in words(modifiers) else None
    return dispatch


def spring_candidates(ports, concrete, resolvers):
    candidates = defaultdict(list)
    implements = defaultdict(set)
    product_ranks = {}
    for root, types in resolvers.items():
        for decl in walk(root, "class_declaration"):
            bases = next((c for c in decl.named_children if c.type == "delegation_specifiers"), None)
            for spec in bases.named_children if bases else ():
                typ = next(walk(spec, "user_type"), None)
                if typ is None:
                    continue
                port = types.resolve("".join(words(typ)), decl)
                if port in ports:
                    implementation = concrete.get(decl)
                    if implementation:
                        implements[implementation].add(port)
                    tags = annotations(decl, types)
                    if implementation:
                        product_ranks[implementation] = {key: tags[key] for key in PRIORITY.intersection(tags)}
                    for stereotype in STEREOTYPES.intersection(tags):
                        name = decl.child_by_field_name("name").text.decode()
                        default = name if len(name) > 1 and name[1].isupper() and name[0].isupper() else name[:1].lower() + name[1:]
                        candidates[port].append(bean_candidate(implementation, default, tags[stereotype], tags))
    for root, types in resolvers.items():
        for fun in walk(root, "function_declaration"):
            tags = annotations(fun, types)
            if BEAN not in tags:
                continue
            options = {ws[0]: ws[2:] for arg in walk(tags[BEAN], "value_argument")
                       if (ws := words(arg))[1:2] == ["="]}
            autowire = options.get("autowireCandidate", ["true"])
            if autowire == ["false"]:
                continue
            default = options.get("defaultCandidate", ["true"])
            body = next((c for c in fun.named_children if c.type == "function_body"), None)
            call = next((c for c in body.named_children if c.type == "call_expression"), None) if body else None
            implementation = types.resolve("".join(words(call.named_children[0])), call) if call else None
            declared = next((c for c in fun.named_children if c.type in {"user_type", "nullable_type"}), None)
            result = types.resolve("".join(words(declared)).removesuffix("?"), fun) if declared else implementation
            cls = owner(fun, "class_declaration")
            config = annotations(cls, types) if cls else {}
            registered = CONTEXT + "Configuration" in config or not STEREOTYPES.isdisjoint(config)
            tags.update(product_ranks.get(implementation, {}))
            for port in [result] if result in ports else implements.get(result, ()):
                target = implementation if registered and port in implements.get(implementation, ()) else None
                name = fun.child_by_field_name("name").text.decode()
                uncertain = conditional(config) or autowire != ["true"] or default not in (["true"], ["false"])
                candidate = bean_candidate(target, name, tags[BEAN], tags, uncertain, default != ["false"])
                candidates[port].append(candidate if target else candidate._replace(unknown_priority=True))
    return candidates


def link_spring_interfaces(packages, concrete, by_package, methods, build):
    ports = {name: cls for cls, name in concrete.items() if any(c.type == "interface" for c in cls.children)}
    if not ports:
        return
    known = set(concrete.values()) | CONSUMERS | PRIORITY | {BEAN, PRIMARY, QUALIFIER, PROFILE, CONDITIONAL, AUTOWIRED, FALLBACK}
    for root in packages:
        if b"ConditionalOn" in root.text:
            for annotation in walk(root, "annotation"):
                typ = next(walk(annotation, "user_type"), None)
                if typ is not None and typ.text.startswith(b"ConditionalOn"):
                    known.add(BOOT_CONDITIONS + typ.text.decode().removeprefix("ConditionalOn"))
    resolvers = {root: KotlinTypes(root, known, same_package=by_package[pkg]) for root, pkg in packages.items()}
    candidates = spring_candidates(ports, concrete, resolvers)
    targets = {}
    constructor_names = constructor_names_available(build)
    for root, types in resolvers.items():
        for kind in ("class_parameter", "property_declaration"):
            for site in walk(root, kind):
                variable = next((c for c in site.named_children if c.type == "variable_declaration"), None)
                declared = next((c for c in (variable or site).named_children if c.type in {"user_type", "nullable_type"}), None)
                port = types.resolve("".join(words(declared)).removesuffix("?"), site) if declared else ""
                if port not in candidates:
                    continue
                tags = annotations(site, types, b"param:" if kind == "class_parameter" else b"field:")
                # A custom qualifier or value provider can change which instance is injected.
                if tags.keys() - INJECTION_ANNOTATIONS:
                    continue
                if kind == "property_declaration" and AUTOWIRED not in tags:
                    continue
                cls = owner(site, "class_declaration")
                consumer = annotations(cls, types) if cls else {}
                if conditional(consumer) or (len(candidates[port]) > 1 and CONSUMERS.isdisjoint(consumer)):
                    continue
                name = next((c for c in (variable or site).named_children if c.type == "identifier"), None)
                if name is None:
                    continue
                known_name = kind == "property_declaration" or constructor_names
                implementation = select_candidate(candidates[port], tags.get(QUALIFIER), name.text.decode(), known_name)
                if implementation:
                    pair = (port, implementation)
                    if pair not in targets:
                        targets[pair] = port_methods(ports[port], implementation, methods)
                    for name, target in targets[pair].items():
                        methods[site, name] = target


def sql_findings(group: dict[str, Node], build: Node | None = None) -> dict[str, list[tuple[str, Node]]]:
    """Follow request values to database calls, reporting the location of the SQL argument."""
    findings = defaultdict(dict)
    if not any(any(marker in root.text for marker in (b"jdbc", b"persistence", b"r2dbc")) for root in group.values()):
        return {}
    helpers = project_functions(group)
    packages = {root: package(root) for root in group.values()}
    concrete, by_package = project_classes(packages)
    class_names = set(concrete.values())
    methods = {}
    owners = {}
    work = deque()
    for path, root in group.items():
        for fun, cls, method in method_contexts(root, class_names, by_package[packages[root]]):
            owners[fun] = (path, method)
            work.extend((fun, param, False, True) for param in method.sources)
        for cls in root.named_children:
            if cls not in concrete:
                continue
            body = next((c for c in cls.named_children if c.type == "class_body"), None)
            for member in body.named_children if body else ():
                name = member.child_by_field_name("name")
                if member.type != "function_declaration" or name is None:
                    continue
                key = (concrete[cls], name.text.decode())
                modifiers = next((c for c in member.named_children if c.type == "modifiers"), None)
                hidden = modifiers is not None and {"private", "protected", "open", "abstract"}.intersection(words(modifiers))
                methods[key] = call_target(member, member) if key not in methods and not hidden and member in owners else None
    link_spring_interfaces(packages, concrete, by_package, methods, build)

    visited = set()
    while work:
        state = work.popleft()
        if state in visited:
            continue
        visited.add(state)
        fun, param, sql, raw = state
        path, method = owners[fun]
        scope = method.scope.copy()
        scope[param] = scope[param]._replace(external=True, sql=sql, raw_text=raw)
        for receiver, name, args, local in calls_with_scope(method.body, scope, helpers):
            argument = sql_argument(receiver, name, args)
            if argument is not None:
                value = value_of(argument, local, helpers)
                if value.external and (value.sql or value.raw_text):
                    findings[path][argument.start_byte] = ("sql-injection", argument)
            target = methods.get((receiver.injection, name)) or methods.get((receiver.receiver_type, name))
            if target is not None:
                for parameter, value in argument_values(args, target, owners[target.function][1], local, helpers):
                    work.append((target.function, parameter, value.sql, value.raw_text))
    return {p: list(locations.values()) for p, locations in findings.items()}
