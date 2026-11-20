"""Review a narrow cross-file pattern: a web path ID directly selects an owner-bearing row."""

import re

from tree_sitter import Node

from garden.kotlin_checks import kotlin_imports, tokens, walk, words


OWNER = re.compile(r"\b(?:owner|customer|user|tenant|account)_id\b", re.I)
PRE_POST = "org.springframework.security.access.prepost."
EXPRESSION_GUARDS = {PRE_POST + name for name in ("PreAuthorize", "PostAuthorize")}
IDENTITY = {"AuthenticationPrincipal", "Principal", "Authentication", "SecurityContextHolder"}


def child(node: Node, kind: str) -> Node | None:
    return next((c for c in node.named_children if c.type == kind), None)


def names(node: Node | None) -> list[str]:
    return words(node) if node is not None else []


def access_conditions(modifiers: Node | None, imports: dict[str, str]) -> dict[str, bool]:
    """True if that annotation may restrict access beyond a login check."""
    conditions = {}
    for annotation in modifiers.named_children if modifiers else ():
        if annotation.type != "annotation" or not annotation.named_children:
            continue
        entry = annotation.named_children[-1]
        invoked = entry.type == "constructor_invocation"
        name = "".join(words(entry.named_children[0] if invoked else entry))
        path = imports.get(name, name)
        simple = path.rsplit(".", 1)[-1]
        if simple not in {"PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed"}:
            continue
        restricts = True
        if invoked and (path in EXPRESSION_GUARDS or path in {"PreAuthorize", "PostAuthorize"}):
            path = PRE_POST + simple
            args = words(entry.named_children[-1])[1:-1]
            if args[:2] == ["value", "="]:
                args = args[2:]
            restricts = len(args) != 1 or not re.fullmatch(r'"\s*isAuthenticated\s*\(\s*\)\s*"', args[0])
        conditions[path] = restricts
    return conditions


def bean_methods(root: Node, annotation: str):
    imports = {name: path for path, name in kotlin_imports(root) if name != "*"}
    for cls in walk(root, "class_declaration"):
        modifiers = child(cls, "modifiers")
        body = child(cls, "class_body")
        if annotation not in names(modifiers) or body is None:
            continue
        inherited = access_conditions(modifiers, imports)
        for fun in body.named_children:
            if fun.type == "function_declaration":
                # A method overrides the class condition of the same annotation type.
                effective = inherited | access_conditions(child(fun, "modifiers"), imports)
                if not any(effective.values()):
                    yield cls, fun


def parameter_types(node: Node | None) -> dict[str, str]:
    ws = names(node)
    return {ws[i-1]: ws[i+1] for i in range(1, len(ws)-1) if ws[i] == ":"}


def package(root: Node) -> str:
    return "".join(names(child(root, "package_header"))[1:])


def reader_methods(root: Node):
    for cls, fun in bean_methods(root, "Repository"):
        receivers = {key for key, typ in parameter_types(child(cls, "primary_constructor")).items() if typ == "JdbcTemplate"}
        if not receivers:
            continue
        parameters = parameter_types(child(fun, "function_value_parameters"))
        body = child(fun, "function_body")
        if len(parameters) != 1 or body is None or IDENTITY.intersection(words(fun)):
            continue
        parameter = next(iter(parameters))
        for call in walk(body, "call_expression"):
            callee = words(call.named_children[0])
            if len(callee) != 3 or callee[0] not in receivers or callee[1:] not in ([".", "query"], [".", "queryForObject"], [".", "queryForMap"]):
                continue
            args = child(call, "value_arguments")
            values = [words(arg) for arg in args.named_children if arg.type == "value_argument"] if args else []
            if len(values) < 2 or len(values[0]) != 1 or [parameter] not in values[1:]:
                continue
            sql = values[0][0].strip('"').strip()
            match = re.fullmatch(r"select\s+(.+?)\s+from\s+[\w.]+\s+where\s+([\w.]+)\s*=\s*\?\s*;?", sql, re.I | re.S)
            if match and OWNER.search(match[1]) and not OWNER.search(match[2]):
                cls_name = cls.child_by_field_name("name").text.decode()
                yield (package(root), cls_name, fun.child_by_field_name("name").text.decode())


def unscoped_reads(root: Node, readers: set[tuple[str, str, str]]):
    imports = list(kotlin_imports(root))
    explicit = {name: path for path, name in imports if name != "*"}
    packages = {package(root)} | {path[:-2] for path, name in imports if name == "*"}
    for cls, fun in bean_methods(root, "RestController"):
        types = parameter_types(child(cls, "primary_constructor"))
        modifiers = names(child(fun, "modifiers"))
        get_route = "GetMapping" in modifiers or ("RequestMapping" in modifiers and "GET" in modifiers and "method" in modifiers)
        if not get_route:
            continue
        params = child(fun, "function_value_parameters")
        if params is None:
            continue
        path_params = set()
        children = params.named_children
        for annotation, parameter in zip(children, children[1:]):
            if annotation.type == "parameter_modifiers" and parameter.type == "parameter" and "PathVariable" in words(annotation):
                path_params.add(parameter.named_children[0].text.decode())
        if not path_params:
            continue
        body = child(fun, "function_body")
        if body is None:
            continue
        parts = tokens(body)
        ws = [n.text.decode() for n in parts]
        # Only a direct return or a nullable response wrapper. Guards and transformations need human review.
        if ws[:1] == ["="]:
            ws, parts = ws[1:], parts[1:]
        elif ws[:2] == ["{", "return"] and ws[-1:] == ["}"]:
            ws, parts = ws[2:-1], parts[2:-1]
            if ws[-1:] == [";"]:
                ws, parts = ws[:-1], parts[:-1]
        else:
            continue
        if ws[:2] == ["ResponseEntity", "."] and ws[2:4] in (["ofNullable", "("], ["ok", "("]) and ws[-1:] == [")"]:
            ws, parts = ws[4:-1], parts[4:-1]
        if len(ws) != 6 or ws[1] != "." or ws[3] != "(" or ws[4] not in path_params or ws[5] != ")":
            continue
        typ = types.get(ws[0])
        if not typ:
            continue
        candidates = {explicit[typ]} if typ in explicit else {f"{pkg}.{typ}" for pkg in packages}
        if any(m == ws[2] and f"{pkg}.{c}" in candidates for pkg, c, m in readers):
            yield "object-authorization", parts[2]
