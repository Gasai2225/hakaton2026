"""Trace an HTTP identifier through reachable Kotlin returns to an owner-bearing row."""

import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from tree_sitter import Node

from garden.jdbc_format import static_string
from garden.kotlin_checks import kotlin_imports, walk, words
from garden.kotlin_types import KotlinTypes, package, top_level_names
from garden.ownership_flow import returned_calls
from garden.ownership_types import Hierarchy, SPRING_TYPES


OWNER = re.compile(r"\b(?:owner|customer|user|tenant|account)_id\b", re.I)
PRE_POST = "org.springframework.security.access.prepost."
EXPRESSION_GUARDS = {PRE_POST + name for name in ("PreAuthorize", "PostAuthorize")}
IDENTITY = {"AuthenticationPrincipal", "Principal", "Authentication", "SecurityContextHolder"}
WEB = "org.springframework.web.bind.annotation."
JDBC = "org.springframework.jdbc.core."
CLIENT = JDBC + "simple.JdbcClient"
PLAIN = {JDBC + "JdbcTemplate", JDBC + "JdbcOperations"}
NAMED = {JDBC + "namedparam.NamedParameterJdbc" + kind for kind in ("Template", "Operations")}
PARAM_SOURCE = JDBC + "namedparam.MapSqlParameterSource"
REPOSITORY, SERVICE = ("org.springframework.stereotype." + name for name in ("Repository", "Service"))
RESPONSE = "org.springframework.http.ResponseEntity"
MAP_OF = "kotlin.collections.mapOf"
MAPPINGS = {WEB + name for name in ("GetMapping", "RequestMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping")}
KNOWN = PLAIN | NAMED | {CLIENT, PARAM_SOURCE, MAP_OF, RESPONSE, REPOSITORY, SERVICE} | {
    WEB + name for name in ("RestController", "PathVariable", "RequestParam")} | MAPPINGS
IDENT = r'(?:[A-Za-z_]\w*|"[A-Za-z_]\w*")'
COLUMN = rf'{IDENT}(?:\.{IDENT}){{0,2}}'
PROJECTION = re.compile(rf'({COLUMN})(?:\s+(?:AS\s+)?{IDENT})?', re.I)
LOOKUP = re.compile(
    rf'SELECT\s+(.+?)\s+FROM\s+{COLUMN}(?:\s+(?:AS\s+)?{IDENT})?\s+WHERE\s+'
    rf'({COLUMN})\s*=\s*(\?|:\w+)(?:\s+LIMIT\s+1)?\s*;?', re.I | re.S)


def child(node: Node, kind: str) -> Node | None:
    return next((c for c in node.named_children if c.type == kind), None)


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
            login_or_public = r'"\s*(?:true|permitAll(?:\s*\(\s*\))?|(?:isAuthenticated|isFullyAuthenticated)\s*\(\s*\))\s*"'
            restricts = len(args) != 1 or not re.fullmatch(login_or_public, args[0])
        conditions[path] = restricts
    return conditions


def annotations(modifiers: Node | None, types: KotlinTypes):
    for node in modifiers.named_children if modifiers else ():
        if node.type == "annotation" and (typ := next(walk(node, "user_type"), None)) is not None:
            yield types.resolve("".join(words(typ)), node), node


def fields(cls: Node, types: KotlinTypes, hierarchy: Hierarchy | None = None, runtime: str = "") -> dict:
    constructor = child(cls, "primary_constructor")
    result = {}
    for p in walk(constructor, "class_parameter") if constructor else ():
        name, typ = child(p, "identifier"), child(p, "user_type")
        if name is not None and typ is not None and any(c.type == "val" for c in p.children):
            declared = types.resolve("".join(words(typ)), p)
            result[name.text.decode()] = hierarchy.receiver(declared, p, types, runtime) if hierarchy else declared
    return result


def arguments(call: Node) -> list[Node]:
    args = child(call, "value_arguments")
    return [a for a in args.named_children if a.type == "value_argument"] if args else []


def binds_input(expr: Node, param: str, locals_at_call: dict[str, Node]) -> bool:
    terms = words(expr)
    if terms == [param]:
        return True
    alias = locals_at_call.get(terms[0]) if len(terms) == 1 else None
    return alias is not None and alias.type == "identifier" and alias.text.decode() == param


def row_placeholder(sql: str) -> str | None:
    match = LOOKUP.fullmatch(sql.strip())
    if not match or OWNER.fullmatch(match[2].split(".")[-1].strip('"')):
        return None
    # A column alias, string constant or aggregate mentioning owner_id is not ownership evidence.
    columns = [PROJECTION.fullmatch(item.strip()) for item in match[1].split(",")]
    if all(columns) and any(OWNER.fullmatch(c[1].split(".")[-1].strip('"')) for c in columns):
        return match[3]
    return None


def member(call: Node | None, receivers: dict[str, str], params: set[str]):
    if call is None or call.type != "call_expression":
        return None
    target = call.named_children[0]
    if target.type != "navigation_expression" or len(target.named_children) != 2:
        return None
    receiver, method = target.named_children
    path = words(receiver)
    if len(path) == 3 and path[:2] == ["this", "."]:
        field = path[2]
    elif len(path) == 1 and path[0] not in params:
        field = path[0]
    else:
        return None
    if typ := receivers.get(field):
        return typ, method
    return None


def sql_binding(argument: Node, sql_literals: dict[str, Node]) -> str | None:
    value = argument.named_children[-1]
    literal = sql_literals.get(value.text.decode()) if value.type == "identifier" else value
    if literal is None or literal.type not in {"string_literal", "multiline_string_literal"} or len(literal.text) > 16384:
        return None
    sql = static_string(literal)
    return row_placeholder(sql) if sql else None


def chained_receiver(call: Node | None, method: bytes) -> Node | None:
    if call is not None and call.type == "call_expression" and child(call, "annotated_lambda") is None:
        target = call.named_children[0]
        if (target.type == "navigation_expression" and len(target.named_children) == 2
                and target.named_children[1].text == method):
            return target.named_children[0]
    return None


def client_reads_row(call: Node, receivers: dict[str, str], param: str, sql_literals: dict[str, Node]) -> bool:
    query = chained_receiver(call, b"singleRow")
    if query is None or arguments(call) or arguments(query):
        return False
    binding = chained_receiver(query, b"query")
    statement = chained_receiver(binding, b"param")
    target = member(statement, receivers, {param, *sql_literals})
    if target is None or target[0] != CLIENT or target[1].text != b"sql" or len(arguments(statement)) != 1:
        return False
    placeholder = sql_binding(arguments(statement)[0], sql_literals)
    args = arguments(binding)
    if not args or not binds_input(args[-1], param, sql_literals):
        return False
    if placeholder == "?":
        return len(args) == 1 or (len(args) == 2 and words(args[0]) == ["1"])
    if placeholder and len(args) == 2:
        key = args[0].named_children[-1]
        return key.type == "string_literal" and static_string(key) == placeholder[1:]
    return False


def reads_row(call: Node, receivers: dict[str, str], param: str, types: KotlinTypes, shadowed: set[str],
              sql_literals: dict[str, Node]) -> bool:
    if call.type != "call_expression" or param in sql_literals or IDENTITY.intersection(words(call)):
        return False
    if chained_receiver(call, b"singleRow") is not None:
        return client_reads_row(call, receivers, param, sql_literals)
    target = call.named_children[0]
    if (target.type == "navigation_expression" and target.named_children[-1].text in
            {b"first", b"single", b"firstOrNull", b"singleOrNull"} and not arguments(call)
            and child(call, "annotated_lambda") is None):
        call = target.named_children[0]
    resolved = member(call, receivers, {param, *sql_literals})
    if not resolved:
        return False
    driver, method = resolved
    if driver not in PLAIN | NAMED or method.text not in {b"query", b"queryForObject", b"queryForMap"}:
        return False
    args = arguments(call)
    if len(args) != (2 if method.text == b"queryForMap" else 3):
        return False
    if method.text != b"queryForMap":
        mapper = args[1 if driver in PLAIN else 2].named_children[-1]
        if mapper.type == "lambda_literal":
            parts = [c for c in mapper.named_children if "comment" not in c.type]
            if len(parts) != 2 or parts[0].type != "lambda_parameters" or not parts[0].named_children:
                return False
            row = parts[0].named_children[0].named_children[0].text.decode()
            if (row == "_" or parts[1].type not in {"call_expression", "navigation_expression", "identifier"}
                    or row not in words(parts[1])):
                return False
    placeholder = sql_binding(args[0], sql_literals)
    if not placeholder:
        return False
    if driver in PLAIN:
        return placeholder == "?" and binds_input(args[-1], param, sql_literals)
    binding = args[1].named_children[-1]
    if not placeholder.startswith(":") or binding.type != "call_expression":
        return False
    factory = "".join(words(binding.named_children[0]))
    parts = [a.named_children[-1] for a in arguments(binding)]
    key = placeholder[1:]
    if factory in receivers or factory == param or factory in sql_literals or factory in shadowed:
        return False
    if types.resolve(factory, binding) == PARAM_SOURCE and len(parts) == 2:
        return parts[0].type == "string_literal" and static_string(parts[0]) == key and binds_input(parts[1], param, sql_literals)
    if (types.resolve(factory, binding) == MAP_OF and "to" not in shadowed
            and len(parts) == 1 and parts[0].type == "infix_expression"):
        pair = parts[0].named_children
        return (len(pair) == 3 and pair[0].type == "string_literal" and static_string(pair[0]) == key
                and pair[1].text == b"to" and binds_input(pair[2], param, sql_literals))
    return False


NUMERIC_TYPES = {"kotlin." + name for name in ("Byte", "Short", "Int", "Long", "Float", "Double")}
KOTLIN_TYPES = NUMERIC_TYPES | {"kotlin." + name for name in ("Any", "Boolean", "Char", "CharSequence", "Number", "String")}


@dataclass(frozen=True)
class Parameter:
    name: str
    type_name: str
    nullable: bool

    @classmethod
    def read(cls, node: Node, types: KotlinTypes):
        name = node.named_children[0].text.decode()
        nullable = child(node, "nullable_type")
        typ = child(nullable if nullable is not None else node, "user_type")
        # A generic declaration needs substitution before its arguments can be compared.
        resolved = types.resolve("".join(words(typ)), node) if typ and child(typ, "type_arguments") is None else ""
        return cls(name, resolved, nullable is not None)

    def accepts(self, actual: "Parameter", hierarchy: Hierarchy) -> bool:
        if not self.type_name or not actual.type_name or (actual.nullable and not self.nullable):
            return False
        return (self.type_name in {actual.type_name, "kotlin.Any"}
                or self.type_name == "kotlin.CharSequence" and actual.type_name == "kotlin.String"
                or self.type_name == "kotlin.Number" and actual.type_name in NUMERIC_TYPES
                or hierarchy.is_subtype(actual.type_name, self.type_name))


def forwarded(call: Node, receivers, parameters: set[str], input_name: str, locals_at_call, hierarchy: Hierarchy):
    target = member(call, receivers, parameters | locals_at_call.keys())
    args = arguments(call) if target else []
    if len(args) != 1 or child(call, "annotated_lambda") is not None:
        return None
    arg = args[0].named_children[-1]
    if not binds_input(arg, input_name, locals_at_call):
        return None
    receiver, method = target
    dispatch = hierarchy.target(receiver, method.text.decode())
    if dispatch:
        key, formal_name = dispatch
        if words(args[0]) in ([arg.text.decode()], [formal_name, "=", arg.text.decode()]):
            return key, method
    return None


Method = tuple[str, str]


def project_types(roots):
    packages = {root: package(root) for root in roots}
    local = defaultdict(dict)
    classes = Counter()
    binding_names = {b"mapOf", b"to", b"MapSqlParameterSource"}
    visible_bindings = defaultdict(set)
    file_bindings = defaultdict(set)
    for root, pkg in packages.items():
        for name, private in top_level_names(root):
            if name in binding_names:
                file_bindings[root].add(name.decode())
                if not private:
                    visible_bindings[pkg].add(name.decode())
        for cls in root.named_children:
            if cls.type in {"class_declaration", "object_declaration", "type_alias"}:
                name = cls.child_by_field_name("name")
                if name is not None:
                    short = name.text.decode()
                    full = ".".join(filter(None, (pkg, short)))
                    local[pkg][short] = full
                    classes[full] += 1
    known = KNOWN | KOTLIN_TYPES
    defaults = {path.rpartition(".")[2]: path for path in known}
    types = {root: KotlinTypes(root, known | SPRING_TYPES | classes.keys(), defaults, local[pkg])
             for root, pkg in packages.items()}
    shadows = {}
    for root in types:
        # A user-defined factory or infix operator can change the named parameter map.
        imports = list(kotlin_imports(root))
        shadowed = {f.child_by_field_name("name").text.decode() for f in walk(root, "function_declaration")}
        shadowed.update(file_bindings[root] | visible_bindings[packages[root]])
        for path, alias in imports:
            if alias == "*":
                shadowed.update(visible_bindings[path[:-2]])
            elif alias == "to" and path != "kotlin.to":
                shadowed.add("to")
        shadows[root] = shadowed
    return types, classes, shadows


def reader_methods(hierarchy: Hierarchy, types, shadows) -> dict[Method, Parameter]:
    methods = {}
    links = defaultdict(list)
    for role, runtime, cls, fun in hierarchy.bean_methods({REPOSITORY, SERVICE}):
        params = child(fun, "function_value_parameters")
        parameters = [p for p in params.named_children if p.type == "parameter"] if params else []
        body = child(fun, "function_body")
        if len(parameters) != 1 or body is None:
            continue
        resolver = types[cls.parent]
        param = Parameter.read(parameters[0], resolver)
        key = runtime, fun.child_by_field_name("name").text.decode()
        receivers = fields(cls, resolver, hierarchy if role == SERVICE else None, runtime)
        for call, locals_at_call in returned_calls(body, param.name):
            if role == REPOSITORY:
                if reads_row(call, receivers, param.name, resolver, shadows[cls.parent], locals_at_call):
                    methods[key] = param
                    break
            else:
                link = forwarded(call, receivers, {param.name}, param.name, locals_at_call, hierarchy)
                if link:
                    links[link[0]].append((key, param))
    pending = deque(methods)
    while pending:
        target = pending.popleft()
        for key, param in links[target]:
            if key not in methods and methods[target].accepts(param, hierarchy):
                methods[key] = param
                pending.append(key)
    return methods


def get_mapping(fun: Node, resolver: KotlinTypes) -> bool | None:
    routes = [(kind, node) for kind, node in annotations(child(fun, "modifiers"), resolver) if kind in MAPPINGS]
    if not routes:
        return None
    if len(routes) != 1:
        return False
    kind, node = routes[0]
    return kind == WEB + "GetMapping" or (kind == WEB + "RequestMapping" and {"method", "GET"} <= set(words(node)))


def http_inputs(fun: Node, resolver: KotlinTypes, contracts, types) -> list[Parameter]:
    """Map HTTP annotations on an interface to the implementation's parameter positions."""
    inherited_routes = set()
    positions = set()
    for cls, declaration in contracts:
        contract_types = types[cls.parent]
        mapping = get_mapping(declaration, contract_types)
        if declaration == fun and mapping is False:
            return []
        if mapping is not None:
            inherited_routes.add(mapping)
        params = child(declaration, "function_value_parameters")
        index = 0
        modifiers = None
        for item in params.named_children if params else ():
            if item.type == "parameter_modifiers":
                modifiers = item
            if item.type == "parameter":
                if any(kind in {WEB + "PathVariable", WEB + "RequestParam"} for kind, _ in annotations(modifiers, contract_types)):
                    positions.add(index)
                modifiers = None
                index += 1
    if get_mapping(fun, resolver) is None and inherited_routes != {True}:
        return []
    params = child(fun, "function_value_parameters")
    actual = [p for p in params.named_children if p.type == "parameter"] if params else []
    return [Parameter.read(p, resolver) for i, p in enumerate(actual) if i in positions]


def endpoint_reads(hierarchy, types, methods, runtime, cls, fun):
    resolver = types[cls.parent]
    inputs = http_inputs(fun, resolver, hierarchy.contracts(runtime, fun), types)
    body = child(fun, "function_body")
    if not inputs or body is None:
        return
    params = child(fun, "function_value_parameters")
    parameters = {p.named_children[0].text.decode() for p in params.named_children if p.type == "parameter"}
    receivers = fields(cls, resolver, hierarchy, runtime)

    def unwrap(call, locals_at_call):
        callee = call.named_children[0]
        if callee.type == "navigation_expression" and len(callee.named_children) == 2:
            owner, method = callee.named_children
            name = "".join(words(owner))
            if (method.text in {b"ok", b"ofNullable"} and resolver.resolve(name, call) == RESPONSE
                    and name not in parameters and name not in locals_at_call and name not in receivers
                    and len(arguments(call)) == 1):
                return arguments(call)[0].named_children[-1]
        return None

    for param in inputs:
        seen = set()
        for call, locals_at_call in returned_calls(body, param.name, unwrap=unwrap):
            link = forwarded(call, receivers, parameters, param.name, locals_at_call, hierarchy)
            if link:
                key, location = link
                expected = methods.get(key)
                if key not in seen and expected and expected.accepts(param, hierarchy):
                    seen.add(key)
                    yield location


def ownership_findings(group: dict[str, Node], build: Node | None):
    if not any(OWNER.search(root.text.decode()) for root in group.values()):
        return {}
    types, classes, shadows = project_types(group.values())
    hierarchy = Hierarchy(types, classes, access_conditions, build)
    methods = reader_methods(hierarchy, types, shadows)
    if not methods:
        return {}
    paths = {root: path for path, root in group.items()}
    findings = defaultdict(list)
    for _, runtime, cls, fun in hierarchy.bean_methods({WEB + "RestController"}):
        findings[paths[cls.parent]].extend(("object-authorization", loc) for loc in
                                         endpoint_reads(hierarchy, types, methods, runtime, cls, fun))
    return findings
