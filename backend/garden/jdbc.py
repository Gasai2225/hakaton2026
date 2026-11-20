"""Track HTTP text through Kotlin values into SQL and JPQL query arguments."""
import re
from typing import NamedTuple

from tree_sitter import Node

from garden.kotlin_checks import kotlin_imports, owner, template_names, walk, words


JDBC_METHODS = frozenset({"query", "queryForList", "queryForMap", "queryForObject", "queryForRowSet", "update", "execute"})
JPA_METHODS = frozenset({"createQuery", "createNativeQuery"})
HTTP_PARAMS = {"RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue"}
SQL_START = re.compile(r"^\s*\|?\s*(?:SELECT|UPDATE|DELETE|INSERT|WITH|MERGE)\b", re.I)


class Value(NamedTuple):
    sql: bool = False
    external: bool = False
    query_methods: frozenset[str] = frozenset()


UNKNOWN = Value()
Helper = tuple[str, Node]
Helpers = dict[tuple[Node, bytes], Helper | None]


def simple_helpers(root: Node) -> Helpers:
    """Index one-argument helpers by lexical scope. Ambiguous names mask outer ones."""
    helpers = {}
    for fun in walk(root, "function_declaration"):
        name = fun.child_by_field_name("name")
        if name is None:
            continue
        key = (fun.parent, name.text)
        duplicate = key in helpers
        helpers[key] = None
        modifiers = next((c for c in fun.named_children if c.type == "modifiers"), None)
        local = fun.parent.type in {"block", "lambda_literal"}
        if duplicate or not (local or (modifiers and "private" in words(modifiers))):
            continue
        if any(c.type != "modifiers" and c.end_byte <= name.start_byte for c in fun.named_children):
            continue  # Extension receivers and type parameters need overload resolution.
        params = next(c for c in fun.named_children if c.type == "function_value_parameters")
        ps = words(params)
        if len(ps) != 5 or ps[2] != ":" or ps[3] not in {"String", "CharSequence"}:
            continue
        body = next((c for c in fun.named_children if c.type == "function_body"), None)
        if not body or not body.named_children:
            continue
        expr = body.named_children[-1]
        if expr.type == "block":
            statements = [c for c in expr.named_children if "comment" not in c.type]
            if len(statements) != 1 or statements[0].type != "return_expression":
                continue
            if not statements[0].named_children:
                continue
            expr = statements[0].named_children[-1]
        helpers[key] = (ps[1], expr)
    return helpers


def visible_helper(callee: Node, helpers: Helpers) -> Helper | None:
    parent = callee.parent
    while parent is not None:
        key = (parent, callee.text)
        if key in helpers:
            return helpers[key]
        if parent.type == "lambda_literal":
            break  # The lambda may introduce a different implicit receiver.
        parent = parent.parent
    return None


def value_of(node: Node, scope: dict[str, Value], helpers: Helpers, depth: int = 0) -> Value:
    if depth > 48:
        return UNKNOWN
    if node.type == "identifier":
        return scope.get(node.text.decode(), UNKNOWN)
    if node.type in {"string_literal", "multiline_string_literal"}:
        literal = node.text.decode().strip('"')
        dynamic = any(scope.get(name, UNKNOWN).external for name in template_names(literal))
        if not dynamic:
            dynamic = any(value_of(c.named_children[0], scope, helpers, depth + 1).external
                          for c in node.named_children if c.type == "interpolation" and c.named_children)
        return Value(bool(SQL_START.match(literal)), dynamic)
    children = node.named_children
    if node.type == "parenthesized_expression" and len(children) == 1:
        return value_of(children[0], scope, helpers, depth + 1)
    if node.type == "binary_expression" and any(c.type == "+" for c in node.children) and len(children) == 2:
        left = value_of(children[0], scope, helpers, depth + 1)
        right = value_of(children[1], scope, helpers, depth + 1)
        return Value(left.sql, left.external or right.external)
    if node.type == "call_expression" and len(children) == 2 and children[1].type == "value_arguments":
        callee, args = children
        parts = callee.named_children
        if len(parts) == 2 and parts[1].text in {b"trim", b"trimIndent", b"trimMargin", b"lowercase", b"uppercase"}:
            return value_of(parts[0], scope, helpers, depth + 1)
        if helpers and callee.type == "identifier" and callee.text.decode() not in scope and len(args.named_children) == 1:
            arg = args.named_children[0]
            helper = visible_helper(callee, helpers)
            if helper and arg.type == "value_argument" and len(arg.named_children) == 1:
                name, expr = helper
                value = value_of(arg.named_children[0], scope, helpers, depth + 1)
                return value_of(expr, {name: value}, {}, depth + 1)
    return UNKNOWN


def body_hits(body: Node, scope: dict[str, Value], helpers: Helpers):
    pending = [(body, scope)]
    while pending:
        node, local = pending.pop()
        children = node.named_children
        if node.type in {"function_declaration", "class_declaration", "object_declaration"}:
            continue
        if node.type in {"block", "lambda_literal"}:
            local = local.copy()
            if node.type == "lambda_literal":
                local.pop("it", None)
                params = next((c for c in children if c.type == "lambda_parameters"), None)
                if params:
                    for decl in walk(params, "variable_declaration"):
                        local.pop(decl.named_children[0].text.decode(), None)
        if node.type == "property_declaration":
            variable = next((c for c in children if c.type == "variable_declaration"), None)
            if variable is not None:
                name = variable.named_children[0].text.decode()
                immutable = any(c.type == "val" for c in node.children)
                local[name] = value_of(children[-1], local, helpers) if immutable else UNKNOWN
        if node.type == "call_expression" and children and children[0].type == "navigation_expression":
            callee = children[0].named_children
            args = next((c for c in children if c.type == "value_arguments"), None)
            if (len(callee) == 2 and args and args.named_children
                    and callee[1].text.decode() in value_of(callee[0], local, helpers).query_methods):
                argument = args.named_children[0].named_children[-1]
                value = value_of(argument, local, helpers)
                if value.sql and value.external:
                    yield "sql-injection", argument
        pending.extend((child, local) for child in reversed(children))


def unsafe_sql(root: Node):
    imported = {}
    mvc = "org.springframework.web.bind.annotation"
    http_params = HTTP_PARAMS | {f"{mvc}.{name}" for name in HTTP_PARAMS}
    for path, local_name in kotlin_imports(root):
        package, _, name = path.rpartition(".")
        if package == mvc and name in HTTP_PARAMS:
            http_params.add(local_name)
        elif local_name in HTTP_PARAMS:
            http_params.discard(local_name)
        if package in {"jakarta.persistence", "javax.persistence"}:
            types, methods = {"EntityManager"}, JPA_METHODS
        elif package == "org.springframework.jdbc.core":
            types, methods = {"JdbcTemplate", "JdbcOperations"}, JDBC_METHODS
        elif package == "org.springframework.jdbc.core.namedparam":
            types, methods = {"NamedParameterJdbcTemplate", "NamedParameterJdbcOperations"}, JDBC_METHODS
        elif package == "org.springframework.jdbc.core.simple":
            types, methods = {"JdbcClient"}, frozenset({"sql"})
        else:
            continue
        if name == "*":
            imported.update(dict.fromkeys(types, methods))
        elif name in types:
            imported[local_name] = methods
    if not imported:
        return
    helpers = simple_helpers(root)
    for function in walk(root, "function_declaration"):
        cls = owner(function, "class_declaration")
        constructor = next((c for c in cls.named_children if c.type == "primary_constructor"), None) if cls else None
        scope = {}
        if constructor:
            for param in walk(constructor, "class_parameter"):
                ws = words(param)
                if ":" in ws:
                    i = ws.index(":")
                    scope[ws[i - 1]] = Value(query_methods=imported.get(ws[i + 1], frozenset()))
        params = next((c for c in function.named_children if c.type == "function_value_parameters"), None)
        body = next((c for c in function.named_children if c.type == "function_body"), None)
        if params is None or body is None:
            continue
        annotations = set()
        for child in params.named_children:
            if child.type == "parameter_modifiers":
                annotations = set()
                for annotation in walk(child, "annotation"):
                    typ = next(walk(annotation, "user_type"), None)
                    if typ is not None:
                        annotations.add("".join(words(typ)))
            elif child.type == "parameter":
                ws = words(child)
                name, typ = ws[0], ws[ws.index(":") + 1]
                scope[name] = Value(external=bool(annotations & http_params) and typ in {"String", "CharSequence"},
                                    query_methods=imported.get(typ, frozenset()))
                annotations.clear()
        if any(v.external for v in scope.values()):
            yield from body_hits(body, scope, helpers)
