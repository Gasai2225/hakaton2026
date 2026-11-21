"""Track HTTP text through Kotlin values into SQL and JPQL query arguments."""
import re
from functools import cached_property
from typing import NamedTuple

from tree_sitter import Node

from garden.jdbc_format import static_string, text_slots
from garden.kotlin_checks import kotlin_imports, owner, template_names, walk, words
from garden.kotlin_types import KotlinTypes


JDBC_METHODS = frozenset({"query", "queryForList", "queryForMap", "queryForObject", "queryForRowSet", "update", "execute"})
JPA_METHODS = frozenset({"createQuery", "createNativeQuery"})
R2DBC_CLIENT = "org.springframework.r2dbc.core.DatabaseClient"
R2DBC_TEMPLATES = {"org.springframework.data.r2dbc.core.R2dbcEntityTemplate",
                   "org.springframework.data.r2dbc.core.R2dbcEntityOperations"}
HTTP_PARAMS = {"RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue"}
MVC_PARAMS = {name: "org.springframework.web.bind.annotation." + name for name in HTTP_PARAMS}
DATABASE_METHODS = {
    "jakarta.persistence.EntityManager": JPA_METHODS,
    "javax.persistence.EntityManager": JPA_METHODS,
    "org.springframework.jdbc.core.JdbcTemplate": JDBC_METHODS,
    "org.springframework.jdbc.core.JdbcOperations": JDBC_METHODS,
    "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate": JDBC_METHODS,
    "org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations": JDBC_METHODS,
    "org.springframework.jdbc.core.simple.JdbcClient": frozenset({"sql"}),
    R2DBC_CLIENT: frozenset({"sql"}),
}
SQL_START = re.compile(r"^\s*\|?\s*(?:SELECT|UPDATE|DELETE|INSERT|WITH|MERGE)\b", re.I)
STRING_TRANSFORMS = {b"trim", b"trimIndent", b"trimMargin", b"lowercase", b"uppercase"}


class Value(NamedTuple):
    sql: bool = False
    external: bool = False
    query_methods: frozenset[str] = frozenset()
    literal: Node | None = None
    is_locale: bool | None = None
    receiver_type: str = ""
    raw_text: bool = False
    injection: Node | None = None
    boolean: bool | None = None


UNKNOWN = Value()
REACTIVE_CLIENT = Value(query_methods=DATABASE_METHODS[R2DBC_CLIENT], receiver_type=R2DBC_CLIENT)
Helper = tuple[str, Node]
BUILD_STRING = "kotlin.text.buildString"
FORMAT = "kotlin.text.format"
LOCALE = "java.util.Locale"
STRING = "kotlin.String"
Function = Helper | str | None
CHECKS = {"require": "kotlin.require", "check": "kotlin.check"}
COLLECTIONS = {"setOf": "kotlin.collections.setOf", "listOf": "kotlin.collections.listOf"}


class Functions(dict[tuple[Node, bytes], Function]):
    @cached_property
    def without_helpers(self) -> "Functions":
        # Resolve stdlib calls in the final body without recursively expanding arbitrary calls.
        return Functions((key, None if isinstance(target, tuple) else target) for key, target in self.items())


def scoped_functions(root: Node) -> Functions:
    """Index known stdlib names and one-argument helpers, respecting lexical shadowing."""
    defaults = {"buildString": BUILD_STRING, "format": FORMAT, "String": STRING, **CHECKS, **COLLECTIONS}
    helpers = Functions({(root, name.encode()): path for name, path in defaults.items()})
    for path, name in kotlin_imports(root):
        if path == "java.util.*":
            helpers.setdefault((root, b"Locale"), LOCALE)
        elif path == "java.lang.String":
            helpers[root, name.encode()] = STRING
        elif path == LOCALE or path in defaults.values():
            helpers[root, name.encode()] = path
        elif name in {*defaults, "Locale"} or (name in {"append", "appendLine"} and not path.startswith("kotlin.text.")):
            helpers[root, name.encode()] = None
    builtin_names = {name for (_, name) in helpers} | {b"append", b"appendLine"}
    for kind in ("class_declaration", "object_declaration", "type_alias"):
        for item in walk(root, kind):
            name = item.child_by_field_name("name")
            if name and name.text in builtin_names:
                helpers[item.parent, name.text] = None
    for prop in walk(root, "property_declaration"):
        if prop.parent.type in {"class_body", "source_file"}:
            var = next((c for c in prop.named_children if c.type == "variable_declaration"), None)
            if var is not None and var.named_children[0].text in builtin_names:
                helpers[prop.parent, var.named_children[0].text] = None
    for fun in walk(root, "function_declaration"):
        name = fun.child_by_field_name("name")
        if name is None:
            continue
        key = (fun.parent, name.text)
        duplicate = key in helpers and not isinstance(helpers[key], str)
        helpers[key] = None
        modifiers = next((c for c in fun.named_children if c.type == "modifiers"), None)
        local = fun.parent.type in {"block", "lambda_literal"}
        if duplicate or not (local or fun.parent == root or (modifiers and "private" in words(modifiers))):
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


def collapse_forwarders(helpers: Functions, links: dict) -> None:
    """Resolve imported names and wrappers that only forward their argument."""
    for key, helper in helpers.items():
        if not isinstance(helper, tuple) or key[0].type not in {"source_file", "class_body"}:
            continue
        parameter, expr = helper
        if expr.type != "call_expression":
            continue
        parts = [c for c in expr.named_children if "comment" not in c.type]
        if len(parts) != 2 or parts[0].type != "identifier" or parts[1].type != "value_arguments":
            continue
        if words(parts[1]) != ["(", parameter, ")"] or parts[0].text.decode() == parameter:
            continue
        target = (key[0], parts[0].text)
        if isinstance(helpers.get(target), tuple) or target in links:
            links[key] = target
    # Removing visited edges bounds total work and lets us detect cycles without recursion.
    for current in tuple(links):
        if current not in links:
            continue
        path = set()
        while current in links:
            path.add(current)
            current = links.pop(current)
        summary = None if current in path else helpers[current]
        for key in path:
            helpers[key] = summary


def function_key(callee: Node, helpers: Functions, *, cross_lambdas: bool = False) -> tuple[Node, bytes] | None:
    name = callee.text
    parent = callee.parent
    while parent is not None:
        key = (parent, name)
        if key in helpers:
            return key
        if parent.type == "lambda_literal" and not cross_lambdas:
            break  # The lambda may introduce a different implicit receiver.
        parent = parent.parent
    return None


def append_arguments(call: Node, scope: dict[str, Value], helpers: Functions) -> list[Node] | None:
    """Read an append chain back to the implicit builder or an explicit this."""
    parts = []
    while call.type == "call_expression":
        children = [c for c in call.named_children if "comment" not in c.type]
        if len(children) != 2 or children[1].type != "value_arguments":
            return None
        callee, args = children
        method = callee.named_children[-1] if callee.type == "navigation_expression" else callee
        if method.text not in {b"append", b"appendLine"}:
            return None
        arguments = [a for a in args.named_children if a.type == "value_argument"]
        if len(arguments) == 1 and len(arguments[0].named_children) == 1:
            parts.append(arguments[0].named_children[0])
        elif arguments or method.text != b"appendLine":
            return None
        if callee.type == "identifier":
            if method.text.decode() in scope or function_key(method, helpers, cross_lambdas=True) is not None:
                return None
            break
        call = callee.named_children[0]
        if call.type == "this_expression" and call.text == b"this":
            break
    else:
        return None
    parts.reverse()
    return parts


def only_text_calls(expr: Node, methods: set[bytes]) -> bool:
    for call in walk(expr, "call_expression"):
        callee = call.named_children[0]
        if callee.type != "navigation_expression" or callee.named_children[-1].text not in methods:
            return False
    return True


def conditional_appends(statement: Node, scope: dict[str, Value], helpers: Functions) -> list[Node] | None:
    condition = statement.child_by_field_name("condition")
    if condition is None or not only_text_calls(condition, {b"isEmpty", b"isNotEmpty", b"isBlank", b"isNotBlank"}):
        return None
    branches = [c for c in statement.named_children if c != condition and "comment" not in c.type]
    if condition.text == b"true":
        branches = branches[:1]
    elif condition.text == b"false":
        branches = branches[1:]
    pieces = []
    for branch in branches:
        for action in branch.named_children if branch.type == "block" else [branch]:
            if "comment" in action.type:
                continue
            args = append_arguments(action, scope, helpers)
            if args is None:
                return None
            pieces.extend(args)
    return pieces


def build_string_value(callee: Node, lam: Node, scope: dict[str, Value], helpers: Functions, depth: int) -> Value:
    if callee.type == "call_expression":  # buildString(capacity) { ... }
        callee = callee.named_children[0]
    if callee.type == "identifier":
        key = function_key(callee, helpers)
        if callee.text.decode() in scope or key is None or helpers[key] != BUILD_STRING:
            return UNKNOWN
    elif callee.type != "navigation_expression" or words(callee) != ["kotlin", ".", "text", ".", "buildString"]:
        return UNKNOWN

    local = scope.copy()
    sql, external = None, False
    for statement in lam.named_children:
        if "comment" in statement.type:
            continue
        if statement.type == "property_declaration":
            # A local initializer can itself mutate the builder (e.g. val x = clear()).
            var = next((c for c in statement.named_children if c.type == "variable_declaration"), None)
            if var is None or not only_text_calls(statement, STRING_TRANSFORMS):
                return UNKNOWN
            bind_property(statement, local, helpers, depth)
            continue
        if sql and statement.type == "if_expression":
            pieces = conditional_appends(statement, local, helpers)
        else:
            pieces = append_arguments(statement, local, helpers)
        if pieces is None:
            return UNKNOWN  # An unmodelled statement may replace or clear the accumulated text.
        for piece in pieces:
            if not only_text_calls(piece, STRING_TRANSFORMS):
                return UNKNOWN
            if piece.type in {"string_literal", "multiline_string_literal"} and not piece.text.strip(b'"').strip():
                continue
            value = value_of(piece, local, helpers, depth)
            if sql is None:
                sql = value.sql
            external |= value.external
    return Value(bool(sql), external, is_locale=False)


def symbol(node: Node, scope: dict[str, Value], helpers: Functions) -> str | None:
    if node.type == "identifier" and node.text.decode() not in scope:
        key = function_key(node, helpers, cross_lambdas=True)
        target = helpers[key] if key is not None else None
        return target if isinstance(target, str) else None
    if node.type == "navigation_expression" and node.named_children[-1].text in {b"String", b"Locale"}:
        parts = words(node)
        if parts[0] not in scope:
            return "".join(parts)
    return None


def allowed_name(condition: Node, scope: dict[str, Value], helpers: Functions) -> str | None:
    if condition.type != "in_expression" or not any(c.type == "in" for c in condition.children):
        return None
    name, collection = condition.child_by_field_name("left"), condition.child_by_field_name("right")
    if name.type != "identifier" or collection.type != "call_expression":
        return None
    parts = [c for c in collection.named_children if "comment" not in c.type]
    if len(parts) != 2 or symbol(parts[0], scope, helpers) not in COLLECTIONS.values() or parts[1].type != "value_arguments":
        return None
    for arg in parts[1].named_children:
        if "comment" in arg.type:
            continue
        values = [c for c in arg.named_children if "comment" not in c.type]
        if len(values) != 1 or values[0].type not in {"string_literal", "multiline_string_literal"} or static_string(values[0]) is None:
            return None
    return name.text.decode()


def boolean_value(expr: Node, scope: dict[str, Value]) -> bool | None:
    negate = False
    while expr.type == "parenthesized_expression" or (expr.type == "unary_expression" and expr.children[0].type == "!"):
        negate ^= expr.type == "unary_expression"
        expr = next(c for c in expr.named_children if "comment" not in c.type)
    if expr.type != "identifier":
        return None
    value = {b"true": True, b"false": False}.get(expr.text, scope.get(expr.text.decode(), UNKNOWN).boolean)
    return value != negate if value is not None else None


def branch_nodes(node: Node, scope: dict[str, Value], helpers: Functions):
    """Yield reachable tests and result expressions with their local value constraints."""
    if node.type == "when_expression":
        subject = next((c for c in node.named_children if c.type == "when_subject"), None)
        subject_expr = subject.named_children[-1] if subject and subject.named_children else None
        subject_value = boolean_value(subject_expr, scope) if subject_expr is not None else True
        if subject:
            yield subject, scope, False
        for entry in (c for c in node.named_children if c.type == "when_entry"):
            tests = entry.children_by_field_name("condition")
            reachable = not tests
            always = not tests
            for test in tests:
                yield test, scope, False
                value = boolean_value(test, scope)
                if value is None or subject_value is None:
                    reachable = True
                elif value == subject_value:
                    reachable = always = True
                    break
            if not reachable:
                continue
            guard = next((c for c in entry.named_children if c.type == "when_guard"), None)
            if guard:
                yield guard, scope, False
                always = False
            local = scope
            if (subject_expr and subject_expr.type == "identifier" and tests and all(
                    c.type in {"string_literal", "multiline_string_literal"} and static_string(c) is not None for c in tests)):
                local = scope | {subject_expr.text.decode(): UNKNOWN}
            yield next(c for c in reversed(entry.named_children) if "comment" not in c.type), local, True
            if always:
                break
        return
    condition = node.child_by_field_name("condition")
    if condition is None:
        return
    yield condition, scope, False
    known = boolean_value(condition, scope)
    allowed = allowed_name(condition, scope, helpers)
    truth = True
    for child in node.children:
        if child.type == "else":
            truth = False
        elif (child.is_named and child != condition and "comment" not in child.type
              and (known is None or known == truth)):
            yield child, scope | {allowed: UNKNOWN} if allowed and truth else scope, True


def alternative_value(node: Node, scope: dict[str, Value], helpers: Functions, depth: int) -> Value:
    if node.type == "if_expression" and not any(c.type == "else" for c in node.children):
        return UNKNOWN
    values = []
    for branch, local, is_result in branch_nodes(node, scope, helpers):
        if not is_result:
            continue
        if branch.type == "block":
            statements = [c for c in branch.named_children if "comment" not in c.type]
            if len(statements) != 1:
                values.append(UNKNOWN)
                continue
            branch = statements[0]
        values.append(value_of(branch, local, helpers, depth + 1))
    if not values:
        return UNKNOWN
    if all(v == values[0] for v in values):
        return values[0]
    # Keep the SQL prefix and external input correlated when merging complete queries.
    return Value(sql=all(v.sql for v in values) or any(v.sql and v.external for v in values),
                 external=any(v.external for v in values), raw_text=any(v.raw_text for v in values))


def formatted_value(callee: Node, arguments: Node, scope: dict[str, Value], helpers: Functions, depth: int) -> Value:
    receiver, method = callee.named_children
    receiver_class = symbol(receiver, scope, helpers)
    companion = receiver_class in {STRING, "java.lang.String"}
    java_static = receiver_class == "java.lang.String" and method.text == b"format"
    if not java_static and symbol(method, scope, helpers) != FORMAT:
        return UNKNOWN
    template = UNKNOWN if companion else value_of(receiver, scope, helpers, depth)
    if not companion and template.literal is None:
        return Value(template.sql, template.external) if template.external else UNKNOWN
    values = []
    for argument in arguments.named_children:
        if "comment" in argument.type:
            continue
        children = [c for c in argument.named_children if "comment" not in c.type]
        if argument.type != "value_argument" or len(children) != 1 or children[0].type == "spread_expression":
            return UNKNOWN
        values.append(value_of(children[0], scope, helpers, depth))
    if values and values[0].is_locale:
        values = values[1:]
    elif values and not companion and values[0].is_locale is None:
        return UNKNOWN  # The locale overload would shift every substitution by one slot.
    if companion:
        if not values:
            return UNKNOWN
        template, *values = values
    if template.literal is None:
        return Value(template.sql, template.external)
    pattern = static_string(template.literal)
    if pattern is None:
        return Value(template.sql, template.external)
    strings = {i for i, v in enumerate(values) if v.external or v.sql or v.literal is not None}
    used = text_slots(pattern, len(values), strings)
    if used is None:
        return UNKNOWN
    return Value(bool(SQL_START.match(pattern)), any(values[i].external for i in used), is_locale=False)


def value_of(node: Node, scope: dict[str, Value], helpers: Functions, depth: int = 0) -> Value:
    if depth > 48:
        return UNKNOWN
    if node.type == "identifier":
        if node.text in {b"true", b"false"}:
            return Value(boolean=node.text == b"true")
        return scope.get(node.text.decode(), UNKNOWN)
    if node.type == "unary_expression" and node.children[0].type == "!":
        return Value(boolean=boolean_value(node, scope))
    if node.type in {"if_expression", "when_expression"}:
        return alternative_value(node, scope, helpers, depth)
    if node.type == "navigation_expression" and node.named_children[0].type == "this_expression":
        if words(node.named_children[0]) == ["this"]:
            return scope.get("this." + node.named_children[-1].text.decode(), UNKNOWN)
    if node.type == "navigation_expression" and node.named_children[-1].text == b"databaseClient":
        receiver = value_of(node.named_children[0], scope, helpers, depth + 1)
        return REACTIVE_CLIENT if receiver.receiver_type in R2DBC_TEMPLATES else UNKNOWN
    if node.type in {"number_literal", "character_literal"}:
        return Value(is_locale=False)
    if node.type == "navigation_expression" and symbol(node.named_children[0], scope, helpers) == LOCALE:
        if node.named_children[-1].text.isupper():
            return Value(is_locale=True)
    if node.type in {"string_literal", "multiline_string_literal"}:
        literal = node.text.decode().strip('"')
        dynamic = any(scope.get(name, UNKNOWN).external for name in template_names(literal))
        if not dynamic:
            dynamic = any(value_of(c.named_children[0], scope, helpers, depth + 1).external
                          for c in node.named_children if c.type == "interpolation" and c.named_children)
        return Value(bool(SQL_START.match(literal)), dynamic, literal=node, is_locale=False)
    children = node.named_children
    if node.type == "parenthesized_expression" and len(children) == 1:
        return value_of(children[0], scope, helpers, depth + 1)
    if node.type == "binary_expression" and any(c.type == "+" for c in node.children) and len(children) == 2:
        left = value_of(children[0], scope, helpers, depth + 1)
        right = value_of(children[1], scope, helpers, depth + 1)
        return Value(left.sql, left.external or right.external,
                     is_locale=False if left.sql or left.external or right.external or left.literal is not None else None)
    if node.type == "call_expression" and len(children) == 2 and children[1].type == "annotated_lambda":
        lam = children[1].named_children[-1]
        if lam.type == "lambda_literal":
            return build_string_value(children[0], lam, scope, helpers, depth + 1)
    if node.type == "call_expression" and len(children) == 2 and children[1].type == "value_arguments":
        callee, args = children
        parts = callee.named_children
        if len(parts) == 2 and parts[1].text in STRING_TRANSFORMS:
            text = value_of(parts[0], scope, helpers, depth + 1)
            if text.receiver_type or text.query_methods:
                return UNKNOWN
            # Default whitespace trims preserve formatter slots. Case changes can alter conversions.
            preserves_slots = parts[1].text in {b"trim", b"trimIndent", b"trimMargin"} and not args.named_children
            return text._replace(literal=text.literal if preserves_slots else None, is_locale=False)
        if callee.type == "navigation_expression" and len(parts) == 2:
            if parts[1].text == b"getDatabaseClient" and not any(c.type == "value_argument" for c in args.named_children):
                receiver = value_of(parts[0], scope, helpers, depth + 1)
                if receiver.receiver_type in R2DBC_TEMPLATES:
                    return REACTIVE_CLIENT
            if parts[1].text == b"format" or symbol(parts[1], scope, helpers) == FORMAT:
                return formatted_value(callee, args, scope, helpers, depth + 1)
            if parts[1].text == b"getDefault" and symbol(parts[0], scope, helpers) == LOCALE and not args.named_children:
                return Value(is_locale=True)
        if (helpers and callee.type in {"identifier", "navigation_expression"} and len(args.named_children) == 1
                and callee.end_byte - callee.start_byte < 512 and callee.text.split(b".", 1)[0].decode() not in scope):
            arg = args.named_children[0]
            key = function_key(callee, helpers)
            helper = helpers[key] if key is not None else None
            if isinstance(helper, tuple) and arg.type == "value_argument" and len(arg.named_children) == 1:
                name, expr = helper
                value = value_of(arg.named_children[0], scope, helpers, depth + 1)
                return value_of(expr, {name: value}, helpers.without_helpers, depth + 1)
    return UNKNOWN


def bind_property(node: Node, local: dict[str, Value], helpers: Functions, depth: int = 0):
    variable = next((c for c in node.named_children if c.type == "variable_declaration"), None)
    if variable is not None:
        name = variable.named_children[0].text.decode()
        immutable = any(c.type == "val" for c in node.children)
        local[name] = value_of(node.named_children[-1], local, helpers, depth) if immutable else UNKNOWN


def calls_with_scope(body: Node, scope: dict[str, Value], helpers: Functions):
    pending = [(body, scope)]
    while pending:
        node, local = pending.pop()
        children = node.named_children
        if node.type in {"function_declaration", "class_declaration", "object_declaration"}:
            continue
        if node.type in {"if_expression", "when_expression"}:
            pending.extend(reversed([(child, state) for child, state, _ in branch_nodes(node, local, helpers)]))
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
            bind_property(node, local, helpers)
        if node.type == "call_expression" and node.parent.type in {"block", "lambda_literal"} and len(children) == 2:
            callee, arguments = children
            if (symbol(callee, local, helpers) in CHECKS.values() and arguments.type == "value_arguments"
                    and len(arguments.named_children) == 1):
                argument = arguments.named_children[0]
                if argument.type == "value_argument" and len(argument.named_children) == 1:
                    name = allowed_name(argument.named_children[0], local, helpers)
                    if name is not None:
                        local[name] = UNKNOWN
        if node.type == "call_expression" and children and children[0].type == "navigation_expression":
            callee = children[0].named_children
            args = next((c for c in children if c.type == "value_arguments"), None)
            if len(callee) == 2:
                receiver = value_of(callee[0], local, helpers)
                if args is not None and (receiver.query_methods or receiver.receiver_type):
                    arguments = [a for a in args.named_children if a.type == "value_argument"]
                    yield receiver, callee[1].text.decode(), arguments, local
                elif receiver.receiver_type == R2DBC_CLIENT and callee[1].text == b"sql" and children[-1].type == "annotated_lambda":
                    yield receiver, "sql", [children[-1].named_children[-1]], local
        pending.extend((child, local) for child in reversed(children))


def parameter_type(parameter: Node, types: KotlinTypes) -> str:
    typ = next((c for c in parameter.named_children if c.type in {"user_type", "nullable_type"}), None)
    return types.resolve("".join(words(typ)).removesuffix("?"), parameter) if typ else ""


class SqlMethod(NamedTuple):
    body: Node
    scope: dict[str, Value]
    parameters: tuple[str, ...]
    text_parameters: set[str]
    sources: set[str]


def method_contexts(root: Node, class_names: set[str], same_package: dict[str, str]):
    primitive = {t: "kotlin." + t for t in ("String", "CharSequence", "Int", "Long", "Boolean", "Double", "Float")}
    defaults = {**primitive, **MVC_PARAMS}
    receivers = class_names | R2DBC_TEMPLATES | {R2DBC_CLIENT}
    types = KotlinTypes(root, DATABASE_METHODS.keys() | defaults.values() | {LOCALE} | receivers, defaults, same_package)
    http_params = set(MVC_PARAMS.values())
    for function in walk(root, "function_declaration"):
        cls = owner(function, "class_declaration")
        constructor = next((c for c in cls.named_children if c.type == "primary_constructor"), None) if cls else None
        scope = {}
        class_body = next((c for c in cls.named_children if c.type == "class_body"), None) if cls else None
        for field_decl in class_body.named_children if class_body else ():
            if field_decl.type != "property_declaration":
                continue
            var = next((c for c in field_decl.named_children if c.type == "variable_declaration"), None)
            if var is not None:
                field = var.named_children[0].text.decode()
                typ = parameter_type(var, types)
                scope[field] = scope["this." + field] = Value(query_methods=DATABASE_METHODS.get(typ, frozenset()),
                                                             receiver_type=typ if typ in receivers else "", injection=field_decl)
        if constructor:
            for param in walk(constructor, "class_parameter"):
                name = next((c for c in param.named_children if c.type == "identifier"), None)
                if name is not None and any(c.type in {"val", "var"} for c in param.children):
                    typ = parameter_type(param, types)
                    value = Value(query_methods=DATABASE_METHODS.get(typ, frozenset()),
                                  receiver_type=typ if typ in receivers else "", injection=param)
                    field = name.text.decode()
                    scope[field] = scope["this." + field] = value
        params = next((c for c in function.named_children if c.type == "function_value_parameters"), None)
        body = next((c for c in function.named_children if c.type == "function_body"), None)
        if params is None or body is None:
            continue
        annotations = set()
        parameters, text_parameters, sources = [], set(), set()
        for child in params.named_children:
            if child.type == "parameter_modifiers":
                annotations = set()
                for annotation in walk(child, "annotation"):
                    typ = next(walk(annotation, "user_type"), None)
                    if typ is not None:
                        annotations.add(types.resolve("".join(words(typ)), annotation))
            elif child.type == "parameter":
                name = child.named_children[0].text.decode()
                typ = parameter_type(child, types)
                is_locale = None
                if typ == LOCALE:
                    is_locale = True
                elif typ in primitive.values():
                    is_locale = False
                parameters.append(name)
                if typ in {"kotlin.String", "kotlin.CharSequence"}:
                    text_parameters.add(name)
                    if annotations & http_params:
                        sources.add(name)
                scope[name] = Value(query_methods=DATABASE_METHODS.get(typ, frozenset()), is_locale=is_locale,
                                    receiver_type=typ if typ in receivers else "")
                annotations.clear()
        yield function, cls, SqlMethod(body, scope, tuple(parameters), text_parameters, sources)


def sql_argument(receiver: Value, name: str, args: list[Node]) -> Node | None:
    if name not in receiver.query_methods or not args:
        return None
    if receiver.receiver_type != R2DBC_CLIENT:
        return args[0].named_children[-1]
    # The R2DBC API accepts exactly one String or Supplier<String>.
    if len(args) != 1:
        return None
    value = args[0] if args[0].type == "lambda_literal" else args[0].named_children[-1]
    if value.type == "lambda_literal":
        statements = [c for c in value.named_children if "comment" not in c.type]
        return statements[0] if len(statements) == 1 else None
    return value
