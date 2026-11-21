"""Inspect Spring annotation and programmatic CORS policies."""
from dataclasses import dataclass

from tree_sitter import Node

from garden.kotlin_checks import call_arguments, plain_literal, receiver_has_type, scope_call, walk, words
from garden.kotlin_types import KotlinTypes


CONFIG = "org.springframework.web.cors.CorsConfiguration"
ANNOTATION = "org.springframework.web.bind.annotation.CrossOrigin"
REGISTRIES = {"org.springframework.web.servlet.config.annotation.CorsRegistry",
              "org.springframework.web.reactive.config.CorsRegistry"}


def any_origin(arguments: list[list[str]]) -> bool | None:
    """Detect Spring's global origin in literal lists, including comma-delimited elements."""
    known = True
    for arg in arguments:
        if len(arg) != 1 or not plain_literal(arg[0]) or "\\" in arg[0]:
            known = False
            continue
        literal = arg[0][1:-1]
        if "," not in literal:
            if literal.removesuffix("/") == "*":
                return True
            continue
        # Commas within a bracketed port list are part of the same pattern.
        start, inside = 0, False
        for i, char in enumerate(literal + ","):
            if char in "[]":
                inside = char == "["
            elif char == "," and not inside:
                if literal[start:i].strip().removesuffix("/") == "*":
                    return True
                start = i + 1
    return False if known else None


@dataclass
class Registration:
    credentials: bool = False
    wildcard: Node | None = None
    invalid_origins: bool = False
    unknown: bool = False

    def findings(self):
        if self.credentials and self.wildcard is not None and not (self.invalid_origins or self.unknown):
            yield "credentialed-cors", self.wildcard

    def configure(self, call: Node, method: Node):
        args = call_arguments(call)
        if method.text == b"allowedOriginPatterns":
            self.wildcard = method if any_origin(args) else None
        elif method.text == b"allowCredentials":
            self.credentials = args == [["true"]]
        elif method.text == b"allowedOrigins":
            # Spring rejects an explicit "*" origin with credentials.
            self.invalid_origins = any_origin(args) is not False
        elif method.text not in {b"allowedMethods", b"allowedHeaders", b"exposedHeaders", b"maxAge", b"allowPrivateNetwork"}:
            self.unknown = True


def registration_chain(expr: Node):
    calls = []
    while expr.type == "call_expression":
        nav = expr.named_children[0]
        if nav.type != "navigation_expression":
            break
        calls.append((expr, nav.named_children[-1]))
        expr = nav.named_children[0]
    calls.reverse()
    return expr, calls


def registry_settings(block: Node, types: KotlinTypes):
    mappings = {}
    aliases = {}
    registries = {}
    for statement in block.named_children:
        variable = None
        var = None
        expr = statement
        if statement.type == "property_declaration" and statement.children[0].type == "val":
            var = next((c for c in statement.named_children if c.type == "variable_declaration"), None)
            if var is not None:
                variable = var.named_children[0].text
                expr = statement.named_children[-1]
        if variable and expr.type == "identifier":
            if expr.text in aliases:
                if var.named_child_count == 1:
                    aliases[variable] = aliases[expr.text]
                    continue
            names = REGISTRIES | {n for n, path in types.names.items() if path in REGISTRIES and types.resolve(n, expr) == path}
            retained_type = var.named_child_count == 1 or types.resolve("".join(words(var.named_children[-1])), var) in REGISTRIES
            if retained_type and (expr.text in registries or receiver_has_type(statement, names, receiver=expr)):
                registries[variable] = registries.get(expr.text, expr.text)
                continue
        receiver, calls = registration_chain(expr)
        # Once a registration escapes into another call or branch, its final settings are unknown.
        if aliases:
            for name in walk(statement, "identifier"):
                if name.text not in aliases or (calls and name == receiver):
                    continue
                if name.parent.type == "variable_declaration" and name == name.parent.named_children[0]:
                    continue
                if name.parent.type == "navigation_expression" and name == name.parent.named_children[-1]:
                    continue
                # A lambda parameter or a local declaration can reuse the registration's name.
                scopes = types.value_scopes.get(name.text.decode(), ())
                if not any(statement.start_byte <= start <= name.start_byte < end <= statement.end_byte for start, end in scopes):
                    aliases[name.text].unknown = True
        if not calls:
            continue
        first, method = calls[0]
        if method.text == b"addMapping":
            names = REGISTRIES | {n for n, path in types.names.items() if path in REGISTRIES and types.resolve(n, first) == path}
            if receiver.text not in registries and not receiver_has_type(first, names):
                continue
            registry_id = registries.get(receiver.text, receiver.text)
            args = call_arguments(first)
            if len(args) != 1 or len(args[0]) != 1 or not plain_literal(args[0][0]):
                for (registry, _), state in mappings.items():
                    if registry == registry_id:
                        state.unknown = True
                continue
            # Spring keeps the last registration for each path on the same registry.
            state = Registration()
            mappings[registry_id, args[0][0]] = state
            calls = calls[1:]
        elif receiver.type == "identifier" and receiver.text in aliases:
            state = aliases[receiver.text]
        else:
            continue
        for call, method in calls:
            state.configure(call, method)
        if variable is not None:
            aliases[variable] = state
    for state in mappings.values():
        yield from state.findings()


def configure_instance(state: Registration, statements: list[Node], receiver: str, implicit: bool, types: KotlinTypes):
    receivers = {receiver}
    for statement in statements:
        if statement.type in {"return_expression", "throw_expression"}:
            break
        if statement.type == "property_declaration" and statement.children[0].type == "val":
            expr = statement.named_children[-1]
            if expr.type == "identifier" and expr.text.decode() in receivers:
                var = next((c for c in statement.named_children if c.type == "variable_declaration"), None)
                if var and (var.named_child_count == 1 or types.resolve("".join(words(var.named_children[-1])), var) == CONFIG):
                    receivers.add(var.named_children[0].text.decode())
        if statement.type not in {"assignment", "call_expression"}:
            continue
        ws = words(statement)
        if ws[0] in receivers and ws[1:2] == ["."]:
            ws = ws[2:]
        elif not implicit or ws[1:2] == ["."]:
            continue
        if ws[:2] in (["allowCredentials", "="], ["setAllowCredentials", "("]):
            state.credentials = ws[2:] in (["true"], ["true", ")"])
        elif ws[:2] in (["allowedOriginPatterns", "="], ["setAllowedOriginPatterns", "("],
                        ["allowedOrigins", "="], ["setAllowedOrigins", "("]):
            expr = statement.named_children[-1]
            if expr.type == "value_arguments":
                args = [c for c in expr.named_children if c.type == "value_argument"]
                expr = args[0].named_children[-1] if len(args) == 1 else expr
            wide = False if expr.text == b"null" else None
            if (expr.type == "call_expression" and types.resolve_expression_name(expr.named_children[0])
                    in {"kotlin.collections.listOf", "kotlin.collections.mutableListOf", "kotlin.collections.emptyList"}):
                wide = any_origin(call_arguments(expr))
            if ws[0] in {"allowedOrigins", "setAllowedOrigins"}:
                state.invalid_origins = wide is not False
            else:
                state.wildcard = statement if wide else None
        elif ws[:2] == ["addAllowedOriginPattern", "("] and any_origin(call_arguments(statement)):
            state.wildcard = statement
        elif ws[:2] == ["addAllowedOrigin", "("] and any_origin(call_arguments(statement)) is not False:
            state.invalid_origins = True


def annotation_settings(annotation: Node, types: KotlinTypes):
    call = next((c for c in annotation.named_children if c.type == "constructor_invocation"), None)
    if call is None or types.resolve("".join(words(call.named_children[0])), annotation) != ANNOTATION:
        return
    credentials, wildcard, invalid_origins = False, None, False
    for argument in call.named_children[-1].named_children:
        if argument.type != "value_argument":
            continue
        fields = [n for n in argument.named_children if "comment" not in n.type]
        if len(fields) == 1:
            invalid_origins |= any_origin([words(fields[0])]) is not False
        if len(fields) != 2:
            continue
        name, value = fields
        if name.text == b"allowCredentials":
            credentials = value.text.lower() == b'"true"'
        elif name.text == b"originPatterns" and value.type == "collection_literal":
            wildcard = next((item for item in value.named_children if any_origin([words(item)])), None)
        elif name.text in {b"value", b"origins"}:
            invalid_origins |= (value.type != "collection_literal" or
                                any_origin([words(item) for item in value.named_children if "comment" not in item.type]) is not False)
    if credentials and wildcard is not None and not invalid_origins:
        yield "credentialed-cors", wildcard


def config_instance(expr: Node, types: KotlinTypes) -> bool:
    parts = [c for c in expr.named_children if "comment" not in c.type]
    if expr.type != "call_expression" or len(parts) != 2:
        return False
    callee, args = parts
    return (args.type == "value_arguments" and not any(c.type == "value_argument" for c in args.named_children)
            and types.resolve_expression_name(callee) == CONFIG)


def cors(root: Node):
    source = root.text
    registry = b"addMapping" in source and b"allowedOriginPatterns" in source
    if b"CrossOrigin" not in source and b"CorsConfiguration" not in source and not registry:
        return
    list_factories = {name: "kotlin.collections." + name for name in ("listOf", "mutableListOf", "emptyList")}
    types = KotlinTypes(root, {CONFIG, ANNOTATION, *list_factories.values()} | REGISTRIES, list_factories)
    for annotation in walk(root, "annotation"):
        yield from annotation_settings(annotation, types)
    for scope in walk(root, "lambda_literal"):
        host = scope_call(scope, {"apply", "also"})
        if host is None:
            continue
        nav = host.named_children[0]
        if not config_instance(nav.named_children[0], types):
            continue
        implicit = nav.named_children[-1].text == b"apply"
        params = next((c for c in scope.named_children if c.type == "lambda_parameters"), None)
        variable = words(params)[0] if params else ("this" if implicit else "it")
        state = Registration()
        configure_instance(state, scope.named_children, variable, implicit, types)
        prop = host.parent
        if prop.type == "property_declaration" and prop.children[0].type == "val" and prop.parent.type == "block":
            var = next((c for c in prop.named_children if c.type == "variable_declaration"), None)
            if var:
                block = prop.parent.named_children
                configure_instance(state, block[block.index(prop) + 1:], var.named_children[0].text.decode(), False, types)
        yield from state.findings()
    for block in walk(root, "block"):
        if registry and b"addMapping" in block.text:
            yield from registry_settings(block, types)
        statements = block.named_children
        for i, node in enumerate(statements):
            if node.type != "property_declaration" or not any(c.type == "val" for c in node.children):
                continue
            var = next((c for c in node.named_children if c.type == "variable_declaration"), None)
            if var is not None and config_instance(node.named_children[-1], types):
                state = Registration()
                configure_instance(state, statements[i + 1:], var.named_children[0].text.decode(), False, types)
                yield from state.findings()
