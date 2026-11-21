"""Local syntax checks. Comments and unrelated functions are excluded from matches."""
import re
from base64 import b64decode
from collections.abc import Callable, Iterator

from tree_sitter import Node

from garden.kotlin_strings import static_string


def walk(root: Node, kind: str) -> Iterator[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == kind:
            yield node
        stack.extend(reversed(node.named_children))


def tokens(root: Node) -> list[Node]:
    result = []
    stack = [root]
    while stack:
        node = stack.pop()
        if "comment" in node.type:
            continue
        if node.child_count and node.type not in {"string_literal", "multiline_string_literal"}:
            stack.extend(reversed(node.children))
        else:
            result.append(node)
    return result


def words(node: Node) -> list[str]:
    return [part.text.decode() for part in tokens(node)]


def owner(node: Node, kind: str) -> Node | None:
    while node is not None and node.type != kind:
        node = node.parent
    return node


def kotlin_imports(root: Node):
    for item in walk(root, "import"):
        parts = words(item)[1:]
        path = "".join(parts[:parts.index("as")] if "as" in parts else parts)
        yield path, parts[-1]


def plain_literal(word: str) -> bool:
    return len(word) > 2 and word.startswith('"') and word.endswith('"') and "$" not in word


# A dollar followed by an identifier or brace starts interpolation. Kotlin's
# character-literal dollar expression is constant in both string forms.
DOLLAR = r"\$\{\s*'\$'\s*\}|(\$(?=[^\W\d]|[{`]))"
REGULAR_DOLLARS = re.compile(r"\\.|" + DOLLAR, re.S)
RAW_DOLLARS = re.compile(DOLLAR)


def credential_literal(word: str) -> bool:
    if "$" not in word:
        return plain_literal(word)
    raw = word.startswith('"""')
    quote = '"""' if raw else '"'
    if not word.startswith(quote) or not word.endswith(quote):
        return False
    pattern = RAW_DOLLARS if raw else REGULAR_DOLLARS
    return not any(match[1] for match in pattern.finditer(word, len(quote), len(word) - len(quote)))


def credential_fallback(expr: list[str]) -> bool:
    if expr[:3] == ["java", ".", "lang"] and expr[3:4] == ["."]:
        expr = expr[4:]
    if expr[:4] == ["System", ".", "getProperty", "("] and len(expr) == 8 and expr[5] == "," and expr[7] == ")":
        default = expr[6]
    elif len(expr) >= 3 and expr[-2] == "?:" and any(k in expr[:-2] for k in ("getenv", "getProperty")):
        default = expr[-1]
    else:
        return False
    return credential_literal(default) and bool(default.strip('"').strip())


def template_names(word: str) -> set[str]:
    pattern = r"(?<!\\)\$(?:\{\s*(\w+)(?:\.(?:trim|uppercase|lowercase)\(\))?\s*\}|(\w+))"
    return {a or b for a, b in re.findall(pattern, word)}


def binding(constants, name: str, use: Node):
    for kind, declaration in reversed(constants.get(name, [])):
        scope = declaration.parent
        if declaration.end_byte > use.start_byte:
            modifiers = next((c for c in declaration.named_children if c.type == "modifiers"), None)
            if scope.type not in {"source_file", "class_body"} or modifiers is None or "const" not in words(modifiers):
                continue
        if scope.start_byte <= use.start_byte < scope.end_byte:
            for lam in enclosing_lambdas(use, scope):
                params = next((c for c in lam.named_children if c.type == "lambda_parameters"), None)
                names = [v.named_children[0].text.decode() for v in walk(params, "variable_declaration")] if params else ["it"]
                if name in names:
                    return None
            return kind, declaration
    return None


def enclosing_lambdas(use: Node, scope: Node):
    parent = use.parent
    while parent is not None and parent != scope:
        if parent.type == "lambda_literal":
            yield parent
        parent = parent.parent


def basic_password(encoded: str) -> bool:
    try:
        decoded = b64decode(encoded, validate=True)
    except ValueError:
        return False
    return bool(decoded.partition(b":")[2])


def encoded_basic_location(argument: list[str], call: Node, constants) -> Node | None:
    if len(argument) != 1:
        return None
    word, location = argument[0], call
    resolved = binding(constants, word, call)
    if resolved and resolved[0] == "literal":
        location = resolved[1]
        word = words(location)[-1]
    return location if plain_literal(word) and basic_password(word.strip('"')) else None


def scope_call(lam: Node, methods: set[str]) -> Node | None:
    parent = lam.parent
    if parent.type != "annotated_lambda" or parent.parent.type != "call_expression":
        return None
    call = parent.parent
    callee = call.named_children[0]
    if callee.type == "navigation_expression" and callee.named_children[-1].text.decode() in methods:
        return call
    return None


def receiver_has_type(call: Node, types: set[str], depth: int = 0, *, receiver: Node | None = None,
                      factory: Callable[[Node, int], bool] | None = None) -> bool:
    if depth > 32:
        return False
    callee = call.named_children[0]
    if receiver is None and callee.type == "navigation_expression":
        receiver = callee.named_children[0]
    if receiver is None or receiver.type == "this_expression":
        if receiver is not None and words(receiver) != ["this"]:
            return False
        lam = owner(call, "lambda_literal")
        if lam is None or owner(lam, "function_declaration") != owner(call, "function_declaration"):
            return False
        host = scope_call(lam, {"apply", "run"})
        return host is not None and receiver_has_type(host, types, depth + 1, factory=factory)
    while receiver.type == "parenthesized_expression" and len(receiver.named_children) == 1:
        receiver = receiver.named_children[0]
    if receiver.type == "as_expression":
        typ = receiver.child_by_field_name("right")
        return typ is not None and "".join(words(typ)).removesuffix("?") in types
    if receiver.type == "call_expression":
        if factory is not None:
            return factory(receiver, depth + 1)
        return "".join(words(receiver.named_children[0])) in types
    scope = call.parent
    if receiver.type == "identifier":
        name = receiver.text.decode()
    elif receiver.type == "navigation_expression" and receiver.named_children[0].text == b"this":
        cls = owner(call, "class_body")
        lam = owner(call, "lambda_literal")
        if cls is None or (lam is not None and lam.start_byte > cls.start_byte):
            return False
        scope = cls
        name = receiver.named_children[-1].text.decode()
    else:
        return False
    while scope:
        if scope.type in {"block", "lambda_literal", "class_body"}:
            for decl in reversed(scope.named_children):
                if decl.type != "property_declaration" or (scope.type != "class_body" and decl.end_byte > call.start_byte):
                    continue
                var = next((c for c in decl.named_children if c.type == "variable_declaration"), None)
                if var and var.named_children[0].text.decode() == name:
                    if len(var.named_children) > 1:
                        return "".join(words(var.named_children[-1])).removesuffix("?") in types
                    value = decl.named_children[-1]
                    while value.type == "parenthesized_expression" and len(value.named_children) == 1:
                        value = value.named_children[0]
                    if value.type == "identifier" and any(c.type == "val" for c in decl.children):
                        return receiver_has_type(decl, types, depth + 1, receiver=value, factory=factory)
                    if factory is not None:
                        return value.type == "call_expression" and factory(value, depth + 1)
                    rhs = words(value)
                    return rhs[-2:] == ["(", ")"] and "".join(rhs[:-2]) in types
            if scope.type == "lambda_literal":
                params = next((c for c in scope.named_children if c.type == "lambda_parameters"), None)
                if name in (words(params) if params else ["it"]):
                    host = scope_call(scope, {"also", "let"})
                    return host is not None and receiver_has_type(host, types, depth + 1, factory=factory)
        if scope.type in {"function_declaration", "class_declaration"}:
            params = next((c for c in scope.named_children if c.type in {"function_value_parameters", "primary_constructor"}), None)
            if params:
                kind = "parameter" if scope.type == "function_declaration" else "class_parameter"
                for param in walk(params, kind):
                    identifier = next((c for c in param.named_children if c.type == "identifier"), None)
                    if identifier and identifier.text.decode() == name:
                        typ = next((c for c in param.named_children if c.type in {"user_type", "nullable_type"}), None)
                        return typ is not None and "".join(words(typ)).removesuffix("?") in types
            if scope.type == "class_declaration":
                return False
        scope = scope.parent
    return False


HEADER_TARGETS = {'"x-api-key"': "api-key", '"authorization"': "authorization"}


def header_credential(target: str, argument: Node, constants):
    children = [c for c in argument.named_children if "comment" not in c.type]
    if len(children) != 1:
        return None
    expr = children[0]
    word = expr.text.decode()
    auth = target == "authorization"
    # For an alias of the whole credential, report the declaration once.
    # Adding the HTTP authentication scheme to an alias doesn't change its origin.
    pattern = r'"(?:Bearer|Basic)\s+\$(?:\{(\w+)\}|(\w+))"' if auth else r'"\$(?:\{(\w+)\}|(\w+))"'
    match = re.fullmatch(pattern, word, re.I)
    name = word if expr.type == "identifier" else ""
    if match:
        name = match[1] or match[2]
    origin = binding(constants, name, expr) if name else None
    if origin and origin[0] == "secret-fallback" and (not auth or match):
        return "secret-fallback", origin[1]

    def lookup(name: str, use: Node) -> Node | None:
        resolved = binding(constants, name, use)
        return resolved[1] if resolved else None

    text = static_string(expr, lookup)
    if text is None or not text.strip():
        return None
    location = origin[1] if origin else argument
    simple = expr.type in {"string_literal", "multiline_string_literal"} and credential_literal(word)
    compound = origin[0] != "literal" if origin else not simple
    if auth:
        scheme = re.fullmatch(r"(Bearer|Basic)\s+(\S+)", text.strip(), re.I)
        if not scheme:
            return None
        if scheme[1].lower() == "basic":
            return ("recoverable-token", location) if basic_password(scheme[2]) else None
        target = "configuration-token"
    return ("recoverable-token" if compound and target != "password" else target), location


def inherited_constants(file_constants, function: Node | None):
    constants = {name: items.copy() for name, items in file_constants.items()}
    scope = function
    while scope is not None and constants:
        if scope.type in {"function_declaration", "class_declaration"}:
            params = next((c for c in scope.named_children if c.type in {"primary_constructor", "function_value_parameters"}), None)
            if params is not None:
                kind = "class_parameter" if params.type == "primary_constructor" else "parameter"
                for param in walk(params, kind):
                    name = next((c.text.decode() for c in param.named_children if c.type == "identifier"), "")
                    constants.pop(name, None)
        elif scope.type in {"block", "class_body", "lambda_literal"}:
            for prop in scope.named_children:
                if prop.type != "property_declaration" or (scope.type != "class_body" and prop.start_byte > function.start_byte):
                    continue
                var = next((c for c in prop.named_children if c.type == "variable_declaration"), None)
                if var:
                    name = var.named_children[0].text.decode()
                    if not any(decl == prop for _, decl in constants.get(name, [])):
                        constants.pop(name, None)
        scope = scope.parent
    return constants


def auth_constants(root: Node, http_header_checker):
    valid_header = None
    header_class = "org.springframework.http.HttpHeaders"
    imported = list(kotlin_imports(root))
    header_types = {header_class} | {name for path, name in imported if path == header_class}
    if ("org.springframework.http.*", "*") in imported and not any(name == "HttpHeaders" for _, name in imported):
        local_types = (node.child_by_field_name("name") for node in root.named_children
                       if node.type in {"class_declaration", "object_declaration", "type_alias"})
        if not any(name and name.text == b"HttpHeaders" for name in local_types):
            header_types.add("HttpHeaders")
    global_constants = {}
    for scope in [root, *walk(root, "function_declaration")]:
        function = None if scope == root else scope
        constants = inherited_constants(global_constants, function)
        for declaration in walk(scope, "property_declaration"):
            if owner(declaration, "function_declaration") != function:
                continue
            parts = tokens(declaration)
            ws = [n.text.decode() for n in parts]
            if not {"val", "var"}.intersection(ws) or "=" not in ws:
                continue
            name = ws[next(i for i, word in enumerate(ws) if word in {"val", "var"}) + 1]
            expr = ws[ws.index("=") + 1:]
            kind = "unknown"
            if "val" not in ws:
                constants.setdefault(name, []).append((kind, declaration))
                continue
            if len(expr) == 1 and credential_literal(expr[0]):
                kind = "literal"
            elif credential_fallback(expr):
                kind = "secret-fallback"
            elif (len(expr) >= 3 and len(expr) % 2 and all(op == "+" for op in expr[1::2])
                  and all(credential_literal(v) or (binding(constants, v, declaration) or ("",))[0] == "literal" for v in expr[::2])):
                kind = "recoverable-token"
            constants.setdefault(name, []).append((kind, declaration))
            if function is None and "const" in ws[:ws.index("val")]:
                global_constants.setdefault(name, []).append((kind, declaration))
        emitted = set()
        for call in walk(scope, "call_expression"):
            if owner(call, "function_declaration") != function:
                continue
            arguments = next((n for n in call.named_children if n.type == "value_arguments"), None)
            if arguments is None:
                continue
            values = [n for n in arguments.named_children if n.type == "value_argument"]
            args = [words(value) for value in values]
            method = words(call.named_children[0])[-1]
            if method in {"header", "setHeader", "headers", "set", "add"}:
                if (len(args) % 2 or (method != "headers" and len(args) != 2)
                        or not any(len(h) == 1 and h[0].lower() in HEADER_TARGETS for h in args[::2])):
                    continue
                if method in {"set", "add"}:
                    if not receiver_has_type(call, header_types):
                        continue
                else:
                    if valid_header is None:
                        valid_header = http_header_checker(root)
                    if not valid_header(call):
                        continue
                for header, value in zip(args[::2], values[1::2]):
                    target = HEADER_TARGETS.get(header[0].lower()) if len(header) == 1 else None
                    found = header_credential(target, value, constants) if target else None
                    if found and found[1].start_byte not in emitted:
                        emitted.add(found[1].start_byte)
                        yield found
                continue
            if method == "setBasicAuth":
                if not receiver_has_type(call, header_types):
                    continue
                if len(args) == 1:
                    location = encoded_basic_location(args[0], call, constants)
                    if location is not None:
                        yield "recoverable-token", location
                    continue
                if len(args) not in {2, 3}:
                    continue
                index, direct = 1, "password"
            elif method == "setBearerAuth" and len(args) == 1 and receiver_has_type(call, header_types):
                index, direct = 0, "configuration-token"
            else:
                continue
            found = header_credential(direct, values[index], constants)
            if found and found[1].start_byte not in emitted:
                emitted.add(found[1].start_byte)
                yield found




HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
SPRING_HTTP_METHOD = "org.springframework.http.HttpMethod"
ACCESS_RULES = {"permitAll", "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority", "authenticated", "denyAll"}


def call_arguments(call: Node) -> list[list[str]]:
    arguments = next((c for c in call.named_children if c.type == "value_arguments"), None)
    return [words(arg) for arg in arguments.named_children if arg.type == "value_argument"] if arguments else []


def matcher_http_method(parts: list[str], use: Node, types, aliases: dict[str, str]) -> str | None:
    if not parts or parts[0].startswith('"'):
        return None
    if len(parts) == 1 and parts[0] in aliases:
        return aliases[parts[0]]
    if any(start <= use.start_byte < end for start, end in types.value_scopes.get(parts[0], ())):
        return None
    if len(parts) == 1:
        resolved = types.resolve(parts[0], use)
    elif parts[-2:-1] == ["."]:
        owner = types.resolve("".join(parts[:-2]), use)
        resolved = owner + "." + parts[-1] if owner else ""
    else:
        return None
    prefix, _, method = resolved.rpartition(".")
    return method if prefix == SPRING_HTTP_METHOD and method in HTTP_METHODS else None


def matcher_rules(statement: Node, receiver: str, registry: str):
    if statement.type != "call_expression":
        return
    callee = statement.named_children[0]
    if callee.type == "identifier" and callee.text == b"authorize":
        if registry.endswith("-fluent"):
            return
        args = call_arguments(statement)
        if registry == "webflux-dsl":
            if len(args) == 2 and args[0][:2] == ["access", "="]:
                args.reverse()
            if args and args[0][:2] == ["antPattern", "="]:
                args[0] = args[0][2:]
            if len(args) == 2 and args[1][:2] == ["access", "="]:
                args[1] = args[1][2:]
            if len(args) == 1:
                yield args, "authenticated", True, callee
                return
            if len(args) != 2:
                return
        if len(args) >= 2:
            access = args[-1]
            simple = len(access) == 1 or (access[1:2] == ["("] and access.count("(") == 1 and access[-1:] == [")"])
            if simple and access[0] in ACCESS_RULES:
                yield args[:-1], access[0], True, callee
        return
    # Follow the fluent registry from its lambda parameter through each matcher/access pair.
    if registry.endswith("-dsl"):
        return
    matchers = {b"pathMatchers", b"anyExchange"} if registry == "webflux-fluent" else {b"requestMatchers", b"anyRequest"}
    chain = []
    call = statement
    while call.type == "call_expression":
        nav = call.named_children[0]
        if nav.type != "navigation_expression":
            return
        call, method = nav.named_children[0], nav.named_children[-1]
        chain.append((method, nav.parent))
    if call.text.decode() != receiver:
        return
    chain.reverse()
    for (matcher, declaration), (access, _) in zip(chain[::2], chain[1::2]):
        action = access.text.decode()
        if matcher.text not in matchers or action not in ACCESS_RULES:
            break
        yield call_arguments(declaration), action, False, matcher


SECURITY_BUILDERS = {
    "authorizeHttpRequests": ("servlet", "org.springframework.security.config.annotation.web.builders.HttpSecurity",
                              "org.springframework.security.config.annotation.web"),
    "authorizeExchange": ("webflux", "org.springframework.security.config.web.server.ServerHttpSecurity",
                          "org.springframework.security.config.web.server"),
}


def authorization_registry(host: Node, types, family: str, builder_type: str, dsl_imported: bool) -> str | None:
    names = {builder_type} | {name for name, path in types.names.items() if path == builder_type and types.resolve(name, host) == builder_type}

    def configured_receiver(expr: Node, depth: int) -> bool:
        nav = expr.named_children[0]
        if nav.type != "navigation_expression" or nav.named_children[-1].text not in {
            b"cors", b"csrf", b"formLogin", b"httpBasic", b"headers", b"logout", b"sessionManagement", b"exceptionHandling"
        }:
            return False
        # The overload taking a Customizer returns the security builder.
        if not call_arguments(expr) and not any(c.type == "annotated_lambda" for c in expr.named_children):
            return False
        return receiver_has_type(expr, names, depth, factory=configured_receiver)

    callee = host.named_children[0]
    if callee.type == "navigation_expression":
        return family + "-fluent" if receiver_has_type(host, names, factory=configured_receiver) else None
    block = host.parent
    if not dsl_imported or callee.type != "identifier" or block.type != "lambda_literal" or block.parent.type != "annotated_lambda":
        return None
    builder = block.parent.parent
    if builder.type != "call_expression":
        return None
    receiver = builder.named_children[0]
    return family + "-dsl" if receiver_has_type(builder, names, receiver=receiver, factory=configured_receiver) else None


def matcher_conflicts(root: Node):
    from garden.kotlin_types import KotlinTypes

    source = root.text
    if b"authorizeHttpRequests" not in source and b"authorizeExchange" not in source:
        return
    method_names = {name: SPRING_HTTP_METHOD + "." + name for name in HTTP_METHODS}
    # Existing partial snippets can omit imports. Explicit imports and visible declarations take precedence.
    defaults = {"HttpMethod": SPRING_HTTP_METHOD, **method_names}
    types = KotlinTypes(root, {entry[1] for entry in SECURITY_BUILDERS.values()} | set(defaults.values()), defaults)
    imported = set(kotlin_imports(root))
    for scope in walk(root, "lambda_literal"):
        parent = scope.parent
        if parent.type == "value_argument" and parent.parent.type == "value_arguments":
            parent = parent.parent
        if parent.type not in {"annotated_lambda", "value_arguments"} or parent.parent.type != "call_expression":
            continue
        host = parent.parent
        method = words(host.named_children[0])[-1]
        if method not in SECURITY_BUILDERS:
            continue
        family, builder, package = SECURITY_BUILDERS[method]
        registry = authorization_registry(host, types, family, builder,
                                          bool(imported & {(package + ".invoke", "invoke"), (package + ".*", "*")}))
        if registry is None:
            continue
        params = next((c for c in scope.named_children if c.type == "lambda_parameters"), None)
        receiver = words(params)[0] if params else "it"
        public = []
        previous = []
        emitted = set()
        any_rule = "anyExchange" if family == "webflux" else "anyRequest"
        default_seen = False
        method_aliases = {}
        for statement in scope.named_children:
            if statement.type == "property_declaration" and statement.children[0].type == "val":
                var = next((c for c in statement.named_children if c.type == "variable_declaration"), None)
                if var and (var.named_child_count == 1 or types.resolve("".join(words(var.named_children[-1])), var) == SPRING_HTTP_METHOD):
                    value = statement.named_children[-1]
                    verb = matcher_http_method(words(value), value, types, method_aliases)
                    if verb:
                        method_aliases[var.named_children[0].text.decode()] = verb
                continue
            for args, access, native, loc in matcher_rules(statement, receiver, registry):
                if default_seen:
                    break
                if (native and args == [[any_rule]]) or (not native and not args and loc.text.decode() == any_rule):
                    default_seen = True
                    if access == "permitAll" and (("**",), None, None) not in previous:
                        if native:
                            loc = next((n for n in walk(statement, "identifier") if n.text.decode() == any_rule), loc)
                        yield "open-default", loc
                    continue
                method = matcher_http_method(args[0], loc, types, method_aliases) if args else None
                if method:
                    args = args[1:]
                    if not args and family == "servlet":
                        # The method-only servlet overload matches every path for this verb.
                        args = [['"/**"']]
                if not args or any(len(a) != 1 or not plain_literal(a[0]) or not a[0].startswith('"/') for a in args):
                    continue
                paths = [a[0][1:-1] for a in args]
                servlet = None
                if native and len(paths) == 2:
                    servlet = paths.pop()
                if native and len(paths) != 1:
                    continue
                patterns = [path_segments(path) for path in paths]
                prior_count = len(previous)
                previous.extend((p, method, servlet) for p in patterns)
                if access == "permitAll":
                    public.extend((path, method, servlet, loc, prior_count) for path in patterns)
                    continue
                for earlier, verb, mount, location, prior in public:
                    if mount != servlet or (verb and method and verb != method) or location.start_byte in emitted:
                        continue
                    for path in patterns:
                        if path == ("**",):
                            continue
                        overlap = intersect_paths(earlier, path)
                        if overlap is None:
                            continue
                        if any(s == mount and (m is None or m == (verb or method)) and intersect_paths(p, overlap, prior_guard=True) == overlap
                               for p, m, s in previous[:prior]):
                            continue
                        emitted.add(location.start_byte)
                        yield "route-authorization", location
                        break


def path_segments(path: str) -> tuple[str, ...]:
    if path == "/":
        return ()
    segments = path[1:].split("/")
    for i, segment in enumerate(segments):
        if segment == "*" or re.fullmatch(r"\{\w+\}", segment):
            segments[i] = "*"
        elif i == len(segments) - 1 and (segment == "**" or re.fullmatch(r"\{\*\w+\}", segment)):
            segments[i] = "**"
        # Keep other segment syntax opaque. A literal prefix ending in /**
        # still covers it without interpreting a user-supplied regex.
    return tuple(segments)


def intersect_paths(left: tuple[str, ...], right: tuple[str, ...], *, prior_guard: bool = False) -> tuple[str, ...] | None:
    """Return the common pattern for literals, one segment (*) and any suffix (**)."""
    common = []
    for i, (a, b) in enumerate(zip(left, right)):
        if a == "**":
            return tuple(common) + right[i:]
        if b == "**":
            return tuple(common) + left[i:]
        if a == b:
            common.append(a)
        elif a == "*" and b:
            common.append(b)
        elif b == "*" and a:
            common.append(a)
        elif prior_guard and any(c in a for c in "*?{"):
            # An earlier custom constraint may already protect this segment.
            common.append(b)
        else:
            return None
    remaining = (left if len(left) > len(right) else right)[len(common):]
    return tuple(common) if remaining in ((), ("**",)) else None
