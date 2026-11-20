"""Local syntax checks. Comments and unrelated functions are excluded from matches."""
import re
from collections.abc import Iterator

from tree_sitter import Node


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


def imports(root: Node, path: str) -> bool:
    return any("".join(words(item)[1:]).startswith(path) for item in walk(root, "import"))


def kotlin_imports(root: Node):
    for item in walk(root, "import"):
        parts = words(item)[1:]
        path = "".join(parts[:parts.index("as")] if "as" in parts else parts)
        yield path, parts[-1]


def plain_literal(word: str) -> bool:
    return len(word) > 2 and word.startswith('"') and word.endswith('"') and "$" not in word


def credential_fallback(expr: list[str]) -> bool:
    if expr[:3] == ["java", ".", "lang"] and expr[3:4] == ["."]:
        expr = expr[4:]
    if expr[:4] == ["System", ".", "getProperty", "("] and len(expr) == 8 and expr[5] == "," and expr[7] == ")":
        default = expr[6]
    elif len(expr) >= 3 and expr[-2] == "?:" and any(k in expr[:-2] for k in ("getenv", "getProperty")):
        default = expr[-1]
    else:
        return False
    return plain_literal(default) and bool(default.strip('"').strip())


def template_names(word: str) -> set[str]:
    pattern = r"(?<!\\)\$(?:\{\s*(\w+)(?:\.(?:trim|uppercase|lowercase)\(\))?\s*\}|(\w+))"
    return {a or b for a, b in re.findall(pattern, word)}


def binding(constants, name: str, use: Node):
    for kind, declaration in reversed(constants.get(name, [])):
        scope = declaration.parent
        if declaration.end_byte <= use.start_byte and scope.start_byte <= use.start_byte < scope.end_byte:
            return kind, declaration
    return None


def scope_call(lam: Node, methods: set[str]) -> Node | None:
    parent = lam.parent
    if parent.type != "annotated_lambda" or parent.parent.type != "call_expression":
        return None
    call = parent.parent
    callee = call.named_children[0]
    if callee.type == "navigation_expression" and callee.named_children[-1].text.decode() in methods:
        return call
    return None


def http_headers_receiver(call: Node, types: set[str], depth: int = 0) -> bool:
    if depth > 32:
        return False
    callee = call.named_children[0]
    receiver = callee.named_children[0] if callee.type == "navigation_expression" else None
    if receiver is None or receiver.type == "this_expression":
        if receiver is not None and words(receiver) != ["this"]:
            return False
        lam = owner(call, "lambda_literal")
        if lam is None or owner(lam, "function_declaration") != owner(call, "function_declaration"):
            return False
        host = scope_call(lam, {"apply", "run"})
        return host is not None and http_headers_receiver(host, types, depth + 1)
    if receiver.type == "call_expression":
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
                    rhs = words(decl.named_children[-1])
                    return rhs[-2:] == ["(", ")"] and "".join(rhs[:-2]) in types
            if scope.type == "lambda_literal":
                params = next((c for c in scope.named_children if c.type == "lambda_parameters"), None)
                if name in (words(params) if params else ["it"]):
                    host = scope_call(scope, {"also", "let"})
                    return host is not None and http_headers_receiver(host, types, depth + 1)
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


def auth_constants(root: Node):
    spring_headers = imports(root, "org.springframework.http.") or imports(root, "org.springframework.web.client.")
    header_class = "org.springframework.http.HttpHeaders"
    imported = list(kotlin_imports(root))
    header_types = {header_class} | {name for path, name in imported if path == header_class}
    if ("org.springframework.http.*", "*") in imported and not any(name == "HttpHeaders" for _, name in imported):
        local_types = (node.child_by_field_name("name") for node in root.named_children
                       if node.type in {"class_declaration", "object_declaration", "type_alias"})
        if not any(name and name.text == b"HttpHeaders" for name in local_types):
            header_types.add("HttpHeaders")
    for function in walk(root, "function_declaration"):
        constants = {}
        for declaration in walk(function, "property_declaration"):
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
            if len(expr) == 1 and plain_literal(expr[0]):
                kind = "literal"
            elif credential_fallback(expr):
                kind = "secret-fallback"
            elif (len(expr) >= 3 and len(expr) % 2 and all(op == "+" for op in expr[1::2])
                  and all(plain_literal(v) or (binding(constants, v, declaration) or ("",))[0] == "literal" for v in expr[::2])):
                kind = "recoverable-token"
            constants.setdefault(name, []).append((kind, declaration))
        emitted = set()
        for call in walk(function, "call_expression"):
            if owner(call, "function_declaration") != function:
                continue
            args = next((c for c in call.named_children if c.type == "value_arguments"), None)
            if args is None:
                continue
            method = words(call.named_children[0])[-1]
            arg = words(args)
            if method == "setBearerAuth" and len(arg) == 3 and http_headers_receiver(call, header_types):
                value = arg[1]
                direct = "configuration-token"
            elif method == "setBasicAuth" and len(arg) == 5 and arg[2] == ",":
                value = arg[3]
                direct = "password"
            elif (method in {"set", "add"} and len(arg) == 5 and arg[1].lower() == '"x-api-key"'
                  and http_headers_receiver(call, header_types)):
                value, direct = arg[3], "api-key"
            elif method in {"header", "set", "add"} and len(arg) == 5 and arg[1].lower() == '"authorization"':
                value = arg[3]
                direct = "configuration-token" if re.match(r'^"(?:Bearer|Basic)\s+\S', value, re.I) else None
            else:
                continue
            spring_call = spring_headers or method == "setBearerAuth" or direct == "api-key"
            if spring_call and direct and plain_literal(value) and value.strip('"').strip():
                yield direct, call
            for name in template_names(value) or {value}:
                resolved = binding(constants, name, call)
                if resolved:
                    kind, location = resolved
                    if kind == "literal":
                        kind = direct if spring_call else None
                    if kind and kind != "unknown" and location.start_byte not in emitted:
                        emitted.add(location.start_byte)
                        yield kind, location


def cors_settings(statements: list[Node], receiver: str, implicit: bool):
    credentials, wildcard = False, None
    for statement in statements:
        if statement.type not in {"assignment", "call_expression"}:
            continue
        ws = words(statement)
        if ws[:2] == [receiver, "."]:
            ws = ws[2:]
        elif not implicit or ws[1:2] == ["."]:
            continue
        if ws[:2] in (["allowCredentials", "="], ["setAllowCredentials", "("]):
            credentials = ws[2:] in (["true"], ["true", ")"])
        elif ws[:2] in (["allowedOriginPatterns", "="], ["setAllowedOriginPatterns", "("]):
            value = ws[2:-1] if ws[1] == "(" else ws[2:]
            wildcard = statement if value[:2] in (["listOf", "("], ["mutableListOf", "("]) and '"*"' in value[2::2] else None
        elif ws == ["addAllowedOriginPattern", "(", '"*"', ")"]:
            wildcard = statement
    if credentials and wildcard is not None:
        yield "credentialed-cors", wildcard


def cors(root: Node):
    if not imports(root, "org.springframework.web.cors."):
        return
    for scope in walk(root, "lambda_literal"):
        host = owner(scope, "call_expression")
        callee = words(host.named_children[0]) if host else []
        if callee[:-1] != ["CorsConfiguration", "(", ")", "."] or callee[-1] not in {"apply", "also"}:
            continue
        params = next((c for c in scope.named_children if c.type == "lambda_parameters"), None)
        implicit = callee[-1] == "apply"
        receiver = "this" if implicit else "it"
        if params:
            receiver = words(params)[0]
        yield from cors_settings(scope.named_children, receiver, implicit)
    for block in walk(root, "block"):
        statements = block.named_children
        for i, node in enumerate(statements):
            if node.type == "property_declaration":
                ws = words(node)
                if ws[:1] == ["val"] and ws[-4:] == ["=", "CorsConfiguration", "(", ")"]:
                    yield from cors_settings(statements[i+1:], ws[1], False)


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
ACCESS_RULES = {"permitAll", "hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority", "authenticated", "denyAll"}


def call_arguments(call: Node) -> list[list[str]]:
    arguments = next((c for c in call.named_children if c.type == "value_arguments"), None)
    return [words(arg) for arg in arguments.named_children if arg.type == "value_argument"] if arguments else []


def matcher_rules(statement: Node, receiver: str):
    if statement.type != "call_expression":
        return
    callee = statement.named_children[0]
    if callee.type == "identifier" and callee.text == b"authorize":
        args = call_arguments(statement)
        if len(args) >= 2:
            access = args[-1]
            simple = len(access) == 1 or (access[1:2] == ["("] and access.count("(") == 1 and access[-1:] == [")"])
            if simple and access[0] in ACCESS_RULES:
                yield args[:-1], access[0], True, callee
        return
    # Follow the fluent registry from its lambda parameter through each matcher/access pair.
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
        if matcher.text != b"requestMatchers" or action not in ACCESS_RULES:
            break
        yield call_arguments(declaration), action, False, matcher


def matcher_conflicts(root: Node):
    if not imports(root, "org.springframework.security."):
        return
    for scope in walk(root, "lambda_literal"):
        host = owner(scope, "call_expression")
        if not host or words(host.named_children[0])[-1:] != ["authorizeHttpRequests"]:
            continue
        params = next((c for c in scope.named_children if c.type == "lambda_parameters"), None)
        receiver = words(params)[0] if params else "it"
        public = []
        protected = []
        emitted = set()
        for statement in scope.named_children:
            for args, access, native, loc in matcher_rules(statement, receiver):
                method = None
                if args and args[0] and args[0][:-1] in ([], ["HttpMethod", "."]) and args[0][-1] in HTTP_METHODS:
                    method, args = args[0][-1], args[1:]
                if not args or any(len(a) != 1 or not plain_literal(a[0]) or not a[0].startswith('"/') for a in args):
                    continue
                paths = [a[0][1:-1] for a in args]
                servlet = None
                if native and len(paths) == 2:
                    servlet = paths.pop()
                if native and len(paths) != 1:
                    continue
                if access == "permitAll":
                    public.extend((path, method, servlet, loc, len(protected)) for path in paths)
                    continue
                for earlier, verb, mount, location, prior in public:
                    if mount != servlet or (verb and method and verb != method) or location.start_byte in emitted:
                        continue
                    for path in paths:
                        if path == "/**" or not (covers(earlier, path) or covers(path, earlier)):
                            continue
                        overlap = path if covers(earlier, path) else earlier
                        if any(s == mount and (m is None or m == (verb or method)) and covers(p, overlap)
                               for p, m, s in protected[:prior]):
                            continue
                        emitted.add(location.start_byte)
                        yield "route-authorization", location
                        break
                protected.extend((p, method, servlet) for p in paths)


def covers(pattern: str, path: str) -> bool:
    if pattern == path:
        return True
    if pattern.endswith("/**") and "*" not in pattern[:-3]:
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/")
    return False


def disabled_tls(root: Node):
    if not imports(root, "javax.net.ssl."):
        return
    for assignment in walk(root, "assignment"):
        ws = words(assignment)
        if ("hostnameVerifier" in ws and "HostnameVerifier" in ws and
                ws[-3:] == ["->", "true", "}"] and ws.count("{") == 1):
            yield "tls-verification", assignment
    for call in walk(root, "call_expression"):
        callee = words(call.named_children[0])
        if callee[-1:] not in (["setHostnameVerifier"], ["setDefaultHostnameVerifier"]):
            continue
        lambdas = list(walk(call, "lambda_literal"))
        if len(lambdas) == 1:
            body = words(lambdas[0])
            if "->" in body and body[body.index("->") + 1:] == ["true", "}"]:
                yield "tls-verification", call
