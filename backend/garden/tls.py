"""Inspect Kotlin hostname and certificate verification in the JSSE API."""
from tree_sitter import Node

from garden.kotlin_checks import kotlin_imports, receiver_has_type, walk, words
from garden.kotlin_types import KotlinTypes


TRUST_MANAGER = "javax.net.ssl.X509TrustManager"
EXTENDED_MANAGER = "javax.net.ssl.X509ExtendedTrustManager"
CERTIFICATE = "java.security.cert.X509Certificate"
CONNECTION_TYPES = {"javax.net.ssl.SSLEngine", "java.net.Socket"}
CERTIFICATE_ERRORS = {"java.security.cert.CertificateException", "java.security.GeneralSecurityException",
                      "java.lang.Exception", "java.lang.Throwable", "kotlin.Exception", "kotlin.Throwable"}
KOTLIN_TYPES = {"kotlin.String", "kotlin.Array", "kotlin.Unit", "kotlin.Exception", "kotlin.Throwable"}
HTTPS_CONNECTION = "javax.net.ssl.HttpsURLConnection"
HOSTNAME_VERIFIER = "javax.net.ssl.HostnameVerifier"


def imported_types(root: Node) -> dict[str, str]:
    known = {TRUST_MANAGER, EXTENDED_MANAGER, CERTIFICATE} | CONNECTION_TYPES | CERTIFICATE_ERRORS | KOTLIN_TYPES
    imports = list(kotlin_imports(root))
    packages = {path[:-2] for path, local in imports if local == "*"}
    names = {path.rsplit(".", 1)[1]: path for path in known if path in KOTLIN_TYPES or path.rsplit(".", 1)[0] in packages}
    names.update({local: path for path, local in imports if local != "*"})
    # A same-file declaration can shadow an import. Evaluating a property
    # called Unit can run a getter, so it is not necessarily a no-op.
    for kind in ("class_declaration", "object_declaration", "type_alias", "type_parameter",
                 "variable_declaration", "class_parameter", "parameter"):
        for decl in walk(root, kind):
            name = decl.child_by_field_name("name") or child(decl, "identifier")
            if name is None:
                continue
            local = name.text.decode()
            if kind not in {"variable_declaration", "class_parameter", "parameter"} or names.get(local) == "kotlin.Unit":
                names.pop(local, None)
    return names


def child(node: Node, kind: str) -> Node | None:
    return next((c for c in node.named_children if c.type == kind), None)


def type_name(parts: list[str], imports: dict[str, str]) -> str:
    if parts[-1:] == ["?"]:
        parts = parts[:-1]
    name = "".join(parts)
    return imports.get(name, name)


def callback_parameters(fun: Node, extended: bool, imports: dict[str, str]) -> list[str] | None:
    params = child(fun, "function_value_parameters")
    if params is None:
        return None
    types, names = [], []
    for param in params.named_children:
        if param.type == "parameter":
            typ = next((c for c in param.named_children if c.type in {"user_type", "nullable_type"}), None)
            if typ is None:
                return None
            names.append(param.named_children[0].text.decode())
            types.append(words(typ))
    if len(types) not in {2, 3} or type_name(types[1], imports) != "kotlin.String":
        return None
    if len(types) == 3 and (not extended or type_name(types[2], imports) not in CONNECTION_TYPES):
        return None
    chain = types[0]
    if chain[-1:] == ["?"]:
        chain = chain[:-1]
    if "<" not in chain or chain[-1:] != [">"]:
        return None
    split = chain.index("<")
    element = chain[split + 1:-1]
    if element[:1] == ["out"]:
        element = element[1:]
    if type_name(chain[:split], imports) == "kotlin.Array" and type_name(element, imports) == CERTIFICATE:
        return names
    return None


def no_validation(body: Node, imports: dict[str, str]) -> bool:
    parts = [p for p in words(body) if p != ";"]
    if parts[:1] == ["="]:
        parts = parts[1:]
    elif parts[:1] == ["{"] and parts[-1:] == ["}"]:
        parts = parts[1:-1]
    if parts[:1] == ["return"]:
        parts = parts[1:]
    return not parts or type_name(parts, imports) == "kotlin.Unit"


def sole_statement(node: Node) -> Node | None:
    children = [c for c in node.named_children if "comment" not in c.type]
    return children[0] if len(children) == 1 else None


def constant_verifier(expr: Node, types: KotlinTypes) -> bool:
    while expr.type in {"value_arguments", "value_argument", "annotated_lambda", "parenthesized_expression", "call_expression"}:
        if expr.type == "call_expression":
            parts = [n for n in expr.named_children if "comment" not in n.type]
            if len(parts) != 2 or types.resolve_expression_name(parts[0]) != HOSTNAME_VERIFIER:
                return False
            expr = parts[1]
        else:
            expr = sole_statement(expr)
            if expr is None:
                return False
    if expr.type != "lambda_literal":
        return False
    body = [c for c in expr.named_children if c.type != "lambda_parameters" and "comment" not in c.type]
    return len(body) == 1 and body[0].text == b"true"


def disabled_tls(root: Node):
    source = root.text
    if b"hostnameVerifier" not in source and b"HostnameVerifier" not in source:
        return
    types = KotlinTypes(root, {HTTPS_CONNECTION, HOSTNAME_VERIFIER})
    for kind in ("assignment", "call_expression"):
        for node in walk(root, kind):
            parts = [c for c in node.named_children if "comment" not in c.type]
            if len(parts) != 2:
                continue
            target, value = parts
            if target.type not in {"identifier", "navigation_expression"}:
                continue
            method = target.named_children[-1] if target.type == "navigation_expression" else target
            if kind == "assignment":
                if method.text != b"hostnameVerifier":
                    continue
            elif method.text not in {b"setHostnameVerifier", b"setDefaultHostnameVerifier"}:
                continue
            if not constant_verifier(value, types):
                continue
            if method.text == b"setDefaultHostnameVerifier":
                if target.type != "navigation_expression" or types.resolve_expression_name(target.named_children[0]) != HTTPS_CONNECTION:
                    continue
            else:
                names = {HTTPS_CONNECTION} | {n for n, path in types.names.items()
                                              if path == HTTPS_CONNECTION and types.resolve(n, node) == path}
                if not receiver_has_type(node, names):
                    continue
            yield "tls-verification", node


def ignored_failure(body: Node, method: Node, parameters: list[str], imports: dict[str, str]) -> Node | None:
    expr = sole_statement(body)
    if expr is not None and expr.type == "block":
        expr = sole_statement(expr)
    if expr is None or expr.type != "try_expression":
        return None
    clauses = [c for c in expr.named_children if "comment" not in c.type]
    if len(clauses) != 2 or clauses[0].type != "block" or clauses[1].type != "catch_block":
        return None
    catch = clauses[1]
    error, recovery = child(catch, "user_type"), child(catch, "block")
    if error is None or type_name(words(error), imports) not in CERTIFICATE_ERRORS:
        return None
    if recovery is None or not no_validation(recovery, imports):
        return None
    call = sole_statement(clauses[0])
    if call is None or call.type != "call_expression":
        return None
    callee, args = call.named_children[0], child(call, "value_arguments")
    if callee.type != "navigation_expression" or callee.named_children[-1].text != method.text or args is None:
        return None
    passed = [words(arg) for arg in args.named_children if arg.type == "value_argument"]
    return catch if passed == [[name] for name in parameters] else None


def manager_bases(specifiers: Node, imports: dict[str, str]) -> set[str]:
    bases = set()
    for spec in specifiers.named_children:
        if spec.type != "delegation_specifier":
            continue
        typ = child(spec, "user_type")
        if typ is None:
            wrapper = next((c for c in spec.named_children if c.type in {"constructor_invocation", "explicit_delegation"}), None)
            typ = child(wrapper, "user_type") if wrapper is not None else None
        if typ is not None:
            bases.add(type_name(words(typ), imports))
    return bases & {TRUST_MANAGER, EXTENDED_MANAGER}


def unchecked_certificates(root: Node):
    imports = None
    for fun in walk(root, "function_declaration"):
        name = fun.child_by_field_name("name")
        if name is None or name.text not in {b"checkServerTrusted", b"checkClientTrusted"}:
            continue
        if fun.parent.type != "class_body":
            continue
        specifiers = child(fun.parent.parent, "delegation_specifiers")
        modifiers, body = child(fun, "modifiers"), child(fun, "function_body")
        if specifiers is None or body is None or modifiers is None or "override" not in words(modifiers):
            continue
        if imports is None:
            imports = imported_types(root)
        bases = manager_bases(specifiers, imports)
        if not bases:
            continue
        params = callback_parameters(fun, EXTENDED_MANAGER in bases, imports)
        if params is None:
            continue
        if no_validation(body, imports):
            yield name, name
        else:
            catch = ignored_failure(body, name, params, imports)
            if catch is not None:
                yield name, catch
