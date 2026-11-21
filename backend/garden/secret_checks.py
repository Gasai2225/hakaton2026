import re
from collections import defaultdict

import yaml
from tree_sitter import Node

from garden.db_secrets import DB_FIELDS, DB_SECTIONS, config_name, database_settings, kotlin_database_secrets
from garden.kotlin_checks import (auth_constants, call_arguments, credential_fallback, credential_literal,
                                  owner, receiver_has_type, walk, words)
from garden.kotlin_types import KotlinTypes
from garden.models import Source
from garden.properties import decode_property_value, property_entries
from garden.user_passwords import spring_user_passwords


SECRET_NAME = re.compile(r"(?:password|passwd|secret|api[_-]?key|token|authorization)$", re.I)
PLACEHOLDER_PARTS = re.compile(r"(\$\{[\w.-]+:|\$\{|[{}])")
STATUS_URI = re.compile(r'"https://[\w.-]+(?::\d+)?/(?:(?:actuator|monitor|monitoring)/)?(?:status|healthz?|readyz|livez)/?"')
LOG_LEVELS = {"OFF", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"}
JDK_SYSTEM = "java.lang.System"
JDK_PROPERTIES = "java.util.Properties"
SPRING_RESOLVERS = {"org.springframework.core.env." + name for name in (
    "PropertyResolver", "ConfigurablePropertyResolver", "Environment", "ConfigurableEnvironment",
    "StandardEnvironment", "PropertySourcesPropertyResolver",
)}
YAML_SECTIONS = DB_SECTIONS | {"logging", "logging.level", "jobs", "jobs.*", "permissions", "jobs.*.permissions"}
LOOKUP_OWNERS = {
    b"getString": "java.util.ResourceBundle",
    **dict.fromkeys((b"findLibrary", b"findPlugin", b"findBundle", b"findVersion"), "org.gradle.api.artifacts.VersionCatalog"),
}


def name_class(name: str) -> str:
    name = name.lower()
    if name.endswith(("password", "passwd")):
        return "password"
    if name.endswith(("token", "authorization")):
        return "configuration-token"
    if re.search(r"api[_-]?key$", name):
        return "api-key"
    return "embedded-secret"


def yaml_documents(source: Source):
    try:
        yield from yaml.compose_all(source.text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError) as error:
        raise ValueError(f"Не удалось разобрать YAML в {source.path}") from error


def yaml_settings(source: Source):
    actions = source.path.rsplit("/", 1)[0] == ".github/workflows"
    for doc in yaml_documents(source):
        pending, visited = [(doc, "")], set()
        while pending:
            node, section = pending.pop()
            if (id(node), section) in visited:
                continue
            visited.add((id(node), section))
            if isinstance(node, yaml.SequenceNode):
                pending.extend((item, None) for item in reversed(node.value))
            elif isinstance(node, yaml.MappingNode):
                for key, value in node.value:
                    segment = key.value if isinstance(key, yaml.ScalarNode) else ""
                    path = config_name(f"{section}.{segment}".lstrip(".")) if section is not None else None
                    if isinstance(key, yaml.ScalarNode) and isinstance(value, yaml.ScalarNode):
                        if value.tag in {"tag:yaml.org,2002:str", "tag:yaml.org,2002:int", "tag:yaml.org,2002:float"}:
                            if (actions and section in {"permissions", "jobs.*.permissions"} and segment == "id-token"
                                    and value.value in {"none", "write"}):
                                continue
                            qualified = path in DB_FIELDS or (path or "").startswith("logging.level.")
                            name = path if qualified else segment.rsplit(".", 1)[-1]
                            yield name, value.value, key.start_mark.line + 1, key.start_mark.column + 1
                    else:
                        if section == "logging.level":
                            path = section
                        elif section == "jobs" and actions:
                            path = "jobs.*"
                        pending.append((value, path if path in YAML_SECTIONS else None))


def config_secrets(source: Source):
    properties = source.path.endswith(".properties")
    settings = property_entries(source.text) if properties else yaml_settings(source)
    hits = set()
    for name, value, line, column in settings:
        if properties:
            value = decode_property_value(value)
        key = config_name(name)
        classification = database_settings(key, value, static_default) if key in DB_FIELDS else setting_secret(name, value)
        if classification:
            hits.add((line, column, classification))
    yield from sorted(hits)


def static_default(value: str) -> str | None:
    """Return the complete value obtainable when no external properties are set."""
    if "#{" in value or r"\${" in value:
        return None
    output, braces = [], []
    for part in PLACEHOLDER_PARTS.split(value):
        if part == "${":
            return None  # A required property or a dynamic property name.
        if part.startswith("${"):
            braces.append(True)
        elif part == "{":
            braces.append(False)
            output.append(part)
        elif part == "}" and braces:
            if not braces.pop():
                output.append(part)
        else:
            output.append(part)
    return None if any(braces) else "".join(output)


def setting_secret(name: str, value: str) -> str | None:
    if not SECRET_NAME.search(name):
        return None
    classification = name_class(name)
    if "${" in value:
        value = static_default(value)
        if value is None:
            return None
        classification = "secret-fallback"
    value = value.strip()
    if name.lower().startswith("logging.level.") and value.upper() in LOG_LEVELS:
        return None
    if name.lower().endswith("authorization") and value.lower() in {"basic", "bearer"}:
        return None
    return classification if value and value not in {"null", "~", '""', "''"} else None


def spring_value_secrets(root: Node):
    qualified = "org.springframework.beans.factory.annotation.Value"
    if b"Value" not in root.text:
        return
    types = KotlinTypes(root, {qualified})
    for annotation in walk(root, "annotation"):
        call = next((c for c in annotation.named_children if c.type == "constructor_invocation"), None)
        if not call or types.resolve("".join(words(call.named_children[0])), annotation) != qualified:
            continue
        args = words(call.named_children[-1])
        if args[1:3] == ["value", "="]:
            args = [args[0], *args[3:]]
        if len(args) != 3 or args[0] != "(" or args[2] != ")":
            continue
        literal = args[1]
        if not (literal.startswith('"') and literal.endswith('"')):
            continue
        raw = literal.startswith('"""')
        body = literal[3:-3] if raw else literal[1:-1]
        # Only Kotlin's constant dollar forms can expand to a Spring placeholder.
        constant = r"(?:[^$]|\$\{'\$'\})*" if raw else r"(?:[^$\\]|\\\$|\$\{'\$'\})*"
        if not re.fullmatch(constant, body) or "#{" in body:
            continue
        value = body.replace("${'$'}", "$")
        if not raw:
            value = value.replace(r"\$", "$")
        match = re.fullmatch(r"\$\{([\w.-]+):[\s\S]*\}", value)
        if not match:
            continue
        key = config_name(match[1])
        result = database_settings(key, value, static_default) if key in DB_FIELDS else setting_secret(match[1], value)
        if result == "secret-fallback":
            yield "secret-fallback", annotation


def name_references(root: Node):
    refs = defaultdict(list)
    for node in walk(root, "identifier"):
        refs[node.text.strip(b"`")].append(node)
    # The Kotlin grammar stores an unbraced $name as string content.
    for kind in ("string_literal", "multiline_string_literal"):
        for literal in walk(root, kind):
            for name in set(re.findall(rb"\$(\w+|`[^`]+`)", literal.text)):
                refs[name.strip(b"`")].append(literal)
    return refs, KotlinTypes(root, {JDK_SYSTEM, JDK_PROPERTIES, *SPRING_RESOLVERS, *LOOKUP_OWNERS.values()},
                             {"System": JDK_SYSTEM})


def jdk_system_method(call: Node, types: KotlinTypes) -> str | None:
    callee = call.named_children[0]
    if callee.type == "navigation_expression" and types.resolve_expression_name(callee.named_children[0]) == JDK_SYSTEM:
        return callee.named_children[-1].text.decode()
    return None


def reads_property_key(call: Node, args: list[Node], types: KotlinTypes) -> bool:
    callee = call.named_children[0]
    if callee.type != "navigation_expression":
        return False
    method = callee.named_children[-1].text
    count = len(args)
    if method in {b"getenv", b"getProperty"} and jdk_system_method(call, types):
        return count == 1 or (method == b"getProperty" and count == 2)
    if count == 1 and method in LOOKUP_OWNERS:
        owners = {LOOKUP_OWNERS[method]}
    elif method == b"getProperty" and count in (1, 2):
        owners = SPRING_RESOLVERS | {JDK_PROPERTIES}
    elif count == 1 and method in {b"getRequiredProperty", b"containsProperty"}:
        owners = SPRING_RESOLVERS
    elif ((method == b"getRequiredProperty" and count == 2) or (method == b"getProperty" and count == 3)):
        target = words(args[1])
        if len(target) < 5 or target[-4:-1] != ["::", "class", "."] or target[-1] not in {"java", "javaObjectType"}:
            return False
        owners = SPRING_RESOLVERS
    else:
        return False
    names = {name for name in types.names if types.resolve(name, call) in owners}
    return receiver_has_type(call, names | owners)


def lookup_key_uses(prop: Node, identifier: Node, refs: dict, types: KotlinTypes) -> list[Node]:
    scope = prop.parent
    if scope.type not in {"block", "lambda_literal"}:
        modifiers = next((c for c in prop.named_children if c.type == "modifiers"), None)
        if not modifiers or "private" not in words(modifiers):
            return []  # Other source files can read this value.
        scope = owner(prop, "source_file")
    uses = [n for n in refs[identifier.text.strip(b"`")]
            if n != identifier and scope.start_byte <= n.start_byte < scope.end_byte]
    for use in uses:
        arg = use.parent
        if use.type != "identifier" or arg.type != "value_argument" or arg.named_children != [use]:
            return []
        args = arg.parent
        call = args.parent
        arguments = [c for c in args.named_children if c.type == "value_argument"]
        if call.type != "call_expression" or not arguments or arguments[0] != arg or not reads_property_key(call, arguments, types):
            return []
    return uses


def jvm_property_defaults(root: Node, known_keys: set[int], references):
    for call in walk(root, "call_expression"):
        callee = call.named_children[0]
        if callee.type != "navigation_expression" or callee.named_children[-1].text != b"getProperty":
            continue
        args = next((c for c in call.named_children if c.type == "value_arguments"), None)
        values = [n for n in args.named_children if n.type == "value_argument"] if args else []
        if len(values) not in (2, 3):
            continue
        key, default = words(values[0]), words(values[-1])
        if len(default) != 1 or not credential_literal(default[0]) or not default[0].strip('"').strip():
            continue
        if values[0].start_byte not in known_keys and not (len(key) == 1 and re.fullmatch(r'"[\w.-]+"', key[0])
                                                           and SECRET_NAME.search(key[0][1:-1])):
            continue
        if references is None:
            references = name_references(root)
        if reads_property_key(call, values, references[1]):
            yield call


def status_read_fallback(location: Node, root: Node) -> bool:
    """Lower the baseline only for a local status token used solely by a known health GET."""
    decl = owner(location, "property_declaration")
    if decl is None or decl.parent.type != "block":
        return False
    var = next((n for n in decl.named_children if n.type == "variable_declaration"), None)
    if var is None or not any(n.type == "val" for n in decl.children):
        return False
    rhs = words(decl.named_children[-1])
    if rhs[:4] == ["java", ".", "lang", "."]:
        rhs = rhs[4:]
    if len(rhs) != 8 or rhs[:4] != ["System", ".", "getenv", "("] or rhs[5:7] != [")", "?:"]:
        return False
    if not re.fullmatch(r'"[A-Za-z_][\w.-]*"', rhs[4]):
        return False
    purpose = re.split(r"[_\-.]", rhs[4].strip('"').lower())
    if purpose[-1] != "token" or not {"health", "status", "readiness", "liveness"}.intersection(purpose):
        return False
    if {"admin", "root", "write"}.intersection(purpose):
        return False
    name = var.named_children[0].text.decode()
    # A second use could exercise wider privileges. Unrelated statements do not affect the observed use.
    reference = re.compile(r"(?<!\w)" + re.escape(name) + r"(?!\w)")
    uses = [n for n in decl.parent.named_children if n.start_byte > decl.end_byte and "comment" not in n.type
            and reference.search(n.text.decode())]
    if len(uses) != 1 or uses[0].type != "return_expression" or not uses[0].named_children:
        return False
    call = uses[0].named_children[-1]
    has_header = False
    if call.type != "call_expression" or words(call)[-4:] != [".", "build", "(", ")"]:
        return False
    while call.type == "call_expression":
        nav = call.named_children[0]
        if nav.type != "navigation_expression":
            return False
        receiver, method = nav.named_children[0], nav.named_children[-1].text
        args = call_arguments(call)
        if method == b"newBuilder":
            if (not has_header or len(args) != 1 or len(args[0]) < 4 or args[0][-3] != "("
                    or args[0][-1] != ")" or not STATUS_URI.fullmatch(args[0][-2])):
                return False
            types = KotlinTypes(root, {"java.net.http.HttpRequest", "java.net.URI", JDK_SYSTEM}, {"System": JDK_SYSTEM})
            getenv = next(walk(decl.named_children[-1], "call_expression"), None)
            uri_type = args[0][:-3]
            if uri_type[-2:] == [".", "create"]:
                uri_type = uri_type[:-2]
            return (types.resolve("".join(words(receiver)), call) == "java.net.http.HttpRequest"
                    and types.resolve("".join(uri_type), call) == "java.net.URI"
                    and getenv is not None and jdk_system_method(getenv, types) == "getenv")
        if method == b"header":
            if len(args) != 2 or len(args[0]) != 1 or args[0][0].lower() != '"authorization"':
                return False
            if has_header or args[1] not in ([f'"Bearer ${name}"'], ['"Bearer ${' + name + '}"']):
                return False
            has_header = True
        elif method not in {b"build", b"GET"} or args:
            return False
        call = receiver
    return False


def http_header_checker(root: Node):
    request = "java.net.http.HttpRequest"
    builder = request + ".Builder"
    rest = "org.springframework.web.client.RestClient"
    types = KotlinTypes(root, {request, builder, rest})
    request_aliases = {name for name, path in types.names.items() if path == request}
    builder_aliases = {name for name, path in types.names.items() if path == builder}
    shadows = set()
    for kind in ("parameter", "class_parameter", "variable_declaration"):
        for decl in walk(root, kind):
            name = next((n.text.decode() for n in decl.named_children if n.type == "identifier"), None)
            if name not in request_aliases and types.names.get(name) != rest:
                continue
            scope = decl.parent
            while scope is not None and scope.type not in {"source_file", "function_declaration", "class_declaration",
                                                           "class_body", "block", "lambda_literal"}:
                scope = scope.parent
            shadows.add((scope, name))

    def static_owner(base: Node, call: Node, expected: str) -> bool:
        name = "".join(words(base))
        if types.resolve(name, call) != expected:
            return False
        scope = call
        while scope is not None:
            if (scope, name) in shadows:
                return False
            scope = scope.parent
        return True

    def factory(call: Node, depth: int) -> bool:
        nav = call.named_children[0]
        if nav.type != "navigation_expression":
            return False
        base, method = nav.named_children[0], nav.named_children[-1].text
        if method == b"newBuilder":
            return static_owner(base, call, request)
        return method in {b"header", b"headers", b"setHeader", b"copy", b"uri", b"version", b"timeout", b"expectContinue",
                          b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"method"} and is_builder(call, depth)

    def is_builder(call: Node, depth: int = 0) -> bool:
        names = {builder} | {n for n in builder_aliases if types.resolve(n, call) == builder}
        names.update(n + ".Builder" for n in request_aliases if types.resolve(n, call) == request)
        return receiver_has_type(call, names, depth, factory=factory)

    def rest_factory(call: Node, depth: int) -> bool:
        nav = call.named_children[0]
        if nav.type != "navigation_expression":
            return False
        base, method = nav.named_children[0], nav.named_children[-1].text
        if method == b"create":
            return static_owner(base, call, rest)
        if method != b"build":
            return False
        while base.type == "call_expression":
            nav = base.named_children[0]
            if nav.type != "navigation_expression":
                break
            base = nav.named_children[0]
            if nav.named_children[-1].text == b"builder":
                return static_owner(base, nav, rest)
            if nav.named_children[-1].text not in {b"baseUrl", b"defaultHeader", b"requestFactory", b"apply"}:
                break
        return False

    def valid_header(call: Node) -> bool:
        if is_builder(call):
            return True
        nav = call.named_children[0]
        if nav.type != "navigation_expression" or nav.named_children[-1].text != b"header":
            return False
        receiver = nav.named_children[0]
        while receiver.type == "call_expression":
            nav = receiver.named_children[0]
            if nav.type != "navigation_expression":
                break
            method = nav.named_children[-1].text
            if method in {b"get", b"post", b"put", b"patch", b"delete", b"head", b"options", b"method"}:
                names = {rest} | {name for name in types.names if types.resolve(name, receiver) == rest}
                return receiver_has_type(receiver, names, factory=rest_factory)
            if method not in {b"uri", b"header", b"accept", b"body", b"contentType", b"attribute"}:
                break
            receiver = nav.named_children[0]
        return False

    return valid_header


def kotlin_secrets(root: Node):
    declarations = {}
    property_keys = set()
    references = None
    reads_defaults = b"getProperty" in root.text
    for kind in ("property_declaration", "class_parameter"):
        for prop in walk(root, kind):
            equals = next((i for i, c in enumerate(prop.children) if c.type == "="), None)
            if equals is None:
                continue
            variable = next((c for c in prop.named_children if c.type in {"variable_declaration", "identifier"}), None)
            if variable is None:
                continue
            name_node = variable if variable.type == "identifier" else variable.named_children[0]
            name = name_node.text.decode().strip(chr(96))
            sensitive = SECRET_NAME.search(name)
            if not sensitive and (kind != "property_declaration" or not reads_defaults):
                continue
            rhs = next((c for c in prop.children[equals+1:] if c.is_named and "comment" not in c.type), None)
            if rhs is None or (not sensitive and rhs.type != "string_literal"):
                continue
            expr = words(rhs)
            if (kind == "property_declaration" and len(expr) == 1 and re.fullmatch(r'"[A-Za-z_][\w.-]*"', expr[0])
                    and (sensitive or SECRET_NAME.search(expr[0][1:-1])) and any(c.type == "val" for c in prop.children)):
                if references is None:
                    references = name_references(root)
                uses = lookup_key_uses(prop, name_node, *references)
                if uses:
                    if SECRET_NAME.search(expr[0][1:-1]):
                        property_keys.update(use.parent.start_byte for use in uses)
                    continue
            if not sensitive:
                continue
            if len(expr) == 1 and credential_literal(expr[0]) and expr[0].strip('"').strip():
                classification = name_class(name)
            elif credential_fallback(expr):
                classification = "secret-fallback"
            elif (len(expr) >= 3 and len(expr) % 2 and all(op == "+" for op in expr[1::2])
                  and all(credential_literal(token) for token in expr[::2])):
                classification = "recoverable-token"
            else:
                continue
            declarations[prop.start_byte] = classification, name_node
    for classification, node in auth_constants(root, http_header_checker):
        declarations.setdefault(node.start_byte, (classification, node))
    for call in jvm_property_defaults(root, property_keys, references):
        declaration = call.parent if call.parent.type in {"property_declaration", "class_parameter"} else call
        declarations.setdefault(declaration.start_byte, ("secret-fallback", call))
    for classification, node in kotlin_database_secrets(root, static_default):
        declarations.setdefault(node.start_byte, (classification, node))
    yield from declarations.values()
    yield from spring_value_secrets(root)
    yield from spring_user_passwords(root)
