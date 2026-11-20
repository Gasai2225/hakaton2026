import re
from collections import defaultdict

import yaml
from tree_sitter import Node

from garden.kotlin_checks import auth_constants, credential_fallback, kotlin_imports, owner, plain_literal, walk, words
from garden.models import Source
from garden.properties import property_entries


SECRET_NAME = re.compile(r"(?:password|passwd|secret|api[_-]?key|token|authorization)$", re.I)
PLACEHOLDER = re.compile(r"\$\{[\w.-]+([:}])")


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
    for doc in yaml_documents(source):
        pending, visited = [doc], set()
        while pending:
            node = pending.pop()
            if id(node) in visited:
                continue
            visited.add(id(node))
            if isinstance(node, yaml.SequenceNode):
                pending.extend(reversed(node.value))
            elif isinstance(node, yaml.MappingNode):
                for key, value in node.value:
                    if isinstance(key, yaml.ScalarNode) and isinstance(value, yaml.ScalarNode):
                        if value.tag in {"tag:yaml.org,2002:str", "tag:yaml.org,2002:int", "tag:yaml.org,2002:float"}:
                            yield key.value, value.value, key.start_mark.line + 1, key.start_mark.column + 1
                    else:
                        pending.append(value)


def config_secrets(source: Source):
    settings = property_entries(source.text) if source.path.endswith(".properties") else yaml_settings(source)
    for name, value, line, column in settings:
        classification = setting_secret(name, value)
        if classification:
            yield line, column, classification


def setting_secret(name: str, value: str) -> str | None:
    if not SECRET_NAME.search(name):
        return None
    classification = name_class(name)
    start, end = 0, len(value)
    while start < end and value[end - 1] == "}":
        match = PLACEHOLDER.match(value, start, end)
        if not match or (match[1] == "}" and match.end() != end):
            break
        start, end = match.end(), end - 1
        classification = "secret-fallback"
    value = value[start:end].strip()
    if value and "${" not in value and value not in {"null", "~", '""', "''"}:
        return classification
    return None


def spring_value_secrets(root: Node):
    qualified = "org.springframework.beans.factory.annotation.Value"
    names = {qualified}
    for item in walk(root, "import"):
        imported = "".join(words(item.named_children[0]))
        if imported == qualified:
            names.add(words(item)[-1])
    for annotation in walk(root, "annotation"):
        call = next((c for c in annotation.named_children if c.type == "constructor_invocation"), None)
        if not call or "".join(words(call.named_children[0])) not in names:
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
        if match and setting_secret(match[1], value) == "secret-fallback":
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
    jdk_system = not any(name == "System" and path != "java.lang.System" for path, name in kotlin_imports(root))
    jdk_system = jdk_system and all(n.parent.type in {"import", "navigation_expression", "qualified_identifier", "user_type"}
                                    for n in refs[b"System"])
    return refs, jdk_system


def only_env_lookup(prop: Node, identifier: Node, refs: dict, jdk_system: bool) -> bool:
    scope = prop.parent
    if scope.type not in {"block", "lambda_literal"}:
        modifiers = next((c for c in prop.named_children if c.type == "modifiers"), None)
        if not modifiers or "private" not in words(modifiers):
            return False  # Other source files can read this value.
        scope = owner(prop, "source_file")
    uses = [n for n in refs[identifier.text.strip(b"`")]
            if n != identifier and scope.start_byte <= n.start_byte < scope.end_byte]
    for use in uses:
        arg = use.parent
        if use.type != "identifier" or arg.type != "value_argument" or arg.named_children != [use]:
            return False
        args = arg.parent
        call = args.parent
        if call.type != "call_expression" or args.named_children != [arg]:
            return False
        callee = words(call.named_children[0])
        if callee != ["java", ".", "lang", ".", "System", ".", "getenv"] and not (jdk_system and callee == ["System", ".", "getenv"]):
            return False
    return bool(uses)


def kotlin_secrets(root: Node):
    declarations = {}
    references = None
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
            if not SECRET_NAME.search(name):
                continue
            rhs = next((c for c in prop.children[equals+1:] if c.is_named and "comment" not in c.type), None)
            if rhs is None:
                continue
            expr = words(rhs)
            if len(expr) == 1 and plain_literal(expr[0]) and expr[0].strip('"').strip():
                if (kind == "property_declaration" and any(c.type == "val" for c in prop.children)
                        and re.fullmatch(r'"[A-Za-z_][A-Za-z_0-9]*"', expr[0])):
                    if references is None:
                        references = name_references(root)
                    if only_env_lookup(prop, name_node, *references):
                        continue
                classification = name_class(name)
            elif credential_fallback(expr):
                classification = "secret-fallback"
            elif (len(expr) >= 3 and len(expr) % 2 and all(op == "+" for op in expr[1::2])
                  and all(plain_literal(token) for token in expr[::2])):
                classification = "recoverable-token"
            else:
                continue
            declarations[prop.start_byte] = classification, name_node
    for classification, node in auth_constants(root):
        declarations.setdefault(node.start_byte, (classification, node))
    yield from declarations.values()
    yield from spring_value_secrets(root)
