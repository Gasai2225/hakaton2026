"""Find plaintext account passwords passed to Spring Security's UserBuilder."""
from collections.abc import Iterator

from tree_sitter import Node

from garden.kotlin_checks import credential_literal, receiver_has_type, walk, words
from garden.kotlin_types import KotlinTypes


USER = "org.springframework.security.core.userdetails.User"
BUILDER = USER + ".UserBuilder"
FACTORIES = {b"builder": 0, b"withUsername": 1, b"withUserDetails": 1, b"withDefaultPasswordEncoder": 0}
FLUENT = {b"username", b"roles", b"authorities", b"accountExpired", b"accountLocked", b"disabled", b"credentialsExpired"}


def spring_user_passwords(root: Node) -> Iterator[tuple[str, Node]]:
    source = root.text
    if b"password" not in source or b"userdetails" not in source:
        return
    types = KotlinTypes(root, {USER, BUILDER})
    user_names = {n for n, path in types.names.items() if path == USER}
    shadowed = []
    for kind in ("variable_declaration", "parameter", "class_parameter"):
        for decl in walk(root, kind):
            name = next((n.text.decode() for n in decl.named_children if n.type == "identifier"), "")
            if name not in user_names:
                continue
            scope = decl.parent
            while scope and scope.type not in {"block", "lambda_literal", "function_declaration", "class_body",
                                               "class_declaration", "source_file"}:
                scope = scope.parent
            if scope:
                start = decl.end_byte if kind == "variable_declaration" and scope.type == "block" else scope.start_byte
                shadowed.append((name, start, scope.end_byte))

    for call in walk(root, "call_expression"):
        nav = call.named_children[0]
        if nav.type != "navigation_expression" or nav.named_children[-1].text != b"password":
            continue
        args = next((c for c in call.named_children if c.type == "value_arguments"), None)
        values = [c for c in args.named_children if c.type == "value_argument"] if args else []
        if len(values) != 1:
            continue
        arg = next((c for c in values[0].named_children if "comment" not in c.type), None)
        if arg is None or arg.type not in {"string_literal", "multiline_string_literal"}:
            continue
        literal = arg.text.decode()
        quotes = 3 if arg.type == "multiline_string_literal" else 1
        content = literal[quotes:-quotes]
        if not credential_literal(literal) or not content.removeprefix("{noop}").strip():
            continue
        noop = content.startswith("{noop}")
        builder_names = {BUILDER} if noop else set()
        if noop:
            builder_names.update(n for n in types.names if types.resolve(n, call) == BUILDER)
            builder_names.update(n + ".UserBuilder" for n in user_names if types.resolve(n, call) == USER)

        def builder_factory(site: Node, depth: int) -> bool:
            invoked = site.named_children[0]
            if invoked.type != "navigation_expression":
                return False
            base, method = invoked.named_children[0], invoked.named_children[-1].text
            if method in FACTORIES:
                name = "".join(words(base))
                args = next((c for c in site.named_children if c.type == "value_arguments"), None)
                if args is None or sum(c.type == "value_argument" for c in args.named_children) != FACTORIES[method]:
                    return False
                return ((noop or method == b"withDefaultPasswordEncoder") and types.resolve(name, site) == USER and
                        not any(n == name and start <= site.start_byte < end for n, start, end in shadowed))
            return method in FLUENT and receiver_has_type(site, builder_names, depth, factory=builder_factory)

        if receiver_has_type(call, builder_names, factory=builder_factory):
            yield "password", arg
