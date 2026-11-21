"""Resolve known Kotlin type names from imports and visible declarations."""
from collections.abc import Collection, Mapping
from functools import cached_property

from tree_sitter import Node

from garden.kotlin_checks import kotlin_imports, walk, words


def package(root: Node) -> str:
    header = next((c for c in root.named_children if c.type == "package_header"), None)
    return "".join(words(header)[1:]) if header else ""


def top_level_names(root: Node):
    for decl in root.named_children:
        name = decl.child_by_field_name("name")
        if decl.type == "property_declaration":
            variable = next((c for c in decl.named_children if c.type == "variable_declaration"), None)
            name = variable.named_children[0] if variable else None
        if decl.type not in {"function_declaration", "class_declaration", "object_declaration", "type_alias", "property_declaration"} or not name:
            continue
        modifiers = next((c for c in decl.named_children if c.type == "modifiers"), None)
        yield name.text, bool(modifiers and "private" in words(modifiers))


class KotlinTypes:
    def __init__(self, root: Node, known: Collection[str], defaults: Mapping[str, str] | None = None,
                 same_package: Mapping[str, str] | None = None):
        self.root = root
        self.names = dict(defaults or {})
        imports = list(kotlin_imports(root))
        packages = {path[:-2] for path, local in imports if local == "*"}
        stars: dict[str, set[str]] = {}
        for path in known:
            package, _, short = path.rpartition(".")
            if package in packages:
                stars.setdefault(short, set()).add(path)
        for name, options in stars.items():
            self.names[name] = next(iter(options)) if len(options) == 1 else ""
        if same_package:
            self.names.update(same_package)
        self.names.update({local: path for path, local in imports if local != "*"})
        self.shadows = set()
        for kind in ("class_declaration", "object_declaration", "type_alias", "type_parameter"):
            for decl in walk(root, kind):
                name = decl.child_by_field_name("name") or next((c for c in decl.named_children if c.type == "identifier"), None)
                if name is not None:
                    if (kind == "class_declaration" and decl.parent == root and same_package
                            and name.text.decode() in same_package):
                        self.names[name.text.decode()] = same_package[name.text.decode()]
                        continue
                    scope = decl.parent.parent if kind == "type_parameter" else decl.parent
                    self.shadows.add((scope, name.text.decode()))

    def resolve(self, name: str, use: Node) -> str:
        if "." in name:
            return name
        while use is not None:
            if (use, name) in self.shadows:
                return ""
            use = use.parent
        return self.names.get(name, "")

    @cached_property
    def value_scopes(self):
        declarations = {}
        scopes = {"source_file", "class_body", "block", "lambda_literal", "class_declaration",
                  "function_declaration", "anonymous_function", "catch_block", "for_statement"}
        for kind in ("variable_declaration", "parameter", "class_parameter", "function_declaration", "catch_block"):
            for node in walk(self.root, kind):
                name = node.child_by_field_name("name") or next((c for c in node.named_children if c.type == "identifier"), None)
                if name is None:
                    continue
                scope = node if kind == "catch_block" else node.parent
                while scope and scope.type not in scopes:
                    scope = scope.parent
                if scope:
                    start = (node.parent.end_byte if node.parent.type == "property_declaration"
                             and scope.type in {"block", "lambda_literal"} else scope.start_byte)
                    declarations.setdefault(name.text.decode(), []).append((start, scope.end_byte))
        return declarations

    def resolve_expression_name(self, expr: Node) -> str:
        name = "".join(words(expr))
        first = name.partition(".")[0]
        if any(start <= expr.start_byte < end for start, end in self.value_scopes.get(first, ())):
            return ""
        return self.resolve(name, expr)
