"""Evaluate a bounded subset of Kotlin strings without executing project code."""
import re
from collections.abc import Callable

from tree_sitter import Node


NAME = re.compile(r"(?:[^\W\d]\w*|`[^`]+`)")
ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "b": "\b", "'": "'", '"': '"', "\\": "\\", "$": "$"}


def static_string(node: Node, lookup: Callable[[str, Node], Node | None]) -> str | None:
    # Stop cyclic, deeply nested or exponentially growing constant expressions.
    remaining = 256
    limit = 16384
    cache: dict[Node, str | None] = {}

    def reference(name: str, use: Node, depth: int) -> str | None:
        decl = lookup(name, use)
        if decl is None:
            return None
        if decl not in cache:
            cache[decl] = None
            children = decl.children
            var = next((c for c in children if c.type == "variable_declaration"), None)
            if var is None or (len(var.named_children) > 1 and var.named_children[-1].text not in {b"String", b"kotlin.String"}):
                return None  # An explicitly wider receiver can select an overloaded plus.
            if any(c.type == "val" for c in children) and not any(c.type in {"getter", "property_delegate"} for c in children):
                equals = next((i for i, c in enumerate(children) if c.type == "="), None)
                if equals is not None:
                    rhs = next((c for c in children[equals + 1:] if c.is_named and "comment" not in c.type), None)
                    if rhs is not None:
                        cache[decl] = evaluate(rhs, depth + 1)
        return cache[decl]

    def evaluate(expr: Node, depth: int) -> str | None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 32:
            return None
        children = [c for c in expr.named_children if "comment" not in c.type]
        if expr.type == "identifier":
            return reference(expr.text.decode(), expr, depth)
        if expr.type == "parenthesized_expression" and len(children) == 1:
            return evaluate(children[0], depth + 1)
        if expr.type == "binary_expression" and len(children) == 2 and any(c.type == "+" for c in expr.children):
            left, right = (evaluate(c, depth + 1) for c in children)
            if left is not None and right is not None and len(left) + len(right) <= limit:
                return left + right
            return None
        if expr.type not in {"string_literal", "multiline_string_literal"} or expr.end_byte - expr.start_byte > limit:
            return None
        parts, size = [], 0
        contents = iter(children)
        for c in contents:
            value = c.text.decode()
            if c.type == "interpolation":
                if re.fullmatch(r"\$\{\s*'\$'\s*\}", value):
                    value = "$"
                elif c.named_child_count == 1:
                    value = evaluate(c.named_children[0], depth + 1)
                else:
                    return None
            elif c.type == "escape_sequence":
                value = chr(int(value[2:], 16)) if re.fullmatch(r"\\u[\da-fA-F]{4}", value) else ESCAPES.get(value[1:])
            elif c.type == "string_content" and value == "$":
                # The grammar exposes unbraced $name as consecutive content nodes.
                following = next(contents, None)
                if following is not None:
                    if following.type != "string_content":
                        return None
                    tail = following.text.decode()
                    match = NAME.match(tail)
                    if match:
                        resolved = reference(match[0], c, depth)
                        value = resolved + tail[match.end():] if resolved is not None else None
                    elif tail == "$":
                        return None
                    else:
                        value += tail
            elif c.type != "string_content":
                return None
            if value is None or size + len(value) > limit:
                return None
            parts.append(value)
            size += len(value)
        return "".join(parts)

    return evaluate(node, 0)
