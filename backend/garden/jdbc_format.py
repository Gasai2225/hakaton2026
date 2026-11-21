"""Resolve text substitutions in a statically known Kotlin/JVM format string."""
import re

from tree_sitter import Node


SPECIFIER = re.compile(
    r"%(?:([1-9][0-9]{0,8})\$)?([-<0]{0,3})([1-9][0-9]{0,8})?"
    r"(?:\.([0-9]{1,9}))?([sSbBhHdoxXcCeEfgGaA])"
)
ESCAPES = {b"\\$": "$", b"\\\\": "\\", b'\\"': '"', b"\\'": "'", b"\\t": "\t", b"\\r": "\r", b"\\n": "\n", b"\\b": "\b"}


def static_string(literal: Node) -> str | None:
    parts = []
    for child in literal.named_children:
        if child.type == "string_content" and child.text != b"$":
            parts.append(child.text.decode())
        elif child.type == "escape_sequence" and child.text in ESCAPES:
            parts.append(ESCAPES[child.text])
        elif child.type == "interpolation" and child.text == b"${'$'}":
            parts.append("$")
        else:
            return None
    return "".join(parts)


def text_slots(pattern: str, count: int, string_args: set[int]) -> set[int] | None:
    """Ordinary indexing advances independently of explicit and relative indexing."""
    selected = set()
    ordinary, previous, offset = 0, -1, 0
    while (start := pattern.find("%", offset)) != -1:
        if pattern.startswith(("%%", "%n"), start):
            offset = start + 2
            continue
        match = SPECIFIER.match(pattern, start)
        if match is None:
            return None
        index, flags, width, precision, conversion = match.groups()
        if len(set(flags)) != len(flags) or ("-" in flags and not width):
            return None
        if "0" in flags and (not width or "-" in flags or conversion in "sSbBhHcC"):
            return None
        if precision is not None and conversion in "doxXcC":
            return None
        if "<" in flags:
            if index is not None:
                return None
        elif index:
            previous = int(index) - 1
        else:
            previous = ordinary
            ordinary += 1
        if not 0 <= previous < count:
            return None
        if previous in string_args and conversion not in "sSbBhH":
            return None  # Formatter rejects a String for a numeric or character conversion.
        if conversion in "sS" and (precision is None or int(precision) > 0):
            selected.add(previous)
        offset = match.end()
    return selected
