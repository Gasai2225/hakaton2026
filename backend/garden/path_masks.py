"""Filename masks used by scanner nodes, relative to the project root."""

import re
from collections.abc import Iterator
from fnmatch import fnmatchcase


def split_outside_classes(expression: str, separator: str) -> Iterator[str]:
    start = 0
    for token in re.finditer(r"\[!?\]?[^\]]*\]|(" + separator + ")", expression):
        if token[1] is not None:
            yield expression[start:token.start()]
            start = token.end()
    yield expression[start:]


def parse_masks(expression: str) -> tuple[list[str], list[str]]:
    includes, excludes = [], []
    # A comma inside a shell character class, such as "[,]", is literal.
    for item in split_outside_classes(expression, ","):
        mask = item.strip()
        exclude = mask.startswith("!")
        if exclude:
            mask = mask[1:].strip()
        if not mask:
            raise ValueError("Укажите маску пути в каждом элементе списка")
        (excludes if exclude else includes).append(mask)
    return includes or ["*"], excludes


def matches_mask(path: str, mask: str) -> bool:
    if "**/" not in mask:
        return fnmatchcase(path, mask)
    sections = list(split_outside_classes(mask, r"(?<![^/])\*\*/"))
    for index, section in enumerate(sections[:-1]):
        if not section:
            continue
        # The next globstar can consume any remaining directories, so the first
        # matching directory boundary suffices. Single stars keep fnmatch semantics.
        for slash in re.finditer("/", path):
            prefix = path[:slash.end()]
            if fnmatchcase(prefix, section) or (index and fnmatchcase(prefix, "*/" + section)):
                path = path[slash.end():]
                break
        else:
            return False
    tail = sections[-1]
    return fnmatchcase(path, tail) or (len(sections) > 1 and fnmatchcase(path, "*/" + tail))


def matches_any(path: str, masks: list[str]) -> bool:
    return any(matches_mask(path, mask) for mask in masks)
