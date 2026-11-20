import re


PROPERTY = re.compile(r"^\s*([\w.-]+)(?:\s*[:=]\s*|\s+)(.*)$")


def property_entries(text: str):
    lines = enumerate(re.split(r"\r\n|\r|\n", text), 1)
    for number, line in lines:
        if line.lstrip(" \t\f").startswith(("#", "!")):
            continue
        parts = []
        while (len(line) - len(line.rstrip("\\"))) % 2:
            parts.append(line[:-1])
            _, line = next(lines, (0, ""))
            line = line.lstrip(" \t\f")
        parts.append(line)
        match = PROPERTY.fullmatch("".join(parts))
        if match:
            yield match[1], match[2].strip(), number, match.start(1) + 1
