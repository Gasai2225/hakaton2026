"""Inspect declared Docker Compose environments without loading .env or contacting Docker."""
import re
import shlex
from pathlib import PurePosixPath

import yaml

from garden.models import Source
from garden.secret_checks import SECRET_NAME, name_class, yaml_documents


MYSQL_FLAGS = {"MYSQL_ALLOW_EMPTY_PASSWORD", "MYSQL_RANDOM_ROOT_PASSWORD", "MYSQL_ONETIME_PASSWORD"}
ROOT_CREDENTIALS = {"MYSQL_ROOT_PASSWORD", "MYSQL_ROOT_PASSWORD_FILE", "MYSQL_RANDOM_ROOT_PASSWORD"}
SUBSTITUTION = re.compile(r"\$\{[A-Za-z_]\w*(:?[-+])(.*)\}", re.S)
MYSQL_IMAGE = re.compile(r"(?:docker\.io/)?(?:library/)?mysql(?::[\w.-]+)?(?:@sha256:[a-f0-9]{64})?")


def is_compose(path: str) -> bool:
    return bool(re.fullmatch(r"(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml", PurePosixPath(path).name))


def fields(node):
    if not isinstance(node, yaml.MappingNode) or node.tag == "!reset":
        return {}
    return {key.value: value for key, value in node.value
            if isinstance(key, yaml.ScalarNode) and value.tag != "!reset"}


def environment(node):
    if isinstance(node, yaml.SequenceNode):
        for entry in node.value:
            if isinstance(entry, yaml.ScalarNode) and entry.tag != "!reset":
                name, equals, value = entry.value.partition("=")
                yield name, (value if equals else None, entry.start_mark)
    elif isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            if isinstance(key, yaml.ScalarNode) and isinstance(value, yaml.ScalarNode) and value.tag != "!reset":
                yield key.value, (None if value.tag.endswith(":null") else value.value, key.start_mark)


def credential(name: str, value: str | None) -> str | None:
    if not value or name in MYSQL_FLAGS or not SECRET_NAME.search(name):
        return None
    # Compose's default/alternative operands can contain another interpolation.
    # Required-variable messages are diagnostic text and bare references resolve at runtime.
    text = value.replace("$$", "\0")
    classification = name_class(name)
    for _ in range(32):
        if not re.search(r"\$(?:\{|[A-Za-z_])", text):
            return classification if text.strip() else None
        match = SUBSTITUTION.fullmatch(text)
        if not match or text.count("{") != text.count("}"):
            return None
        text = match[2]
        classification = "secret-fallback"
    return None


def starts_mysql_server(command: yaml.Node | None) -> bool:
    # The official entrypoint initializes a database only for mysqld, and skips informational options.
    if command is None or command.tag.endswith(":null"):
        return True
    if isinstance(command, yaml.ScalarNode):
        try:
            args = shlex.split(command.value)
        except ValueError as error:
            raise ValueError("Не удалось разобрать команду сервиса MySQL") from error
    elif isinstance(command, yaml.SequenceNode) and all(isinstance(arg, yaml.ScalarNode) for arg in command.value):
        args = [arg.value for arg in command.value]
    else:
        return False
    return (bool(args) and (args[0] == "mysqld" or args[0].startswith("-"))
            and not {"-?", "--help", "--print-defaults", "-V", "--version"}.intersection(args))


def compose_checks(source: Source, kind: str):
    for document in yaml_documents(source):
        top = fields(document)
        services = fields(top["services"]) if "services" in top else top
        for name, service in services.items():
            if name.startswith("x-"):
                continue
            config = fields(service)
            if "services" not in top and not {"image", "build", "extends", "<<"}.intersection(config):
                continue
            env = dict(environment(config.get("environment")))
            if kind == "secrets":
                for key, (value, mark) in env.items():
                    classification = credential(key, value)
                    if classification:
                        yield mark.line + 1, mark.column + 1, classification
                continue
            image = config.get("image")
            if not isinstance(image, yaml.ScalarNode) or not MYSQL_IMAGE.fullmatch(image.value):
                continue
            if {"build", "env_file", "extends", "<<"}.intersection(config) or "<<" in fields(config.get("environment")):
                continue  # External or merged settings may supply a root credential.
            entrypoint = config.get("entrypoint")
            if (entrypoint is not None and not entrypoint.tag.endswith(":null")) or not starts_mysql_server(config.get("command")):
                continue
            flag = env.get("MYSQL_ALLOW_EMPTY_PASSWORD")
            if not flag or not flag[0] or "$" in flag[0]:
                continue
            if any(key in env and env[key][0] != "" for key in ROOT_CREDENTIALS):
                continue  # Includes values inherited from the shell.
            yield flag[1].line + 1, flag[1].column + 1, "empty-database-root-password"
