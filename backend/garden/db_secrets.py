"""Recognize credentials only in database settings and typed JVM database APIs."""
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from tree_sitter import Node

from garden.kotlin_checks import receiver_has_type, walk, words
from garden.kotlin_strings import static_string
from garden.kotlin_types import KotlinTypes


JDBC = "java.sql.DriverManager"
R2DBC = "io.r2dbc.spi.ConnectionFactories"
POOLS = {"com.zaxxer.hikari.HikariConfig", "com.zaxxer.hikari.HikariDataSource"}
DB_SETTINGS = {
    "spring.datasource": {"url", "password"},
    "spring.datasource.hikari": {"jdbcurl", "password"},
    "spring.datasource.hikari.datasourceproperties": {"password"},
    "spring.datasource.tomcat": {"url", "password"},
    "spring.datasource.dbcp2": {"url", "password"},
    "spring.r2dbc": {"url", "password"},
    "spring.flyway": {"url", "password"},
    "spring.liquibase": {"url", "password"},
}
DB_FIELDS = {f"{prefix}.{key}" for prefix, keys in DB_SETTINGS.items() for key in keys}
DB_SECTIONS = {"spring", *DB_SETTINGS}
MASK = re.compile(r"\*{3,}|<redacted>|\[redacted\]|<password>|\{\{[^{}]*\}\}|\$[\w]+", re.I)
SQL_SERVER_KEY = re.compile(r"([^;=]+)=")
BRACED_VALUE = re.compile(r"\{((?:[^}]|}})*)\}[ \t]*(?=;|$)")


def config_name(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "")


def password_kind(value: str, resolve_default) -> str | None:
    kind = "password"
    if "${" in value:
        value = resolve_default(value)
        kind = "secret-fallback"
    if value is None:
        return None
    value = value.strip()
    if not value or value in {"''", '""', "~", "null"} or MASK.fullmatch(value):
        return None
    return kind


def sql_server_passwords(url: str) -> list[str]:
    # Braces quote an entire SQL Server property. A doubled closing brace is literal.
    _, _, settings = url.partition(";")
    passwords, pos = [], 0
    while pos < len(settings):
        if settings[pos] == ";":
            pos += 1
            continue
        key = SQL_SERVER_KEY.match(settings, pos)
        if key is None:
            return []
        pos = key.end()
        while pos < len(settings) and settings[pos] in " \t":
            pos += 1
        if settings.startswith("{", pos):
            quoted = BRACED_VALUE.match(settings, pos)
            if quoted is None:
                return []
            value, pos = quoted[1].replace("}}", "}"), quoted.end()
        else:
            end = settings.find(";", pos)
            end = len(settings) if end < 0 else end
            value, pos = settings[pos:end], end
        if key[1].strip().lower() == "password":
            passwords.append(value)
        pos += 1
    return passwords


def url_password(url: str, resolve_default, family: str) -> str | None:
    outer = url.startswith("${") and url.endswith("}")
    if outer:
        url = resolve_default(url) or ""
    match = re.match(r"(?:(jdbc):(postgresql|mysql|mariadb|sqlserver)|(r2dbcs?):[\w-]+(?::[\w-]+)?):", url, re.I)
    if not match or (family == "jdbc") != bool(match[1]):
        return None
    driver = (match[2] or "").lower()
    address = url[match.end():]
    if driver == "sqlserver":
        passwords = sql_server_passwords(address) if address.startswith("//") else []
    else:
        try:
            parts = urlsplit(address)
            # R2DBC reserves user/password for the authority and rejects them in the query.
            passwords = [v for k, v in parse_qsl(parts.query) if k == "password"] if family == "jdbc" else []
            if (family == "r2dbc" or driver == "mysql") and parts.hostname and parts.password is not None:
                passwords.append(unquote(parts.password))
        except ValueError:
            return None
    for password in passwords:
        kind = password_kind(password, resolve_default)
        if kind:
            return "secret-fallback" if outer else kind
    return None


def database_settings(name: str, value: str, resolve_default) -> str | None:
    if name.endswith(".password"):
        return password_kind(value, resolve_default)
    return url_password(value, resolve_default, "r2dbc" if name == "spring.r2dbc.url" else "jdbc")


def local_binding(name: str, use: Node) -> Node | None:
    scope = use.parent
    while scope and scope.type not in {"function_declaration", "class_body", "source_file"}:
        if scope.type == "for_statement":
            variables = next((n for n in scope.named_children if n.type in {"variable_declaration", "multi_variable_declaration"}), None)
            if variables and name in words(variables):
                return None
        if scope.type in {"block", "lambda_literal"}:
            for prop in reversed(scope.named_children):
                if prop.type == "property_declaration" and prop.end_byte <= use.start_byte:
                    var = next((n for n in prop.named_children if n.type == "variable_declaration"), None)
                    if var and var.named_children[0].text.decode() == name:
                        return prop
            if scope.type == "lambda_literal":
                params = next((n for n in scope.named_children if n.type == "lambda_parameters"), None)
                if name in (words(params) if params else ["it"]):
                    return None
        scope = scope.parent
    return None


def kotlin_database_secrets(root: Node, resolve_default):
    source = root.text
    if not any(part in source for part in (b"java.sql", b"com.zaxxer.hikari", b"io.r2dbc.spi")):
        return
    types = KotlinTypes(root, {JDBC, R2DBC, *POOLS})
    aliases = {n for n, path in types.names.items() if path in {JDBC, R2DBC}}
    shadows = []
    for kind in ("parameter", "class_parameter", "variable_declaration"):
        for decl in walk(root, kind):
            name = next((c.text.decode() for c in decl.named_children if c.type == "identifier"), None)
            if name not in aliases and name not in {"password", "jdbcUrl"}:
                continue
            scope = decl.parent
            while scope is not None and scope.type not in {"block", "function_declaration", "lambda_literal", "class_body",
                                                           "class_declaration", "source_file"}:
                scope = scope.parent
            if scope:
                start = decl.end_byte if kind == "variable_declaration" and scope.type in {"block", "lambda_literal"} else scope.start_byte
                shadows.append((name, start, scope.end_byte))

    for kind in ("call_expression", "assignment"):
        for site in walk(root, kind):
            parts = [c for c in site.named_children if "comment" not in c.type]
            if len(parts) != 2 or parts[0].type not in {"navigation_expression", "identifier"}:
                continue
            target, value = parts
            method = target.named_children[-1].text if target.type == "navigation_expression" else target.text
            if kind == "assignment":
                if method not in {b"password", b"jdbcUrl"} or not any(c.type == "=" for c in site.children):
                    continue
                values = [value]
            else:
                if method not in {b"get", b"getConnection", b"setJdbcUrl", b"setPassword"} or value.type != "value_arguments":
                    continue
                values = [c for arg in value.named_children if arg.type == "value_argument"
                          for c in arg.named_children if "comment" not in c.type]
            if method in {b"get", b"getConnection"}:
                if target.type != "navigation_expression" or not values:
                    continue
                name = "".join(words(target.named_children[0]))
                required = JDBC if method == b"getConnection" else R2DBC
                if (types.resolve(name, site) != required
                        or any(n == name and lo <= site.start_byte < hi for n, lo, hi in shadows)
                        or len(values) not in ({1, 2, 3} if required == JDBC else {1})):
                    continue
                inputs = [(values[0], "jdbc" if required == JDBC else "r2dbc")]
                if len(values) == 3:
                    inputs.append((values[2], "password"))
            else:
                names = POOLS | {n for n in types.names if types.resolve(n, site) in POOLS}
                if len(values) != 1 or not receiver_has_type(site, names):
                    continue
                if target.type == "identifier" and any(n == method.decode() and lo <= site.start_byte < hi for n, lo, hi in shadows):
                    continue
                inputs = [(values[0], "password" if method in {b"password", b"setPassword"} else "jdbc")]
            for arg, field in inputs:
                literal = static_string(arg, local_binding)
                if literal is None:
                    continue
                if field == "password":
                    classification = password_kind(literal, resolve_default)
                else:
                    classification = url_password(literal, resolve_default, field)
                if classification:
                    origin = local_binding(arg.text.decode(), arg) if arg.type == "identifier" else None
                    yield classification, origin or arg
