"""Read-only checks for uploaded Kotlin, Gradle and Spring configuration files."""

import hashlib
import os
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from tree_sitter import Language, Node as SyntaxNode, Parser
import tree_sitter_kotlin

from garden.jdbc import unsafe_sql
from garden.compose import compose_checks, is_compose
from garden.kotlin_checks import cors, disabled_tls, matcher_conflicts, tokens
from garden.maven import Entry, PackageCheck, check_lock, declared, load_catalog, version
from garden.models import Finding, Kind, LockReport, Severity, Source
from garden.ownership import reader_methods, unscoped_reads
from garden.secret_checks import config_secrets, kotlin_secrets


KOTLIN = Language(tree_sitter_kotlin.language())


def finding(file: Source, rule: str, line: int, column: int, title: str, fix: str,
            severity: Severity = "high", advisory: str | None = None, identity: str = "") -> Finding:
    key = f"{file.path}\0{rule}\0{line}\0{column}\0{advisory or ''}"
    if identity:
        key += "\0" + identity
    return Finding(id=hashlib.sha256(key.encode()).hexdigest()[:20], path=file.path, rule=rule, line=line,
                   column=column, title=title, fix=fix, severity=severity, advisory=advisory)


SECRET_RULES = {
    "api-key": ("API-ключ задан в проекте", "Загрузите ключ из хранилища секретов и отзовите опубликованный ключ."),
    "password": ("Пароль задан в проекте", "Вынесите пароль из проекта и смените его у соответствующей учётной записи."),
    "configuration-token": ("Токен авторизации задан в проекте", "Получайте токен из защищённых настроек и замените опубликованный токен."),
    "secret-fallback": ("При отсутствии настройки используется встроенный секрет", "Уберите встроенное значение и проверьте, что при отсутствии настройки приложение сообщает об ошибке."),
    "recoverable-token": ("Токен можно восстановить из строковых констант", "Уберите фрагменты токена из проекта, замените токен и получайте его из хранилища секретов."),
    "embedded-secret": ("Секрет задан в проекте", "Перенесите значение в хранилище секретов и замените опубликованный секрет."),
}


def secret(file: Source, line: int, column: int, classification: str) -> Finding:
    hit = finding(file, "SECRET-LITERAL", line, column, *SECRET_RULES[classification])
    hit.classification = classification
    return hit


def compose_hits(file: Source, kind: Kind) -> list[Finding]:
    hits = []
    # Anchored environment mappings can be shared by multiple services at one source location.
    for line, column, cls in dict.fromkeys(compose_checks(file, kind)):
        if kind == "secrets":
            hits.append(secret(file, line, column, cls))
        else:
            hit = finding(file, "COMPOSE-MYSQL-EMPTY-ROOT", line, column, *SAST_RULES[cls])
            hit.classification = cls
            hits.append(hit)
    return hits


def position(file_bytes: bytes, node: SyntaxNode) -> tuple[int, int]:
    start = node.start_byte - node.start_point.column
    column = len(file_bytes[start:node.start_byte].decode()) + 1
    return node.start_point.row + 1, column


def dependency_hits(file: Source, root: SyntaxNode, data: bytes,
                    entries: dict[str, list[Entry]], files: list[Source], issues: list[str],
                    inventory: list[PackageCheck], extended: bool) -> list[Finding]:
    hits = []
    seen = set()
    for node, dep, entry in declared(root, entries, files, file.path, issues, inventory, extended):
        package = f"{dep.group}:{dep.artifact}"
        key = (package, dep.version, entry.identifier)
        if key in seen:
            continue
        seen.add(key)
        bulletins = entries[package]
        candidates = {v for bulletin in bulletins for v in bulletin.fixedVersions}
        fixed = min((v for v in candidates if version(v) > version(dep.version)
                     and not any(r.contains(v) for bulletin in bulletins for r in bulletin.ranges)),
                    key=lambda v: (version(v), v), default=None)
        fix = f"Проверьте обновление {package} до {fixed}." if fixed else "Подберите версию вне уязвимых диапазонов."
        hit = finding(file, "GRADLE-ADVISORY", *position(data, node),
                      f"{package} {dep.version} входит в диапазон {entry.identifier}", fix,
                      entry.severity.lower(), entry.identifier, package if b"libs.bundles." in node.text else "")
        hit.dependency = dep
        hit.fixed_version = fixed
        hits.append(hit)
    return hits


def kotlin_hits(file: Source, kind: Kind, root: SyntaxNode, readers: set[tuple[str, str, str]]) -> list[Finding]:
    data = file.text.encode()
    if kind == "secrets":
        return [secret(file, *position(data, node), classification) for classification, node in kotlin_secrets(root)]
    nodes = tokens(root)
    words = [data[n.start_byte:n.end_byte].decode() for n in nodes]
    spring_security = any(
        words[i:i + 8] == ["import", "org", ".", "springframework", ".", "security", ".", "config"]
        for i, word in enumerate(words) if word == "import"
    )
    hits = []
    for i, word in enumerate(words):
        if spring_security and word in {"anyRequest", "anyExchange"}:
            java_dsl = words[i + 1:i + 7] == ["(", ")", ".", "permitAll", "(", ")"]
            kotlin_dsl = words[max(0, i - 2):i] == ["authorize", "("] and words[i + 1:i + 4] == [",", "permitAll", ")"]
            if java_dsl or kotlin_dsl:
                hits.append(finding(file, "SPRING-OPEN-DEFAULT", *position(data, nodes[i]),
                                    "Общее правило разрешает доступ всем запросам",
                                    "Ограничьте публичный доступ нужными маршрутами и проверьте остальные маршруты с авторизацией."))
    for matches in (cors(root), unsafe_sql(root), disabled_tls(root), matcher_conflicts(root), unscoped_reads(root, readers)):
        for classification, location in matches:
            title, fix = SAST_RULES[classification]
            hit = finding(file, "SPRING-" + classification.upper(), *position(data, location), title, fix)
            hit.classification = classification
            hits.append(hit)
    return list({hit.id: hit for hit in hits}.values())


SAST_RULES = {
    "empty-database-root-password": ("MySQL разрешает инициализацию с пустым паролем root",
                                     "Уберите MYSQL_ALLOW_EMPTY_PASSWORD и настройте пароль root через хранилище секретов."),
    "object-authorization": ("Чтение записи по ID без проверки владельца в обработчике и запросе",
                             "Свяжите выборку с текущим пользователем и проверьте отказ при доступе к чужой записи."),
    "credentialed-cors": ("CORS разрешает любой источник с учётными данными",
                          "Укажите доверенные источники и проверьте ответы для разрешённого и постороннего origin."),
    "sql-injection": ("Параметр HTTP встроен в текст запроса к БД",
                      "Передайте значение отдельно от текста запроса через параметры JDBC или JPA."),
    "tls-verification": ("Проверка имени узла TLS всегда возвращает true", "Используйте штатную проверку имени узла HTTPS."),
    "route-authorization": ("Публичное исключение пересекается с защищённой группой маршрутов",
                            "Сверьте исключение с политикой доступа. Проверьте порядок правил и тесты авторизации."),
}


@dataclass
class Analysis:
    findings: list[Finding] = field(default_factory=list)
    checked: int = 0
    issues: list[str] = field(default_factory=list)
    packages: list[PackageCheck] = field(default_factory=list)
    lockfile: LockReport = field(default_factory=LockReport)

    @property
    def checked_packages(self) -> int:
        return sum(p.status == "checked" for p in self.packages)


def analyze_maven(files: list[Source], pattern: str) -> Analysis:
    extended = os.environ.get("GARDEN_EXTENDED_SCA") == "1"
    entries = load_catalog(extended)
    result = Analysis()
    parser = Parser(KOTLIN)
    by_path = {f.path: f for f in files}
    inputs = {"build.gradle.kts", "gradle.lockfile"} if extended else {"build.gradle.kts"}
    modules = dict.fromkeys(Path(f.path).parent for f in files
                            if Path(f.path).name in inputs and fnmatchcase(f.path, pattern))
    for module in modules:
        build = by_path.get((module / "build.gradle.kts").as_posix())
        lock = by_path.get((module / "gradle.lockfile").as_posix())
        declarations = []
        errors = []
        if build:
            data = build.text.encode()
            root = parser.parse(data).root_node
            if root.has_error:
                errors.append(f"Ошибка синтаксического разбора Kotlin в {build.path}")
            else:
                hits = dependency_hits(build, root, data, entries, files, errors, declarations, extended)
                if fnmatchcase(build.path, pattern):
                    result.findings.extend(hits)
                    result.packages.extend(declarations)
                    result.checked += 1
            if fnmatchcase(build.path, pattern):
                result.issues.extend(errors)
        if lock and extended:
            classified = build is not None and not errors
            if not classified:
                result.lockfile.issues.append(f"Не удалось определить все прямые зависимости для {lock.path}")
            check_lock(lock, {p.package for p in declarations}, classified, entries, result.lockfile)
            result.checked += 1
    skipped = len(result.lockfile.packages) - result.lockfile.checked
    if skipped:
        result.lockfile.issues.append(f"Записей lockfile без проверки по справочнику: {skipped}")
    return result


def analyze(kind: Kind, files: list[Source], pattern: str) -> Analysis:
    if kind == "sca":
        return analyze_maven(files, pattern)
    parser = Parser(KOTLIN)
    roots = {}
    for file in files:
        if not file.path.endswith((".kt", ".kts")):
            continue
        if kind == "sast" or fnmatchcase(file.path, pattern):
            roots[file.path] = parser.parse(file.text.encode()).root_node
    readers = {entry for root in roots.values() if not root.has_error for entry in reader_methods(root)} if kind == "sast" else set()
    result = Analysis()
    for file in files:
        if not fnmatchcase(file.path, pattern):
            continue
        try:
            if kind in {"sast", "secrets"} and is_compose(file.path):
                hits = compose_hits(file, kind)
            elif file.path.endswith((".yml", ".yaml", ".properties")) and kind == "secrets":
                hits = [secret(file, line, col, cls) for line, col, cls in config_secrets(file)]
            elif file.path in roots:
                root = roots[file.path]
                if root.has_error:
                    raise ValueError(f"Ошибка синтаксического разбора Kotlin в {file.path}")
                hits = kotlin_hits(file, kind, root, readers)
            else:
                continue
            result.checked += 1
            result.findings.extend(hits)
        except ValueError as error:
            result.issues.append(str(error))
    return result


def scan(kind: Kind, files: list[Source], pattern: str) -> tuple[list[Finding], int]:
    result = analyze(kind, files, pattern)
    if result.issues:
        raise ValueError(result.issues[0])
    return result.findings, result.checked
