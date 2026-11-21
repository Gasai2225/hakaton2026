"""Read the competition JSON attached by the saved-workflow Actions job."""
import json
import re
import zlib
from io import BytesIO
from itertools import islice
from pathlib import Path
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile


MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 256
REPORT_NAME = re.compile(r"[0-9]{3,}-([A-Za-z0-9._-]{1,80})\.json")


def _finding(row: dict) -> dict:
    if not isinstance(row, dict) or row.get("category") not in ("SECRET", "SAST", "SCA"):
        raise ValueError("Некорректная категория находки в отчёте GitHub Actions")
    if row.get("severity") not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError("Некорректная критичность в отчёте GitHub Actions")
    fields = ["category", "severity", "path", "description", "remediation"]
    if row["category"] == "SCA":
        fields.extend(["group", "artifact", "version", "advisoryId"])
    else:
        fields.append("class")
        if type(row.get("line")) is not int or row["line"] < 1:
            raise ValueError("Некорректный номер строки в отчёте GitHub Actions")
    result = {}
    for field in fields:
        value = row.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Пропущено текстовое поле находки в отчёте GitHub Actions")
        value.encode("utf-8")  # Escaped lone surrogates cannot be served as UTF-8 JSON.
        result[field] = value
    if row["category"] != "SCA":
        result["line"] = row["line"]
    return result


def _collect(entries) -> list[dict]:
    reports = {}
    total = 0
    for filename, data in entries:
        label = REPORT_NAME.fullmatch(filename)
        if label is None or filename in reports:
            raise ValueError("Некорректное имя или повтор файла отчёта GitHub Actions")
        total += len(data)
        if len(data) > MAX_REPORT_BYTES or total > MAX_EXPANDED_BYTES:
            raise ValueError("Превышен размер отчёта GitHub Actions")
        try:
            document = json.loads(data.decode("utf-8"))
        except (ValueError, RecursionError) as exc:
            raise ValueError("Некорректный JSON отчёта GitHub Actions") from exc
        rows = document.get("findings") if isinstance(document, dict) else None
        if not isinstance(rows, list):
            raise ValueError("В отчёте GitHub Actions отсутствует список находок")
        reports[filename] = {"name": label[1], "findings": [_finding(row) for row in rows]}
    return [reports[key] for key in sorted(reports)]


def read_archive(data: bytes) -> list[dict]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("Архив GitHub Actions слишком велик")
    try:
        with ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES or sum(item.file_size for item in entries) > MAX_EXPANDED_BYTES:
                raise ValueError("Содержимое архива GitHub Actions превышает лимит")

            def files():
                for item in entries:
                    if item.filename.endswith(".json"):
                        if item.file_size > MAX_REPORT_BYTES or item.compress_type not in (ZIP_STORED, ZIP_DEFLATED):
                            raise ValueError("Недопустимый размер или сжатие JSON в архиве GitHub Actions")
                        with archive.open(item) as stream:
                            yield item.filename, stream.read(MAX_REPORT_BYTES + 1)

            return _collect(files())
    except (BadZipFile, RuntimeError, OSError, EOFError, zlib.error) as exc:
        raise ValueError("Не удалось прочитать архив GitHub Actions") from exc


def read_directory(directory: Path) -> list[dict]:
    def files():
        if directory.resolve() != directory.absolute():
            raise ValueError("Каталог отчётов GitHub Actions содержит ссылку")
        try:
            paths = list(islice(directory.iterdir(), MAX_ENTRIES + 1))
        except FileNotFoundError:
            return
        if len(paths) > MAX_ENTRIES:
            raise ValueError("В каталоге отчётов GitHub Actions слишком много файлов")
        for path in paths:
            if path.name.endswith(".json"):
                if path.is_symlink() or not path.is_file():
                    raise ValueError("Ожидался обычный файл отчёта GitHub Actions")
                with path.open("rb") as stream:
                    yield path.name, stream.read(MAX_REPORT_BYTES + 1)

    try:
        return _collect(files())
    except OSError as exc:
        raise ValueError("Не удалось прочитать каталог отчётов GitHub Actions") from exc
