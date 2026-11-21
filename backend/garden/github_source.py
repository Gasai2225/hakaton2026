import asyncio
import ntpath
import re
import stat
from io import BytesIO
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

import httpx
from pydantic import ValidationError, field_validator

from garden.models import Model, Source
from garden.scenarios import IGNORED_SOURCE_DIRS, source_file, sources


REPOSITORY = "https://github.com/TBagirov/training"
MAX_ARCHIVE_BYTES = 10_000_000


class GitHubSource(Model):
    repository: str
    revision: str

    @field_validator("repository")
    @classmethod
    def approved_repository(cls, value: str) -> str:
        if value.strip().rstrip("/").removesuffix(".git").lower() != REPOSITORY.lower():
            raise ValueError(f"Разрешён учебный репозиторий {REPOSITORY}")
        return REPOSITORY

    @field_validator("revision")
    @classmethod
    def commit_sha(cls, value: str) -> str:
        if not re.fullmatch(r"[a-fA-F0-9]{40}", value):
            raise ValueError("Укажите полный SHA коммита (40 шестнадцатеричных символов)")
        return value.lower()


def archive_sources(data: bytes, revision: str) -> list[Source]:
    prefix = f"training-{revision}/training-project/"
    with ZipFile(BytesIO(data)) as archive, TemporaryDirectory() as temp:
        root = Path(temp)
        count = size = 0
        for entry in archive.infolist():
            if not entry.filename.startswith(prefix) or entry.is_dir() or stat.S_ISLNK(entry.external_attr >> 16):
                continue
            name = entry.filename[len(prefix):]
            path = PurePosixPath(name)
            if not source_file(path) or IGNORED_SOURCE_DIRS.intersection(path.parts):
                continue
            if (name != path.as_posix() or path.is_absolute() or ".." in path.parts
                    or "\\" in name or ":" in name or len(name) > 350
                    or any(ntpath.isreserved(part) for part in path.parts)):
                raise ValueError("В архиве недопустимый путь исходного файла")
            count += 1
            size += entry.file_size
            if count > 400 or size > 5_000_000:
                raise ValueError("Лимит проекта — 400 файлов и 5 МБ")
            target = root.joinpath(*path.parts)
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.is_dir():
                    raise IsADirectoryError
                with target.open("xb") as out:
                    out.write(archive.read(entry))
            except (FileExistsError, NotADirectoryError, IsADirectoryError):
                raise ValueError("В архиве конфликт путей файлов и каталогов") from None
        try:
            files = sources(root, read_parent_catalog=False)
        except ValidationError:
            raise ValueError("Размер каждого файла — до 300 000 символов") from None
        if sum(len(f.text.encode()) for f in files) > 5_000_000:
            raise ValueError("Лимит проекта — 400 файлов и 5 МБ")
        return files


async def import_github(client: httpx.AsyncClient, source: GitHubSource) -> list[Source]:
    url = f"https://codeload.github.com/TBagirov/training/zip/{source.revision}"
    async with client.stream("GET", url, timeout=20, follow_redirects=False) as response:
        if response.status_code == 404:
            raise FileNotFoundError("Ревизия учебного репозитория не найдена")
        response.raise_for_status()
        data = bytearray()
        async for chunk in response.aiter_bytes(65_536):
            if len(data) + len(chunk) > MAX_ARCHIVE_BYTES:
                raise ValueError("Архив репозитория превышает 10 МБ")
            data.extend(chunk)
    try:
        return await asyncio.to_thread(archive_sources, bytes(data), source.revision)
    except BadZipFile:
        raise ValueError("GitHub вернул повреждённый архив ревизии") from None
