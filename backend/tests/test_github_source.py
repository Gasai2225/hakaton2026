import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

import httpx

from garden.api import app
from garden.github_source import GitHubSource, REPOSITORY, archive_sources, import_github
from garden.scanners import analyze
from garden.scenarios import sources


SHA = "1" * 40
PREFIX = f"training-{SHA}/training-project/"


def snapshot(entries):
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(PREFIX + name, data)
    return buffer.getvalue()


class GitHubSourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_archive_matches_folder_and_findings(self):
        entries = [("src/app.properties", b"api-key=test-only\r\n# caf\xe9\r\n"),
                   ("src/App.kt", b"\xef\xbb\xbfclass App\r\n"), ("build/Ignored.kt", b"class Generated"),
                   ("settings.gradle.kts", b'rootProject.name = "study"'), ("notes.txt", b"ignored")]
        data = snapshot(entries)
        def download(request):
            self.assertEqual(str(request.url), f"https://codeload.github.com/TBagirov/training/zip/{SHA}")
            return httpx.Response(200, content=data)

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, contents in entries:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
            expected = sources(root)
        async with httpx.AsyncClient(transport=httpx.MockTransport(download)) as client:
            actual = await import_github(client, GitHubSource(repository=REPOSITORY, revision=SHA))
        self.assertEqual(actual, expected)
        found = analyze("secrets", actual, "*").findings
        self.assertTrue(found)
        self.assertEqual(found, analyze("secrets", expected, "*").findings)

    async def test_api_explains_missing_revision_and_rejects_unapproved_inputs(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(404))) as client:
            engine = SimpleNamespace(gateway=SimpleNamespace(client=client))
            with patch.object(app.state, "engine", engine, create=True):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
                    for repository, revision, status, message in [
                        (REPOSITORY, SHA, 404, "Ревизия"),
                        (REPOSITORY, "main", 422, "полный SHA"),
                        ("https://example.com", SHA, 422, "Разрешён учебный репозиторий"),
                    ]:
                        with self.subTest(repository=repository, revision=revision):
                            response = await api.post("/api/sources/github", json={"repository": repository, "revision": revision})
                            self.assertEqual(response.status_code, status)
                            self.assertIn(message, response.json()["detail"])

    def test_import_limits(self):
        for entries, message in [
            ([(f"{i}.kt", b"x") for i in range(401)], "400 файлов"),
            ([("large.kt", b"x" * 300_001)], "300 000 символов"),
            ([(f"{i}.kt", b"x" * 250_001) for i in range(20)], "5 МБ"),
        ]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                archive_sources(snapshot(entries), SHA)

    def test_archive_reads_only_the_project_even_when_temp_is_in_another_checkout(self):
        config = b'dependencyResolutionManagement { versionCatalogs { libs { from(files("../gradle/libs.versions.toml")) } } }'
        with TemporaryDirectory() as outer:
            checkout = Path(outer)
            (checkout / ".git").mkdir()
            (checkout / "gradle").mkdir()
            (checkout / "gradle/libs.versions.toml").write_text("outside", encoding="utf-8")
            with patch("tempfile.tempdir", str(checkout)):
                result = archive_sources(snapshot([("settings.gradle", config)]), SHA)
        self.assertEqual([f.path for f in result], ["settings.gradle"])

    async def test_conflicting_paths_get_a_validation_error(self):
        entries = [("file.kt", b"class A"), ("file.kt/other.kt", b"class B")]
        for order in (entries, list(reversed(entries))):
            data = snapshot(order)
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=data))) as client:
                engine = SimpleNamespace(gateway=SimpleNamespace(client=client))
                with patch.object(app.state, "engine", engine, create=True):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
                        response = await api.post("/api/sources/github", json={"repository": REPOSITORY, "revision": SHA})
            self.assertEqual(response.status_code, 422)
            self.assertIn("конфликт путей", response.json()["detail"])
