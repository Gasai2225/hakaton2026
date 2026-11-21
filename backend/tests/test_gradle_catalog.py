import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garden.gradle_catalog import ATTACHED_CATALOG, catalog_source, imported_catalog
from pydantic import ValidationError

from garden.models import Node, Source
from garden.scanners import analyze
from garden.scenarios import sources


def settings(reference):
    return f'dependencyResolutionManagement {{ versionCatalogs {{ libs {{ from(files("{reference}")) }} }} }}'


class CatalogLocation(unittest.TestCase):
    def test_project_local_named_catalog_is_loaded_only_when_selected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "gradle").mkdir()
            (root / "build.gradle.kts").write_text("dependencies { implementation(libs.parser) }", encoding="utf-8")
            for filename, ver in [("lessons.versions.toml", "1.14.1"), ("shelf.versions.toml", "1.14.2")]:
                (root / "gradle" / filename).write_text(
                    f'[libraries]\nparser = {{ module = "org.jsoup:jsoup", version = "{ver}" }}', encoding="utf-8")
            for name, version, count in [("lessons", "1.14.1", 1), ("shelf", "1.14.2", 0)]:
                with self.subTest(name=name):
                    (root / "settings.gradle.kts").write_text(settings(f"gradle/{name}.versions.toml"), encoding="utf-8")
                    result = analyze("sca", sources(root, read_parent_catalog=False), "*", extended_sca=False)
                    self.assertEqual(result.issues, [])
                    self.assertEqual([(p.package, p.version) for p in result.packages], [("org.jsoup:jsoup", version)])
                    self.assertEqual(len(result.findings), count)

    def test_settings_static_import_and_controls(self):
        reference = "../../gradle/libs.versions.toml"
        text = settings(reference)
        for source, expected in [
            (text, reference), (text.replace("libs {", 'create("libs") {'), reference),
            ("// " + text, None), ("/* " + text + " */", None), ('val example = """' + text + '"""', None),
            (text.replace("libs {", "testing {"), None), (text.replace('"' + reference + '"', 'location()'), ""),
            (text.replace("from(files", "if (enabled) { from(files") + "}", ""),
            (text.replace("from(files", "if (enabled) from(files"), ""),
            (text.replace("))", ')); version("boot", "9")'), ""),
            (text + "\n" + text, ""),
        ]:
            with self.subTest(source=source):
                self.assertEqual(imported_catalog(source), expected)

    def test_separate_nested_build_uses_its_own_settings(self):
        root_catalog = Source(path="gradle/libs.versions.toml", text="root")
        local_catalog = Source(path="included/gradle/libs.versions.toml", text="included")
        build = "included/worker/build.gradle.kts"
        for config, expected in [
            ('rootProject.name = "included"', local_catalog),
            (settings("../gradle/libs.versions.toml"), root_catalog),
            (settings("../missing/libs.versions.toml"), None),
            (settings("../gradle/libs.versions.toml").replace("files(", "dynamicFiles("), None),
        ]:
            with self.subTest(config=config):
                files = [root_catalog, local_catalog, Source(path="included/settings.gradle", text=config)]
                self.assertEqual(catalog_source(files, build), expected)

    def test_module_import_is_limited_to_its_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            outer = Path(temp)
            checkout = outer / "repo"
            module = checkout / "example"
            module.mkdir(parents=True)
            (checkout / ".git").mkdir()
            (module / "build.gradle.kts").write_text("plugins {}", encoding="utf-8")
            for folder in (checkout, outer):
                (folder / "gradle").mkdir()
                (folder / "gradle/libs.versions.toml").write_text("test", encoding="utf-8")
            config = module / "settings.gradle"
            config.write_text(settings("../gradle/libs.versions.toml"), encoding="utf-8")
            attached = catalog_source(sources(module), "build.gradle.kts")
            self.assertEqual((attached.path, attached.text), (ATTACHED_CATALOG, "test"))
            self.assertEqual(catalog_source(sources(checkout), "example/build.gradle.kts").path, "gradle/libs.versions.toml")
            config.write_text(settings("../../gradle/libs.versions.toml"), encoding="utf-8")
            self.assertIsNone(catalog_source(sources(module), "build.gradle.kts"))

    def test_profile_is_local_to_the_run(self):
        files = [Source(path="gradle.lockfile", text="org.yaml:snakeyaml:1.33=runtimeClasspath")]
        with patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": "0"}):
            self.assertTrue(analyze("sca", files, "*", True).lockfile.files)
            self.assertFalse(analyze("sca", files, "*").lockfile.files)
        with patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": "1"}):
            self.assertFalse(analyze("sca", files, "*", False).lockfile.files)

    def test_sca_modes_normalize_old_and_new_nodes(self):
        fields = dict(id="sca", kind="sca", x=0, y=0)
        for saved, expected in [
            ({}, True), ({"extended_sca": None, "online_cve": False}, True),
            ({"extended_sca": True, "online_cve": False}, True), ({"online_cve": True}, True),
            ({"extended_sca": False}, False), ({"extended_sca": False, "online_cve": False}, False),
        ]:
            with self.subTest(saved=saved):
                node = Node(**fields, **saved)
                self.assertEqual((node.extended_sca, node.online_cve), (expected, expected))
                self.assertEqual(Node.model_validate_json(node.model_dump_json()), node)
        with self.assertRaises(ValidationError):
            Node(**fields, extended_sca=False, online_cve=True)
