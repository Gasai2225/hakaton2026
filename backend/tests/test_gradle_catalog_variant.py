import unittest

from garden.models import Source
from garden.scanners import analyze


MODULE = "org.apache.commons:commons-text"


class GradleCatalogVariant(unittest.TestCase):
    def scan(self, expression, version, extended, *, prefix="", lock=None):
        build = Source(path="app/build.gradle.kts", text=prefix + "dependencies {\n    testRuntimeOnly(" + expression + ")\n}")
        catalog = Source(path="gradle/libs.versions.toml", text=f'[libraries]\ntext-utils = "{MODULE}:{version}"\n'
                         '[bundles]\ntools = ["text-utils"]\n')
        files = [build, catalog]
        if lock:
            files.append(Source(path="app/gradle.lockfile", text=f"{MODULE}:{lock}=testRuntimeClasspath"))
        return analyze("sca", files, "*", extended, online_cve=False)

    def test_classifier_and_artifact_type_keep_the_catalog_module_and_lock(self):
        for extended in (False, True):
            for variant, version, lock in [('classifier("tests")', "1.9", None),
                                           ('classifier("tests")', "1.10.0", None),
                                           ('artifactType("jar")', "1.9", "1.10.0"),
                                           ('artifactType("jar")', "1.10.0", "1.9")]:
                with self.subTest(extended=extended, variant=variant, version=version, lock=lock):
                    result = self.scan(f"variantOf(libs.text.utils) {{ {variant} }}", version, extended, lock=lock)
                    actual = lock or version
                    self.assertEqual(result.issues + result.lockfile.issues, [])
                    self.assertEqual([(p.path, p.line, p.package, p.version, p.source, p.status) for p in result.packages],
                                     [("app/build.gradle.kts", 2, MODULE, actual, "gradle.lockfile" if lock else "declaration", "checked")])
                    self.assertEqual([(f.path, f.line, f.dependency.version, f.advisory) for f in result.findings],
                                     [("app/build.gradle.kts", 2, actual, "CVE-2022-42889")] if actual == "1.9" else [])
                    self.assertEqual(result.lockfile.packages, [])

    def test_only_a_single_gradle_catalog_library_can_select_a_variant(self):
        for prefix, expr in [
            ("", 'other.variantOf(libs.text.utils) { classifier("tests") }'),
            ("", 'variantOf(libs.bundles.tools) { classifier("tests") }'),
            ("", 'variantOf(libs.text.utils.get()) { classifier("tests") }'),
            ("", 'variantOf(libs.text.utils) { chooseVariant() }'),
            ("", 'variantOf(libs.text.utils) { classifier("tests") }.map { replacement }'),
            ("fun variantOf(p: Any, action: () -> Unit) = p\n", 'variantOf(libs.text.utils) { classifier("tests") }'),
        ]:
            for extended in (False, True):
                with self.subTest(prefix=prefix, expr=expr, extended=extended):
                    result = self.scan(expr, "1.9", extended, prefix=prefix)
                    self.assertTrue(result.issues)
                    self.assertEqual(result.packages, [])
                    self.assertEqual(result.findings, [])
