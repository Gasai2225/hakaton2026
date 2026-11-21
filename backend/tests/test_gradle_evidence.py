import unittest
from unittest.mock import patch

from garden.maven import LegacyEntry
from garden.models import Source
from garden.osv_client import OsvAdvisory, OsvResult
from garden.scanners import analyze


MODULE = "spec.fixture:codec"
LOCAL = LegacyEntry(package=MODULE, advisory="TEST-LOCAL", introduced="1.0", fixed="2.0", severity="high").convert()
REMOTE = OsvAdvisory("TEST-REMOTE", (), "medium", "2.0", "https://example.invalid/test")


class GradleEvidence(unittest.TestCase):
    def check(self, sources, versions, vulnerable=(), query_versions=None):
        files = [Source(path=path, text=source) for path, source in sources.items()]
        queries = sorted({(MODULE, v) for v in (versions if query_versions is None else query_versions)})
        for extended, online in ((False, False), (True, False), (True, True)):
            with self.subTest(extended=extended, online=online), patch(
                "garden.scanners.load_catalog", return_value={MODULE: [LOCAL]}
            ), patch("garden.osv_client.check_maven") as query:
                query.side_effect = lambda coords: {
                    coord: OsvResult((REMOTE,)) if coord[1] in {"1.0", "1.1"} else OsvResult()
                    for coord in coords
                }
                result = analyze("sca", files, "*", extended, online)
                self.assertEqual([(p.package, p.version) for p in result.packages], [(MODULE, v) for v in versions])
                self.assertCountEqual([(f.advisory, f.dependency.version) for f in result.findings],
                                      [(advisory, v) for v in vulnerable
                                       for advisory in ([LOCAL.id, REMOTE.id] if online else [LOCAL.id])])
                if online and queries:
                    query.assert_called_once_with(queries)
                else:
                    query.assert_not_called()

    def test_kotlin_literals_comments_and_known_unreachable_branches(self):
        self.check({"build.gradle.kts": '''
val help = """implementation("spec.fixture:codec:1.1")"""
/* dependencies { implementation("spec.fixture:codec:1.1") } */
dependencies {
    // implementation("spec.fixture:codec:1.1")
    if ((false)) { implementation("spec.fixture:codec:1.1") } else implementation("spec.fixture:codec:2.0")
    if (true) implementation("spec.fixture:codec:1.0") else implementation("spec.fixture:codec:1.1")
    if (false) implementation("spec.fixture:codec:1.1")
}'''}, ["2.0", "1.0"], ["1.0"])

    def test_only_gradle_dependency_handlers(self):
        self.check({"build.gradle.kts": '''
class Guide {
    fun dependencies(block: Guide.() -> Unit) = block()
    fun implementation(text: String) = Unit
    fun add(name: String, text: String) = Unit
}
val guide = Guide()
guide.dependencies { implementation("spec.fixture:codec:1.1") }
run {
    val dependencies = guide
    dependencies.add("implementation", "spec.fixture:codec:1.1")
}
project.dependencies { implementation("spec.fixture:codec:2.0") }
dependencies.add("implementation", "spec.fixture:codec:1.0")
'''}, ["2.0", "1.0"], ["1.0"])

    def test_included_build_owns_its_properties(self):
        self.check({
            "settings.gradle.kts": 'includeBuild("included")',
            "gradle.properties": "release=1.1",
            "included/settings.gradle.kts": 'include(":app")',
            "included/gradle.properties": "release=2.0",
            "included/app/build.gradle.kts": '''val release: String by project
dependencies { implementation("spec.fixture:codec:$release") }''',
            "build.gradle.kts": '''val release: String by project
dependencies { implementation("spec.fixture:codec:$release") }''',
        }, ["2.0", "1.1"], ["1.1"])

    def test_nested_comment_cannot_import_an_unrelated_version_catalog(self):
        catalog = '[libraries]\ncodec = "spec.fixture:codec:{}"'
        setting = 'dependencyResolutionManagement {{ versionCatalogs {{ create("libs") {{ from(files("{}")) }} }} }}'
        for selected, expected in ((None, "2.0"), ("fixed", "2.0"), ("affected", "1.1")):
            with self.subTest(selected=selected):
                self.check({
                    "settings.gradle.kts": "/* note /* nested */ " + setting.format("unused/libs.versions.toml")
                    + " */\n" + (setting.format(selected + "/libs.versions.toml") if selected else ""),
                    "gradle/libs.versions.toml": catalog.format("2.0"),
                    "unused/libs.versions.toml": catalog.format("1.1"),
                    "fixed/libs.versions.toml": catalog.format("2.0"),
                    "affected/libs.versions.toml": catalog.format("1.1"),
                    "build.gradle.kts": 'dependencies { implementation(libs.codec) }',
                }, [expected], [expected] if expected == "1.1" else [])

    def test_dynamic_selector_needs_a_lock_for_the_same_configuration(self):
        self.check({
            "build.gradle.kts": '''dependencies {
    compileOnly("spec.fixture:codec:[1.0,3.0)")
    runtimeOnly("spec.fixture:codec:[1.0,3.0)")
}''',
            "gradle.lockfile": "spec.fixture:codec:2.0=compileClasspath\nspec.fixture:codec:1.0=runtimeClasspath",
        }, ["2.0", "1.0"], ["1.0"])

    def test_dynamic_range_without_a_matching_lock_stays_unresolved(self):
        selector = "[1.0,3.0)"
        self.check({
            "build.gradle.kts": f'dependencies {{ compileOnly("{MODULE}:{selector}") }}',
            "gradle.lockfile": f"{MODULE}:1.1=testRuntimeClasspath",
        }, [selector], query_versions=[])

    def test_lock_must_satisfy_strict_versions_and_range_bounds(self):
        for selector, locked, expected in [
            ("2.0", "1.1", None), ("1.1", "1.1", "1.1"),
            ("[1.1,2.0)", "1.0", None), ("[1.1,2.0)", "1.1", "1.1"),
            ("[1.1,2.0)", "2.0", None), ("]1.1,2.0]", "2.0", "2.0"),
            ("]1.1,2.0]", "1.1", None),
        ]:
            for declaration in (f'implementation("{MODULE}:{selector}!!")',
                                f'implementation("{MODULE}") {{ version {{ strictly("{selector}") }} }}',
                                'implementation(libs.codec)'):
                with self.subTest(selector=selector, locked=locked, declaration=declaration):
                    self.check({
                        "build.gradle.kts": "dependencies { " + declaration + " }",
                        "gradle/libs.versions.toml": '[libraries]\ncodec = { module = "' + MODULE
                        + '", version.strictly = "' + selector + '" }',
                        "gradle.lockfile": f"{MODULE}:{locked}=runtimeClasspath",
                    }, [expected], [locked] if expected == "1.1" else [], [expected] if expected else [])
