import unittest
from unittest.mock import patch

from garden.maven import LegacyEntry
from garden.models import Source
from garden.scanners import analyze


MODULE = "org.apache.commons:commons-text"
ADVISORY = "CVE-2022-42889"


class GradleRichVersions(unittest.TestCase):
    def check(self, declaration, expected, lock=None, prefix="", catalog=None):
        build = Source(path="app/build.gradle.kts", text=prefix + "\ndependencies {\n" + declaration + "\n}")
        files = [build]
        if catalog is not None:
            files.append(Source(path="gradle/libs.versions.toml", text=catalog))
        if lock is not None:
            files.append(Source(path="app/gradle.lockfile", text=f"{MODULE}:{lock}=runtimeClasspath"))
        for extended in ("0", "1"):
            with self.subTest(extended=extended), patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": extended}):
                result = analyze("sca", files, "*")
                self.assertEqual(len(result.packages), 1)
                checked = result.packages[0]
                self.assertEqual((checked.package, checked.status), (MODULE, "checked" if expected else "unresolved"))
                if expected:
                    self.assertEqual(checked.version, expected)
                self.assertEqual(bool(result.issues), expected is None)
                actual = [(f.path, f.line, f.dependency.version, f.advisory) for f in result.findings]
                self.assertEqual(actual, [(build.path, 3, expected, ADVISORY)] if expected == "1.9" else [])
                self.assertEqual(result.lockfile.packages, [])

    def test_declared_version_overrides(self):
        for coordinate, clause, expected in [
            (MODULE, 'strictly("1.9")', "1.9"),
            (MODULE + ":1.9", 'require(fixed)', "1.10.0"),
            (MODULE + ":1.9", 'strictly(fixed); require("1.9")', "1.9"),
            (MODULE + ":1.10.0", 'require("1.9"); strictly(fixed)', "1.10.0"),
            (MODULE + ":1.10.0", 'prefer("1.9")', "1.10.0"),
            (MODULE + ":1.9", 'strictly("[1.9,2.0["); prefer("1.9")', None),
            (MODULE + ":1.9", 'reject("1.9")', None),
            (MODULE + ":1.9", 'reject("2.0")', "1.9"),
            (MODULE + ":1.9", 'reject("1.9"); require("1.9")', "1.9"),
            (MODULE + ":1.9", "rejectAll()", None),
            (MODULE + ":1.9", "strictly(readVersion())", None),
            (MODULE + ":1.9", 'if (flag) strictly(fixed)', None),
        ]:
            with self.subTest(coordinate=coordinate, clause=clause):
                self.check(f'implementation("{coordinate}") {{ version {{ {clause} }} }}',
                           expected, prefix='val fixed = "1.10.0"')

    def test_lock_file_precedes_version_constraints(self):
        self.check(f'runtimeOnly("{MODULE}") {{ version {{ require("1.9") }} }}', "1.10.0", lock="1.10.0")

    def test_only_the_dependency_being_configured_changes(self):
        declaration = (f'implementation("{MODULE}:1.9") {{ because(version) }}\n'
                       f'constraints {{ implementation("{MODULE}") {{ version {{ strictly("1.9") }} }} }}')
        self.check(declaration, "1.9", prefix='val version = "compatibility"')

    def test_local_bindings_and_conditional_configuration(self):
        for block, expected in [
            ('val selected = "1.9"; version { strictly(selected) }', "1.9"),
            ('version { val selected = "1.9"; strictly(selected) }', "1.9"),
            ('if (flag) { version { strictly(selected) } }', None),
        ]:
            with self.subTest(block=block):
                self.check(f'implementation("{MODULE}:1.9") {{ {block} }}', expected,
                           prefix='val selected = "1.10.0"')

    def test_catalog_rejections(self):
        for version, lock, expected in [
            ('strictly = "1.9", reject = ["1.10.0"]', None, "1.9"),
            ('require = "1.9", reject = ["1.9"]', None, None),
            ('require = "1.9", rejectAll = true', None, None),
            ('require = "1.9", reject = ["1.9"]', "1.10.0", "1.10.0"),
        ]:
            with self.subTest(version=version, lock=lock):
                catalog = f'[versions]\ntext = {{ {version} }}\n[libraries]\ntext = {{ module = "{MODULE}", version.ref = "text" }}'
                self.check("implementation(libs.text)", expected, lock=lock, catalog=catalog)

    def test_strict_shorthand(self):
        for wanted, expected in [("1.9!!", "1.9"), ("1.10.0!!", "1.10.0"), ("[1.9,2.0[!!1.9", None)]:
            with self.subTest(wanted=wanted):
                self.check(f'implementation("{MODULE}:{wanted}")', expected)

    def test_malformed_catalog_keeps_other_findings(self):
        build = Source(path="build.gradle.kts", text=f'dependencies {{\n implementation(libs.text)\n api("{MODULE}:1.9")\n}}')
        catalog = Source(path="gradle/libs.versions.toml", text=f'[libraries]\ntext = {{module = "{MODULE}", version = 19}}')
        result = analyze("sca", [build, catalog], "*")
        self.assertEqual([f.advisory for f in result.findings], [ADVISORY])
        self.assertTrue(any(catalog.path in issue for issue in result.issues))


class GradleModuleNotation(unittest.TestCase):
    def test_classifier_and_extension_keep_exact_module_version(self):
        for suffix, direct, locked, expected in [
            ("@jar", "1.9", None, "1.9"),
            (":tests", "1.9", None, "1.9"),
            (":tests@jar", "1.10.0", None, "1.10.0"),
            (":tests@jar", "1.9", "1.10.0", "1.10.0"),
            ("@jar", "1.10.0", "1.9", "1.9"),
        ]:
            for mode in ("0", "1"):
                with self.subTest(suffix=suffix, declared=direct, lock=locked, mode=mode), patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": mode}):
                    build = Source(path="app/build.gradle.kts", text='val v = "' + direct + '"\n'
                                   f'dependencies {{ testRuntimeOnly("{MODULE}:$v{suffix}") }}')
                    files = [build]
                    if locked:
                        files.append(Source(path="app/gradle.lockfile", text=f"{MODULE}:{locked}=testRuntimeClasspath"))
                    result = analyze("sca", files, "*")
                    self.assertEqual([(p.package, p.version, p.source) for p in result.packages],
                                     [(MODULE, expected, "gradle.lockfile" if locked else "declaration")])
                    self.assertEqual([(f.path, f.line, f.advisory, f.dependency.version) for f in result.findings],
                                     [(build.path, 2, ADVISORY, expected)] if expected == "1.9" else [])
                    self.assertEqual(result.issues + result.lockfile.issues, [])
                    self.assertEqual(result.lockfile.packages, [])

    def test_invalid_notation_cannot_claim_a_locked_module(self):
        build = Source(path="build.gradle.kts", text=f'dependencies {{ implementation("{MODULE}:1.9:jdk8:extra") }}')
        lock = Source(path="gradle.lockfile", text=f"{MODULE}:1.9=runtimeClasspath")
        for mode in ("0", "1"):
            with self.subTest(mode=mode), patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": mode}):
                result = analyze("sca", [build, lock], "*")
                self.assertEqual(result.findings, [])
                self.assertEqual(result.packages, [])
                self.assertTrue(result.issues)
                self.assertEqual([p.scope for p in result.lockfile.packages], ["unclassified"] if mode == "1" else [])

    def test_add_uses_value_of_configuration_variable_to_select_lock(self):
        for name, value, version in [
            ("bucket", "runtimeOnly", "1.9"),
            ("runtimeOnly", "compileOnly", "1.10.0"),
            ("custom", "auditTools", "1.10.0"),
        ]:
            build = Source(path="build.gradle.kts", text='val auditTools by configurations.creating\n'
                           f'dependencies {{ val {name} = "{value}"; add({name}, "{MODULE}") }}')
            lock = Source(path="gradle.lockfile", text=f"{MODULE}:1.9=runtimeClasspath\n{MODULE}:1.10.0=compileClasspath,auditTools")
            for mode in ("0", "1"):
                with self.subTest(name=name, value=value, mode=mode), patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": mode}):
                    result = analyze("sca", [build, lock], "*")
                    self.assertEqual([(p.version, p.source) for p in result.packages], [(version, "gradle.lockfile")])
                    self.assertEqual([f.advisory for f in result.findings], [ADVISORY] if version == "1.9" else [])
                    self.assertEqual(result.issues, [])

    def test_computed_configuration_is_reported_as_incomplete(self):
        build = Source(path="build.gradle.kts", text=f'dependencies {{ add(selectConfiguration(), "{MODULE}:1.9") }}')
        for mode in ("0", "1"):
            with self.subTest(mode=mode), patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": mode}):
                result = analyze("sca", [build], "*")
                self.assertEqual(result.findings, [])
                self.assertTrue(any("конфигурацию Gradle" in issue for issue in result.issues))


class GradleCatalogProviders(unittest.TestCase):
    catalog = Source(path="gradle/libs.versions.toml", text='''[libraries]
boot-bom = "org.springframework.boot:spring-boot-dependencies:4.0.9"
old-text = "org.apache.commons:commons-text:1.9"
json = "org.json:json:20230227"
[bundles]
tools = ["old-text", "json"]
''')

    def test_realized_bom_and_library_with_classified_lock_entries(self):
        lock = Source(path="app/gradle.lockfile", text=f"{MODULE}:1.10.0=runtimeClasspath\norg.yaml:snakeyaml:1.33=runtimeClasspath")
        for platform in ("platform", "enforcedPlatform"):
            build = Source(path="app/build.gradle.kts", text=f'''dependencies {{
    implementation({platform}(libs.boot.bom.get()))
    implementation(libs.old.text.get())
    runtimeOnly("{MODULE}:1.9:tests@jar")
}}''')
            for mode in ("0", "1"):
                with self.subTest(platform=platform, mode=mode), patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": mode}):
                    result = analyze("sca", [build, self.catalog, lock], "*")
                    self.assertEqual(result.issues + result.lockfile.issues, [])
                    self.assertEqual(result.findings, [])
                    self.assertEqual([(p.line, p.package, p.version) for p in result.packages],
                                     [(2, "org.springframework.boot:spring-boot-dependencies", "4.0.9"),
                                      (3, MODULE, "1.10.0"), (4, MODULE, "1.10.0")])
                    transitive = [(p.package, p.scope, [a.id for a in p.advisories]) for p in result.lockfile.packages]
                    self.assertEqual(transitive, [("org.yaml:snakeyaml", "transitive", ["CVE-2022-1471"])] if mode == "1" else [])

    def test_bundle_value_is_lexically_scoped(self):
        build = Source(path="app/build.gradle.kts", text=f'''val tools = libs.bundles.tools
val copy = tools
dependencies {{
    val copy = "{MODULE}:1.10.0"
    implementation(copy)
}}
dependencies {{ implementation(copy) }}''')
        for mode in ("0", "1"):
            with self.subTest(mode=mode), patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": mode}):
                result = analyze("sca", [build, self.catalog], "*")
                self.assertEqual(result.issues, [])
                self.assertEqual([(p.line, p.package, p.version) for p in result.packages],
                                 [(5, MODULE, "1.10.0"), (7, MODULE, "1.9"), (7, "org.json:json", "20230227")])
                self.assertEqual([(f.line, f.advisory) for f in result.findings], [(7, ADVISORY), (7, "CVE-2023-5072")])

    def test_only_actual_catalog_values_resolve(self):
        for expr, known in [('libs.old.text.get()', True), ('"libs.old.text"', False),
                            ('libs.old.text.map { other }', False), ('libs.old.text.get().toString()', False)]:
            with self.subTest(expr=expr):
                build = Source(path="build.gradle.kts", text=f"val tool = {expr}\ndependencies {{ implementation(tool) }}")
                result = analyze("sca", [build, self.catalog], "*")
                self.assertEqual([f.advisory for f in result.findings], [ADVISORY] if known else [])
                self.assertEqual(bool(result.issues), not known)

    def test_same_advisory_for_two_bundle_members_has_stable_distinct_ids(self):
        packages = (MODULE, "org.json:json")
        known = {p: [LegacyEntry(package=p, advisory="FIXTURE-001", introduced="1",
                                 fixed="99999999", severity="high").convert()] for p in packages}
        results = []
        with patch("garden.scanners.load_catalog", return_value=known):
            for argument in ("libs.bundles.tools", "value"):
                code = f"val value = libs.bundles.tools\ndependencies {{ implementation({argument}) }}"
                result = analyze("sca", [Source(path="build.gradle.kts", text=code), self.catalog], "*")
                self.assertEqual(result.issues, [])
                self.assertEqual([f.advisory for f in result.findings], ["FIXTURE-001", "FIXTURE-001"])
                ids = [f.id for f in result.findings]
                self.assertEqual(len(set(ids)), 2)
                results.append(ids)
        self.assertEqual(results[0], results[1])


class SpringSnapshotDependencies(unittest.TestCase):
    catalog = Source(path="gradle/libs.versions.toml", text='''[versions]
boot = "4.2.0-SNAPSHOT"
[plugins]
app = { id = "org.springframework.boot", version.ref = "boot" }
management = { id = "io.spring.dependency-management", version = "1.1.7" }
''')
    build = '''plugins {
    alias(libs.plugins.app)
    alias(libs.plugins.management)
    kotlin("jvm") version "2.2.0"
}
dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.springframework.security:spring-security-test")
    runtimeOnly("org.springframework.boot:spring-boot-starter-web")
    testImplementation("io.projectreactor:reactor-test")
}'''

    @patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": "1"})
    def test_catalog_plugins_select_an_auditable_bom_build(self):
        result = analyze("sca", [self.catalog, Source(path="build.gradle.kts", text=self.build)], "*")
        self.assertEqual(result.issues, [])
        self.assertEqual(result.checked_packages, 4)
        self.assertEqual(result.findings, [])
        self.assertEqual([p.version for p in result.packages], [
            "2.2.0", "7.2.0-20261113.100953-213", "4.2.0-20261115.171420-365", "3.9.0-20261110.081737-23",
        ])
        self.assertEqual(result.packages[0].source, "org.jetbrains.kotlin.jvm")
        self.assertIn("4.2.0-20261115.171420-365", result.packages[1].source)

    @patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": "1"})
    def test_missing_or_unapplied_bom_does_not_invent_versions(self):
        for catalog, code in [
            ([], self.build),
            ([self.catalog], self.build.replace("alias(libs.plugins.app)", "alias(libs.plugins.app) apply false")),
            ([self.catalog], self.build.replace("alias(libs.plugins.management)", "alias(libs.plugins.management) apply(false)")),
            ([Source(path=self.catalog.path, text=self.catalog.text.replace("4.2.0-SNAPSHOT", "9.9.0-SNAPSHOT"))], self.build),
        ]:
            with self.subTest():
                result = analyze("sca", [*catalog, Source(path="build.gradle.kts", text=code)], "*")
                self.assertEqual(result.checked_packages, 0)
                self.assertTrue(result.issues)

    @patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": "1"})
    def test_floating_selection_requires_dated_artifact_or_fixed_lock(self):
        module = "org.springframework.boot:spring-boot-starter-web"
        build = Source(path="build.gradle.kts", text=f'dependencies {{ runtimeOnly("{module}:4.2.0-SNAPSHOT") }}')
        for ver, status, advisories in [(None, "unresolved", []), ("4.2.0-SNAPSHOT", "unresolved", []),
                                       ("2.6.5", "checked", ["CVE-2022-22965"]), ("2.6.6", "checked", []),
                                       ("2.6.6-20220301.100000-1", "checked", ["CVE-2022-22965"])]:
            with self.subTest(version=ver):
                locks = [Source(path="gradle.lockfile", text=f"{module}:{ver}=runtimeClasspath")] if ver else []
                result = analyze("sca", [build, *locks], "*")
                self.assertEqual([p.status for p in result.packages], [status])
                self.assertEqual([f.advisory for f in result.findings], advisories)

    @patch.dict("os.environ", {"GARDEN_EXTENDED_SCA": "1"})
    def test_floating_transitive_version_does_not_count_as_checked(self):
        module = "org.springframework.boot:spring-boot-starter-web"
        lock = Source(path="gradle.lockfile", text=f"{module}:4.2.0-SNAPSHOT=runtimeClasspath")
        result = analyze("sca", [Source(path="build.gradle.kts", text="dependencies {}"), lock], "*")
        self.assertEqual(result.lockfile.checked, 0)
        self.assertEqual([(p.scope, p.status) for p in result.lockfile.packages], [("transitive", "unresolved")])
