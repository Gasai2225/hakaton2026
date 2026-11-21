import unittest

from garden.models import Source
from garden.scanners import analyze


class DatabaseVersions(unittest.TestCase):
    def check_mybatis(self, expr, expected, *, value='"3.5.5"', prefix="", lock=None):
        build = prefix + "\ndependencies {\n " + expr + "\n}"
        files = [
            Source(path="app/build.gradle.kts", text=build),
            Source(path="gradle/libs.versions.toml", text="[versions]\ndb-mybatis = " + value),
        ]
        if lock:
            files.append(Source(path="app/gradle.lockfile", text="org.mybatis:mybatis:" + lock + "=runtimeClasspath"))
        for extended in (False, True):
            with self.subTest(extended=extended, expr=expr, value=value, prefix=prefix):
                result = analyze("sca", files, "*", extended_sca=extended)
                self.assertEqual(len(result.packages), 1)
                package = result.packages[0]
                self.assertEqual(package.package, "org.mybatis:mybatis")
                self.assertEqual(package.status, "checked" if expected else "unresolved")
                if expected:
                    self.assertEqual(package.version, expected)
                self.assertEqual(bool(result.issues), expected is None)
                self.assertEqual([f.advisory for f in result.findings],
                                 ["CVE-2020-26945"] if expected == "3.5.5" else [])

    def test_catalog_get(self):
        for version in ("3.5.5", "3.5.6"):
            get = "libs.versions.db.mybatis.get()"
            for expr, prefix in [
                ('implementation("org.mybatis:mybatis:$driver")', "val driver = " + get),
                ('implementation("org.mybatis:mybatis:${' + get + '}")', ""),
                ('implementation(group="org.mybatis", name="mybatis", version=' + get + ')', ""),
                ('implementation("org.mybatis:mybatis") { version { strictly(' + get + ') } }', ""),
                ('implementation("org.mybatis:mybatis:${driver.get()}")', "val driver = libs.versions.db.mybatis"),
            ]:
                self.check_mybatis(expr, version, value=f'"{version}"', prefix=prefix)

    def test_unresolved_and_locked(self):
        decl = 'runtimeOnly("org.mybatis:mybatis:$driver")'
        for definition, catalog in [
            ("val driver = libs.versions.db.mybatis", '"3.5.5"'),
            ("val driver = libs.versions.db.other.get()", '"3.5.5"'),
            ("val libs = customCatalog()\nval driver = libs.versions.db.mybatis.get()", '"3.5.5"'),
            ("val driver = libs.versions.db.mybatis.get()", '"3.+"'),
            ("val driver = libs.versions.db.mybatis.get()", '{ strictly = "[3.5,4)", prefer = "3.5.5" }'),
        ]:
            self.check_mybatis(decl, None, prefix=definition, value=catalog)
        self.check_mybatis(decl, "3.5.6", prefix="val driver = libs.versions.db.mybatis.get()", lock="3.5.6")

    def test_boot_override_uses_kotlin_bindings(self):
        plugins = ('plugins {\n id("org.springframework.boot") version "4.1.2"\n'
                   ' id("io.spring.dependency-management") version "1.1.7"\n}\n')
        for override, props, expected in [
            ('val name = "h2.version"\nval v = "2.1.214"\nextra[name] = v', '', "2.1.214"),
            ('val v = "2.2.220"\nproject.extra.set("h2.version", v)', "v=2.1.214", "2.2.220"),
            ('extra["h2.version"] = providers.gradleProperty("db").get()', "db=2.1.214", "2.1.214"),
            ('val v = versionAtRuntime()\nextra["h2.version"] = v', "v=2.1.214", None),
            ('extra["h2.version"] = "2.1.214"\nproject.extra.set(keyAtRuntime(), "2.2.220")', "", None),
            ('extra[keyAtRuntime()] = "2.1.214"\nextra["h2.version"] = "2.2.220"', "", "2.2.220"),
            ('val extra = mutableMapOf<String, String>()\nextra["h2.version"] = "2.1.214"', "", "2.4.240"),
        ]:
            with self.subTest(override=override):
                files = [Source(path="build.gradle.kts", text=plugins + override +
                                '\ndependencies { runtimeOnly("com.h2database:h2") }'),
                         Source(path="gradle.properties", text=props)]
                result = analyze("sca", files, "*", extended_sca=True)
                self.assertEqual(result.packages[0].status, "checked" if expected else "unresolved")
                if expected:
                    self.assertEqual(result.packages[0].version, expected)
                self.assertEqual([h.advisory for h in result.findings],
                                 ["CVE-2022-45868"] if expected == "2.1.214" else [])

    def test_unknown_named_argument_cannot_inherit_bom_version(self):
        code = ('plugins {\n id("org.springframework.boot") version "4.1.2"\n'
                ' id("io.spring.dependency-management") version "1.1.7"\n}\n'
                'extra["h2.version"] = "2.1.214"\n'
                'dependencies { runtimeOnly(group="com.h2database", name="h2", version=readVersion()) }')
        result = analyze("sca", [Source(path="build.gradle.kts", text=code)], "*", extended_sca=True)
        self.assertEqual(result.packages[0].status, "unresolved")
        self.assertEqual(result.findings, [])
