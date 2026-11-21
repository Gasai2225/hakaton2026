"""Three independently labelled switches in a small, inert classroom project."""
import itertools
import unittest

from garden.models import Source
from garden.scanners import analyze
from garden.submission import submission


class IndependentControls(unittest.TestCase):
    def test_each_change_affects_only_its_own_finding(self):
        for secret, cors, dependency, nested, reverse, windows in itertools.product((False, True), repeat=6):
            with self.subTest(secret=secret, cors=cors, dependency=dependency, nested=nested, reverse=reverse, windows=windows):
                prefix = "archive/кружок/" if nested else ""
                padding = "\n\n" if nested else ""
                config = prefix + "src/main/resources/application.properties"
                controller = prefix + "src/main/kotlin/ClassList.kt"
                build = prefix + "build.gradle.kts"
                expected = []
                value = "classroom-red-marker" if secret else "${CLASSROOM_KEY}"
                origin = "*" if cors else "https://classroom.example"
                version = "1.14.1" if dependency else "1.14.2"
                if secret:
                    expected.append(("SECRET", config, "api-key", 2 + padding.count("\n")))
                if cors:
                    expected.append(("SAST", controller, "credentialed-cors", 3 + padding.count("\n")))
                if dependency:
                    expected.append(("SCA", build, "org.jsoup:jsoup:1.14.1", "CVE-2021-37714"))
                files = [
                    Source(path=config, text=padding + f"# Classroom connection\nclassroom.api-key={value}\n"),
                    Source(path=controller, text=padding + "import org.springframework.web.bind.annotation.*\n"
                           "@RestController\n" + f'@CrossOrigin(originPatterns=["{origin}"], allowCredentials="true")\n'
                           'class ClassList { @GetMapping("/classes") fun list() = listOf("art") }\n'),
                    Source(path=build, text=padding + f'dependencies {{ implementation("org.jsoup:jsoup:{version}") }}\n'),
                ]
                if reverse:
                    files.reverse()
                if windows:
                    files = [Source(path=f.path.replace("/", "\\"), text="\ufeff" + f.text.replace("\n", "\r\n"))
                             for f in files]
                found = []
                for kind in ("secrets", "sast", "sca"):
                    analysis = analyze(kind, files, "*", extended_sca=False)
                    self.assertEqual(analysis.issues, [])
                    self.assertGreater(analysis.checked, 0)
                    found.extend(analysis.findings)
                actual = []
                for row in submission(found)["findings"]:
                    if row["category"] == "SCA":
                        actual.append(("SCA", row["path"], f'{row["group"]}:{row["artifact"]}:{row["version"]}',
                                       row["advisoryId"]))
                    else:
                        actual.append((row["category"], row["path"], row["class"], row["line"]))
                self.assertCountEqual(actual, expected)
