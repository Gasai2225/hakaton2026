import json
import unittest

from garden.integrations import validate_report
from garden.models import Source
from garden.scanners import analyze


class AdvicePrecision(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = Source(path="build.gradle.kts", text='dependencies { implementation("org.jsoup:jsoup:1.14.1") }')
        cls.hit, = analyze("sca", [build], "*", extended_sca=False).findings

    def test_upgrade_target_is_distinct_from_test_counts_and_times(self):
        for fix, valid in [
            ("Обновите до версии 1.14.2. Повторите проверку до 2 раз.", True),
            ("Обновите до версии 1.14.2. Запустите тесты в 12:30.", True),
            ("Обновите до org.jsoup:jsoup:1.14.2.", True),
            ("Обновите с org.jsoup:jsoup:1.14.1 до 1.14.2.", True),
            ("Обновите до org.jsoup:jsoup:1.14.1.", False),
            ("Upgrade to org.jsoup:jsoup:1.14.1.", False),
            ("Установите версию 9.9.9.", False),
            ("Обновите до 1.14.1.", False),
            ("Проверьте org.example:unrelated.", False),
            ("  \n\t ", False),
        ]:
            with self.subTest(fix=fix):
                group = {"finding_ids": [self.hit.id], "risk": "Версия затронута известной уязвимостью.", "fix": fix}
                raw = json.dumps({"groups": [group]})
                if valid:
                    self.assertEqual(validate_report(raw, [self.hit]).groups[0].fix, fix)
                else:
                    with self.assertRaises(ValueError):
                        validate_report(raw, [self.hit])
