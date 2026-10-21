"""docs/rules.md has exactly one exact-id anchor per rule in rules.py, and agrees with it.

Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import re
import unittest
from collections import Counter
from pathlib import Path

from frisk import rules

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "rules.md"
ANCHOR = re.compile(r'<a id="([^"]+)"></a>')
META_LINE = re.compile(r"^- Severity: `(\w+)` · Category: `([\w-]+)` · OWASP LLM Top 10 \(2025\): (.+)$")


def sections(text: str) -> dict[str, str]:
    """Map each anchor id to the text up to the next anchor."""
    parts = ANCHOR.split(text)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


class TestRulesDoc(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOC.read_text(encoding="utf-8")
        self.ids = set(rules.RULE_META)

    def test_rule_ids_come_from_the_rule_lists(self) -> None:
        listed = {r[0] for r in rules.CODE_RULES + rules.TEXT_RULES} | {rules.UNICODE_RULE[0]}
        self.assertEqual(self.ids, listed)

    def test_every_rule_has_exactly_one_anchor(self) -> None:
        counts = Counter(ANCHOR.findall(self.text))
        self.assertEqual({rid: n for rid, n in counts.items() if n != 1}, {})
        self.assertEqual(sorted(self.ids - set(counts)), [])

    def test_every_anchor_names_a_real_rule(self) -> None:
        self.assertEqual(sorted(set(ANCHOR.findall(self.text)) - self.ids), [])

    def test_heading_follows_each_anchor(self) -> None:
        for rid in self.ids:
            self.assertIn(f'<a id="{rid}"></a>\n### {rid}\n', self.text)

    def test_severity_category_and_owasp_match_the_code(self) -> None:
        for rid, body in sections(self.text).items():
            with self.subTest(rule=rid):
                lines = [m for m in map(META_LINE.match, body.splitlines()) if m]
                self.assertEqual(len(lines), 1)
                cat, sev, _desc = rules.RULE_META[rid]
                self.assertEqual(lines[0].groups(), (sev, cat, rules.owasp_for(cat) or "none"))
                for label in ("- Matches: ", "- Likely false positive: ", "- On a hit: "):
                    self.assertIn(label, body)

    def test_readme_links_the_reference(self) -> None:
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        what = readme.split("## What it detects", 1)[1].split("\n## ", 1)[0]
        self.assertIn("(docs/rules.md)", what)


if __name__ == "__main__":
    unittest.main()
