"""docs/rules.md has exactly one exact-id anchor per rule in rules.py, and agrees with it.

FR-E8 t5: docs/rules.md is what scripts/gen_rules_doc.py renders (a changed rule table or
rule_docs entry fails until it is regenerated), every SARIF helpUri report.py writes, for a
finding of each rule, names an anchor in it, and frisk scanning it finds nothing that
blocks (the two descriptions that quote an override phrase are not repeated).
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import json
import re
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from _scripts import load_script
from frisk import rules
from frisk.engine import Finding, ScanResult, scan_path
from frisk.report import to_sarif

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
        listed = ({r[0] for r in rules.CODE_RULES + rules.TEXT_RULES + rules.INSTRUCTION_RULES + rules.PROSE_RULES
                   + rules.COVERAGE_RULES}
                  | {r[0] for r in rules.UNICODE_RULES})
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



gen = load_script("gen_rules_doc")


class TestGeneratedRulesDoc(unittest.TestCase):
    def test_the_committed_doc_is_fresh(self) -> None:
        self.assertEqual(DOC.read_text(encoding="utf-8"), gen.render(),
                         "docs/rules.md is stale: run python3 scripts/gen_rules_doc.py")

    def test_a_changed_rationale_or_description_makes_it_stale(self) -> None:
        doc = gen.RULE_DOCS["rce.pickle"]
        with mock.patch.dict(gen.RULE_DOCS, {"rce.pickle": doc._replace(why="Reworded.")}):
            self.assertNotEqual(gen.render(), DOC.read_text(encoding="utf-8"))
        table = [(r[0], r[1], r[2], "reworded", r[5]) for r in rules.TEXT_RULES]
        sections = [(t, table if t == "Text rules" else rows, f) for t, rows, f in gen.SECTIONS]
        with mock.patch.object(gen, "SECTIONS", sections):
            self.assertNotEqual(gen.render(), DOC.read_text(encoding="utf-8"))

    def test_every_sarif_help_uri_names_an_anchor(self) -> None:
        result = ScanResult([Finding("<text>", 1, rid, cat, sev, desc, "", origin="text")
                             for rid, (cat, sev, desc) in rules.RULE_META.items()])
        driver = json.loads(to_sarif(result, "0"))["runs"][0]["tool"]["driver"]
        anchors = set(ANCHOR.findall(DOC.read_text(encoding="utf-8")))
        self.assertEqual(len(driver["rules"]), len(rules.RULE_META))
        for rule in driver["rules"]:
            with self.subTest(rule=rule["id"]):
                self.assertIn(rule["helpUri"].split("#", 1)[1], anchors)

    def test_the_doc_quotes_no_blocking_phrase(self) -> None:
        # tests/test_markdown.py also keeps docs/ at WARN; here the generator's own choice is
        # pinned: the two descriptions that quote an override phrase are not repeated.
        self.assertEqual([f.rule for f in scan_path(str(DOC)).findings if f.severity == "block"], [])
        text = DOC.read_text(encoding="utf-8")
        for rid, (_cat, _sev, desc) in rules.RULE_META.items():
            with self.subTest(rule=rid):
                quoted = f"- Reported as: `{desc}`\n" in sections(text)[rid]
                self.assertEqual(quoted, rid not in ("inject.ignore_prev", "inject.disregard"))

if __name__ == "__main__":
    unittest.main()
