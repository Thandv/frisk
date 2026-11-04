"""Write docs/rules.md from the rule tables in src/frisk/rules.py and the prose in scripts/rule_docs.py.

Each rule gets an exact-id anchor (`<a id="<rule id>"></a>`, since GitHub heading slugs drop
the dots), so SARIF helpUri links resolve; then its severity, category, OWASP entry, the
description frisk reports, where it runs (files, and the engine.scan_text contexts the
rule names), and rule_docs' matches, rationale, example, false positive and advice.

  python3 scripts/gen_rules_doc.py           rewrite docs/rules.md
  python3 scripts/gen_rules_doc.py --check   exit 1 if docs/rules.md is stale (writes nothing)

tests/test_rules_doc.py fails when docs/rules.md differs from render().
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "rules.md"
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from frisk import engine, rules  # noqa: E402 - after the sys.path setup above
from rule_docs import RULE_DOCS, SECTION_INTROS  # noqa: E402

# (section title, the rules in it as (id, category, severity, description, contexts), what files it runs on)
SECTIONS = [
    ("Code rules", [(r[0], r[1], r[2], r[4], r[5]) for r in rules.CODE_RULES],
     "code in files: scripts and the code parts of other files (see [Files](#files))"),
    ("Text rules", [(r[0], r[1], r[2], r[4], r[5]) for r in rules.TEXT_RULES], "the text of every file"),
    ("Instruction rules", [(r[0], r[1], r[2], r[4], r[5]) for r in rules.INSTRUCTION_RULES],
     "agent-instruction files"),
    ("Prose rules", [(r[0], r[1], r[2], r[4], r[5]) for r in rules.PROSE_RULES], "no files"),
    ("Hidden characters", [(*r, frozenset(rules.CONTEXTS)) for r in rules.UNICODE_RULES], "the text of every file"),
    ("Coverage", [(*r, frozenset()) for r in rules.COVERAGE_RULES], "reported by the scan itself, not a pattern"),
]

HEADER = """\
# frisk rule reference

One section per rule id. Each anchor equals the id exactly, so `docs/rules.md#<rule-id>` links
(SARIF `helpUri`) resolve. Payloads are described in words, and "Reported as" quotes the
description frisk prints for a finding, unless that quotes a phrase frisk blocks on.

This file is generated: `python3 scripts/gen_rules_doc.py` writes it from the rule tables in
`src/frisk/rules.py` and the prose in `scripts/rule_docs.py`; edit those, not this file.
`tests/test_rules_doc.py` fails while it is stale.

Severity: **block** fails a scan by default; **warn** fails only with `--fail-on warn`.
"Runs on" names the files a rule is matched in and the contexts in which it is matched in a
string (`engine.scan_text`): `default` (`--text`, `--stdin`, frisk-mcp's `scan_text`), and
`frisk proxy`'s `tool_description` and `tool_result` (see [Prose rules](#prose-rules)).
"""


def _exts(names: set[str]) -> str:
    return ", ".join(f"`{e}`" for e in sorted(names))


def _files() -> str:
    """Which files get which rules, from rules.py's extension sets and engine.py's bounds."""
    return f"""\
## Files

- Scripts get the code rules on the whole file, and the text rules: the extensions
  {_exts(rules.CODE_EXTS)}, and any file whose first line is a `#!` shebang.
- Every other file frisk reads gets the text rules, and the code rules on the code inside it
  (fenced code blocks; in markdown, {_exts(rules.MARKDOWN_EXTS)}, also indented code and inline
  code; build-file recipes; command values in JSON: see [Code rules](#code-rules)), whatever its
  extension or none (`Makefile`, `Dockerfile` and `.bashrc` are read).
- Skipped silently: media ({_exts(rules.MEDIA_EXTS)}) whose first
  {engine.MEDIA_SNIFF_BYTES:,} bytes are not text (a NUL byte, or not UTF-8), at any size. A
  media-named file that starts as text, such as a script saved as `setup.png`, is read like any
  other file.
- Not read, a [coverage.binary](#coverage.binary) warning: executables and compiled code
  ({_exts(rules.EXECUTABLE_EXTS)}) and archives ({_exts(rules.ARCHIVE_EXTS)}).
- A file that is not valid UTF-8 is scanned with the bad bytes replaced and warns
  ([coverage.unreadable](#coverage.unreadable)), unless it is opaque data
  ({_exts(rules.OPAQUE_DATA_EXTS)}: skipped silently), or has no code or text extension and no
  shebang and starts like a native executable, or holds NUL bytes and has an extension frisk
  does not list (both [coverage.binary](#coverage.binary)). The text extensions are
  {_exts(rules.TEXT_EXTS)}.
- A file over `--max-file-bytes` (default {engine.MAX_FILE_BYTES:,} bytes) is not read
  ([coverage.too_large](#coverage.too_large)), and a directory walk stops after
  {engine.MAX_FILES:,} files ([coverage.unscanned](#coverage.unscanned)).
"""


def _runs_on(files: str, contexts: frozenset[str]) -> str:
    named = [f"`{c}`" for c in rules.CONTEXTS if c in contexts]
    return f"{files}; strings: {', '.join(named)}" if named else files


def _reported(description: str) -> str:
    """The description frisk reports, quoted, unless it holds a phrase a text rule blocks on
    (text rules block in inline code too, and frisk's own docs must not block)."""
    if any(r[2] == "block" and r[3].search(description) for r in rules.TEXT_RULES):
        return "the phrase this rule matches, quoted (not repeated here)"
    return f"`{description}`"


def _rule(rid: str, category: str, severity: str, description: str, contexts: frozenset[str], files: str) -> str:
    doc = RULE_DOCS[rid]
    owasp = rules.owasp_for(category) or "none"
    return f"""\
<a id="{rid}"></a>
### {rid}

- Severity: `{severity}` · Category: `{category}` · OWASP LLM Top 10 (2025): {owasp}
- Reported as: {_reported(description)}
- Runs on: {_runs_on(files, contexts)}
- Matches: {doc.matches}
- Why it matters: {doc.why}
- Example (in words): {doc.example}
- Likely false positive: {doc.false_positive}
- On a hit: {doc.on_hit}
"""


def render() -> str:
    """docs/rules.md as the rule tables and rule_docs say it should be."""
    parts = [HEADER, _files()]
    for title, table, files in SECTIONS:
        parts.append(f"## {title}\n\n{SECTION_INTROS[title]}\n")
        parts += [_rule(*row, files) for row in table]
    return "\n".join(parts)


def main(argv: list[str]) -> int:
    check = argv == ["--check"]
    if argv and not check:
        print("usage: gen_rules_doc.py [--check]", file=sys.stderr)
        return 2
    fresh = render()
    if DOC.read_text(encoding="utf-8") == fresh:
        return 0
    if check:
        print("docs/rules.md is stale: run python3 scripts/gen_rules_doc.py", file=sys.stderr)
        return 1
    DOC.write_text(fresh, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
