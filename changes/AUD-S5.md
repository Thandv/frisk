### Fixed: findings inside markdown code fences report their file line (AUD-S5)

A finding inside a ```` ``` ```` fence used to be reported at its line within the fence
(the pipe-to-shell installer in `examples/malicious-skill/SKILL.md` showed as line 1).
It is now reported at its line in the file (line 11), in text, `--json` and `--sarif`
output, so GitHub code-scanning annotations land on the right line.

Line numbers are now looked up in a per-file line index, so files with many matches
no longer slow down quadratically.

Internally the engine runs its rules on "surfaces" (`src/frisk/surfaces/`): `plain`
(the whole file) and `fences` (code fences in non-code files). A surface that fails on
a file no longer stops the scan; the rest of the file and every other file are still
scanned, and the failure is recorded in the scan's coverage.
