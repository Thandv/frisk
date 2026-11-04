#!/usr/bin/env bash
# Run the test suite under every local interpreter frisk supports, then the linters, as CI does.
#
# Candidates: the macOS Command Line Tools python3 (3.9, the runtime floor) and
# python3.12 / 3.13 / 3.14 from Homebrew (/opt/homebrew/bin or /usr/local/bin), or
# exactly the space-separated interpreter paths in FRISK_VERIFY_PYTHONS (CI sets it to
# the job's python). A missing candidate is skipped.
# Interpreters are deduplicated by resolved path. Each runs the stdlib unittest suite, and
# pytest too when pytest imports for it (CI's test jobs run both); one PASS/FAIL line per
# run, naming the runner, and a 'skip' line when pytest is not importable.
# Then `ruff check` and `mypy src` (CI's lint job), each only when it is on PATH, else a
# 'skipped: <tool> not on PATH' line.
# Exits non-zero if any run fails, or if fewer than FRISK_MIN_PYTHONS (default 2)
# interpreters ran, so it can never pass vacuously.
# It makes no network access and installs nothing (no pip, no venv).
set -u -o pipefail

min="${FRISK_MIN_PYTHONS:-2}"
case "$min" in
  ''|*[!0-9]*) echo "verify: FRISK_MIN_PYTHONS must be a non-negative integer, got '$min'" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.." || exit 2

if [ -n "${FRISK_VERIFY_PYTHONS:-}" ]; then
  read -r -a candidates <<<"$FRISK_VERIFY_PYTHONS"
else
  candidates=(/Library/Developer/CommandLineTools/usr/bin/python3)
  for prefix in /opt/homebrew/bin /usr/local/bin; do
    for v in 3.12 3.13 3.14; do
      candidates+=("$prefix/python$v")
    done
  done
fi

seen=" "
ran=0
failed=0
log="$(mktemp "${TMPDIR:-/tmp}/frisk-verify.XXXXXX")" || exit 2
trap 'rm -f "$log"' EXIT

for py in "${candidates[@]}"; do
  if [ ! -x "$py" ]; then
    [ -n "${FRISK_VERIFY_PYTHONS:-}" ] && echo "skip: $py not found"
    continue
  fi
  real="$("$py" -c 'import os, sys; print(os.path.realpath(sys.executable))' 2>/dev/null)" || continue
  case "$seen" in *" $real "*) continue ;; esac
  seen="$seen$real "
  version="$("$py" -c 'import platform; print(platform.python_version())')"
  ran=$((ran + 1))
  if PYTHONPATH=src "$py" -B -m unittest discover -s tests >"$log" 2>&1; then
    printf 'PASS  %-8s %s  unittest  (%s)\n' "$version" "$py" "$(tail -n 3 "$log" | grep -m1 '^Ran ')"
  else
    failed=$((failed + 1))
    printf 'FAIL  %-8s %s  unittest\n' "$version" "$py"
    sed 's/^/    /' "$log" | tail -n 30
  fi
  if ! "$py" -c 'import pytest' >/dev/null 2>&1; then
    printf 'skip  %-8s %s  pytest not importable\n' "$version" "$py"
  elif "$py" -B -m pytest -q >"$log" 2>&1; then
    printf 'PASS  %-8s %s  pytest  (%s)\n' "$version" "$py" "$(tail -n 1 "$log")"
  else
    failed=$((failed + 1))
    printf 'FAIL  %-8s %s  pytest\n' "$version" "$py"
    sed 's/^/    /' "$log" | tail -n 30
  fi
done

if [ "$ran" -lt "$min" ]; then
  echo "verify: only $ran interpreter(s) ran; FRISK_MIN_PYTHONS=$min" >&2
  exit 1
fi

lint_failed=0
for tool in "ruff check" "mypy src"; do
  name="${tool%% *}"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "skipped: $name not on PATH"
  elif $tool >"$log" 2>&1; then
    echo "PASS  $tool"
  else
    lint_failed=$((lint_failed + 1))
    echo "FAIL  $tool"
    sed 's/^/    /' "$log" | tail -n 30
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "verify: $failed test run(s) failed on $ran interpreter(s)" >&2
  exit 1
fi
if [ "$lint_failed" -ne 0 ]; then
  echo "verify: $lint_failed linter(s) failed" >&2
  exit 1
fi
echo "verify: all $ran interpreter(s) passed"
