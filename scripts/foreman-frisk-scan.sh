#!/usr/bin/env bash
# TEMPLATE, installed nowhere: frisk ships only the `frisk` and `frisk-mcp` commands.
#
# Foreman's admission scan runs `frisk-scan --stdin --json` (20 s timeout) when a command of
# that name is on its PATH, and reads severity, rule and message from findings[]. Making that
# command switches frisk on as Foreman's admission scanner, so it is an owner act: copy this
# file, fill in FRISK_COMMAND, and put the copy on Foreman's PATH under the name frisk-scan.
#
#   foreman-frisk-scan.sh FRISK_COMMAND [ARGS...]
#
# FRISK_COMMAND is the path of a frisk executable, or a quoted multi-word command such as
# "python3 -m frisk.cli" (split on whitespace; no globbing, no eval). ARGS are passed on.
# `--fail-on never` goes before them: Foreman treats any non-zero exit as "frisk failed" and
# drops its findings, so a BLOCK must still exit 0 (an input error still exits 2).
set -euo pipefail

if [ "$#" -lt 1 ] || [ -z "$1" ]; then
  echo "usage: foreman-frisk-scan.sh FRISK_COMMAND [ARGS...]" >&2
  exit 2
fi
frisk_command=$1
shift
if [ -f "$frisk_command" ] && [ -x "$frisk_command" ]; then
  command=("$frisk_command")
else
  read -r -a command <<<"$frisk_command"
fi
if [ "${#command[@]}" -eq 0 ]; then
  echo "foreman-frisk-scan.sh: FRISK_COMMAND is empty" >&2
  exit 2
fi
exec "${command[@]}" --fail-on never "$@"
