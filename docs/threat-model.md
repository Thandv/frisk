# frisk threat model

What frisk defends against, what it deliberately does not, and how it protects itself.
Each limitation names the code it comes from. Reporting a vulnerability in frisk:
[SECURITY.md](../SECURITY.md).

## What frisk defends against

The asset is the machine and the accounts of the person who runs an AI agent: their files,
credentials and keys, and the instructions their agent follows. The attacker publishes, or
later changes, content that the agent installs or reads: an MCP server, a Claude Code
skill, plugin or subagent, Cursor rules, or a tool's description and results.

| Threat | frisk's answer |
|---|---|
| Content that runs code on install or use: a download piped into a shell, evaluated strings, shell injection, unpickling | Code rules ([docs/rules.md](rules.md#code-rules)), before install: `frisk PATH`, the GitHub Action, frisk-mcp. |
| Content that steals secrets: reads of key and credential locations, the macOS password store, network egress | Code rules (`exfil.*`) and, in agent-instruction files, instructions to hand over key material. |
| Destructive commands | `destroy.*` rules. |
| Prompt injection and tool poisoning: text that addresses the model, hides actions from the user, or carries hidden characters | Text rules, instruction rules and the hidden-Unicode check, on every file and in every scan context. |
| A server that was clean when approved and changes later (rug pull) | `frisk lock` / `frisk verify` pin content and launch details; `frisk proxy` pins each tool and re-checks it on every load ([proxy.md](proxy.md)). |
| An agent installing something it has not vetted | frisk-mcp gives it the scanner as tools ([mcp-server.md](mcp-server.md)). |
| A clean verdict that hides what was not read | Coverage findings: an unread, undecodable, oversized or unscanned file, server or text never leaves the verdict at PASS (`coverage.*`). |

## Accepted limitations

frisk is a pattern matcher with no execution, so these are known and accepted; a PASS means
"no known-bad pattern found", not "safe" (SECURITY.md, "Scope & limitations").

1. **The patterns can be evaded.** A determined author can build a command from pieces,
   encode it in a way frisk does not decode, use a synonym, or split a phrase across lines
   (SECURITY.md; every rule is a regular expression, `src/frisk/rules.py`). frisk reads the
   raw text: a phrase spelled with HTML character references (which a renderer shows as
   ordinary text) is not decoded and not matched; only JSON string escapes are decoded
   (`src/frisk/surfaces/json_values.py`).
2. **Every window is bounded.** Each rule looks for its parts within a fixed distance, so
   the scan stays linear: `rce.eval_b64` and `rce.shell_true` within 400 characters of the
   call (`src/frisk/rules.py:153`, `:163`), `exfil.secret_env_read` 30 characters
   (`:186`), `inject.exfil_instr` 40-45 characters per part (`:253`),
   `inject.hide_from_user` 30 (`:259`), `inject.before_using` 40 (`:265`),
   `inject.read_then_send` 40 (`:270`), `inject.sensitive_path_instruction` 60 characters in
   one sentence (`:287`), and `destroy.rm_rf` 256 words of one command (`:111`). Parts
   placed further apart are not matched.
3. **Size limits.** A file over `--max-file-bytes` (default 2 MiB, `src/frisk/engine.py:31`)
   is not read; it blocks (`coverage.too_large`), so this fails closed. A string over the
   limit (`--text`, frisk-mcp's `scan_text`, proxy messages) has only its first and last
   halves matched (`src/frisk/engine.py:208`) and warns; standard input past the limit is
   not matched at all (`src/frisk/cli.py`, `_scan_stdin`) and warns. A directory walk stops
   after 20,000 files (`src/frisk/engine.py:30`), frisk-mcp's also at 200 MiB or 30 s
   (`src/frisk/mcp_server.py:46`), and warns. With the default `--fail-on block`, a
   warning does not fail the scan.
4. **Real media files are not read past their first bytes.** A file with a media extension
   (`.png`, `.pdf`, `.woff` and the rest of `MEDIA_EXTS`, `src/frisk/rules.py`) whose first
   1,024 bytes hold a NUL byte or are not UTF-8 is skipped silently (`src/frisk/engine.py`,
   `_text_head`); text saved under such a name is scanned. Content appended after a real
   media header (a polyglot file) is not scanned, and the verdict can still be PASS.
5. **Runtime behaviour is not observed.** A remote (HTTP/SSE) server, a package not in the
   local cache, and the dependencies of a cached package are listed, not scanned
   (`coverage.unscanned`, `src/frisk/cli.py`, `_audit_config`); a console-script wrapper's
   package is not read. Code that fetches more code at run time is judged only by what is
   on disk.
6. **Inline code in ordinary documents only warns.** A code-rule hit in a markdown inline
   code span outside an agent-instruction file reports at most `warn`
   (`src/frisk/engine.py:132`), so a README that names a risky command does not block.
   Text rules keep their severity everywhere.
7. **The proxy sees messages, not code.** It wraps stdio servers only; in tool results it
   runs only the injection, credential-instruction and harmful-command rules, so code in a
   result is not judged by the other code rules (`src/frisk/rules.py`, `CONTEXTS`). Its
   first log line names the server command with secrets redacted by pattern, as debug lines
   are (`src/frisk/proxy.py`, `run`): a secret in another form, such as a bare token as an
   argument of its own, reaches the log as written.
8. **Pins cover what frisk can see.** `frisk lock` does not pin `PATH`, pins a git URL
   without its credentials, and redacts secrets by pattern only, so a secret in another
   form is pinned (as a hash) as written (README, "Detect rug pulls").
9. **frisk-mcp without roots can read most paths.** Unless `FRISK_MCP_ROOTS` is set, an
   agent may scan any local path except `/`, the home directory itself and `/System`
   (`src/frisk/mcp_server.py`, `_check_scope`). Results carry rule ids and `path:line`,
   never excerpts.

No hand review notes of further accepted limitations exist in this repository (there is
no `docs/reviews/`).

## How frisk protects itself

frisk is pointed at hostile content by design, so it treats everything it reads as data.

- **Zero execution.** It never imports, runs or evaluates scanned content; rules are
  regular expressions over text (`src/frisk/rules.py:1-4`). Runtime dependencies: none, the
  standard library only (`pyproject.toml:21`).
- **Linear-time patterns.** Every window is bounded and stops at another start of the same
  rule, so crafted input cannot make a rule backtrack for long (`src/frisk/rules.py:15-19`;
  `tests/test_perf.py` times each rule on 1 MiB of adversarial text).
- **Bounded input.** File size, file count, bytes read and time are capped (limitation 3);
  JSON integer literals are bounded (`src/frisk/jsonread.py`), and JSON nested too deep to
  read is an error, not a crash (`src/frisk/proxy.py`, `_parse`; `src/frisk/mcp_server.py`,
  `_respond`).
- **No reads outside the target.** A symlink is never followed out of the scan root; it is an
  `fs.symlink_escape` finding, blocking when it points at a credential location
  (`src/frisk/engine.py:367`).
- **Hardened git.** Clones of untrusted URLs allow only https and ssh, run no hooks, write no
  symlinks, fetch no submodules or LFS objects, ignore the system git config and never
  prompt (`src/frisk/sources.py:62`), and time out after 120 s (`src/frisk/sources.py:134`).
  A URL's credentials are never printed or stored.
- **Safe output.** Excerpts mask secret-like values (`src/frisk/redact.py`); control
  characters and hidden Unicode in names, paths and excerpts are printed as escapes, so
  scanned content cannot rewrite the terminal (`src/frisk/report.py:43`).
- **The proxy fails closed.** A tool, entry or content item it cannot inspect is dropped, a
  message whose inspection fails reaches the client as an error, and a server request it
  cannot inspect is refused (`src/frisk/proxy.py:37-40`). Its pins file holds hashes only,
  written atomically with mode 0600 in a 0700 directory.
- **frisk-mcp keeps serving.** A malformed request gets a JSON-RPC error and a fault inside
  frisk answers `-32603`, never ending the loop; results never include scanned text
  (`src/frisk/mcp_server.py`, `_respond`, `_summary`).
- **The Action** passes its inputs to the scan through environment variables only, never as
  script text, and installs frisk into its own venv (`action.yml`).
