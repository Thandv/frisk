# frisk proxy: check an MCP server at runtime

`frisk proxy` sits between an MCP client and a stdio MCP server. The client starts frisk;
frisk starts the real server, relays the JSON-RPC lines both ways, and inspects every
message the server sends before the client sees it. It catches a server that was clean when
you approved it and changes later (a "rug pull"), on every load rather than on a schedule.
What it checks, and how it fails closed, is in the README's
[Enforce at runtime](../README.md#enforce-at-runtime-proxy) section; this page is the
walkthrough.

```
frisk proxy [--log FILE] [--pins FILE | --no-pins] [--on-change flag|drop] -- <server command>
```

Everything after `--` is the server command, run as given (no shell).

## Walkthrough: Claude Code

1. Vet the server once before you add it: scan its source, or its MCP config entry
   (`frisk ~/.claude.json` audits every server you have configured).
2. Add the server with `frisk proxy --` in front of its command. For a server you would
   add as `claude mcp add some-server -- uvx some-mcp-server`:

   ```
   claude mcp add some-server -- frisk proxy -- uvx some-mcp-server
   ```

   Options for frisk go between `proxy` and the `--`, for example
   `frisk proxy --on-change drop --log /path/to/frisk-proxy.log -- uvx some-mcp-server`.
   In a JSON config (Claude Desktop, Cursor, `.mcp.json`) the same wrapper is
   `"command": "frisk", "args": ["proxy", "--", "uvx", "some-mcp-server"]`.
3. Start Claude Code. On the first `tools/list`, frisk scans each tool and pins it; a tool
   with a block-level finding is dropped, so the model never sees it.
4. On every later load, a tool whose definition differs from its pin is flagged (or
   dropped, with `--on-change drop`). The pins survive restarts.

The proxy needs `frisk` on the client's PATH (or an absolute path to it in the command).

## Where the pins live

Each tool is pinned by a sha256 of its `name`, `title`, `description`, `inputSchema` and
`annotations`. The pins file maps tool names to those hashes; it never holds a description.

- Default: `$XDG_STATE_HOME/frisk/pins/<hash>.json`, with `~/.local/state` when
  `XDG_STATE_HOME` is unset or not an absolute path. `<hash>` is the sha256 of the server
  command as a JSON array (`json.dumps(argv, ensure_ascii=False)`), so each distinct server
  command has its own file, and changing the command starts a fresh set of pins.
- `--pins FILE`: keep them in FILE instead.
- `--no-pins`: keep them in memory only and write nothing; a restart starts over.

The file is written only while the proxy runs, atomically (a temp file in the same
directory, then a rename), with mode 0600 in a directory created with mode 0700. To find the
default file of a server command:

```
python3 -c 'import hashlib, json, sys; print(hashlib.sha256(json.dumps(sys.argv[1:], ensure_ascii=False).encode()).hexdigest())' uvx some-mcp-server
```

A pins file that cannot be read, or is not a JSON object of tool names to hashes, is
logged and the proxy starts as on a first run. A pins file that cannot be written is
logged once (`pins not persisted`) and the proxy keeps relaying with its pins in memory.

## When a tool changes (`--on-change`)

- `--on-change flag` (the default): the changed tool is kept, its description is prefixed
  with `[frisk: definition changed since it was pinned (possible rug pull)]`, and the new
  definition is pinned. The warning shows once, on the load where the change appears.
- `--on-change drop`: the changed tool is dropped and its old pin is kept, so only the
  definition you approved gets through, on every load. To approve the new definition,
  delete the pins file (or the tool's entry in it) and restart the client.

A tool with a block-level finding is dropped whatever `--on-change` says; a tool with only
warn-level findings is kept, with the worst finding's description and rule id prefixed to its
description.

## Reading the logs

Every event is one line starting with `[frisk-proxy]`, written to stderr, which the client
keeps with the server's other output (its MCP logs), or appended to FILE with `--log FILE`.
The real server's own stderr goes to the proxy's stderr, not to the `--log` file. A line
names the tool or entry, the rule id of the worst finding and the number of findings,
never the text of a description, result or request.

| Line | Meaning |
|---|---|
| `started; wrapping: <command>` | The proxy started the server. The command is logged as given, arguments included. |
| `BLOCKED tool '<name>': <rule> (<n> findings)` | The tool had a block-level finding and was dropped. |
| `flagged tool '<name>': ...` | The tool was kept and annotated: warn-level findings, or a changed definition. |
| `dropped tool '<name>': definition changed since it was pinned (possible rug pull)` | `--on-change drop` dropped a changed tool. |
| `BLOCKED prompt '<name>': ...`, `BLOCKED resource ...` | A listing entry with a block-level finding was dropped. |
| `injection in <where>: <rule> (<n> findings)` | Text the model reads (a tool result, a prompt message, a resource, an error) got a warning prefixed. |
| `<where> of <n> characters partially scanned` | A result over frisk's text limit (2 MiB characters) was delivered with a note; only its start and end were matched. |
| `refused <method> from the server: ...` | A `sampling/createMessage` or `elicitation/create` request was answered with error `-32001` and never reached the client. |
| `inspection failed (<error>); answered with an error instead` | A message frisk could not inspect reached the client as error `-32603`. |
| `dropped a server line that is not JSON (<n> characters)` | A server line was not JSON (or not UTF-8) and was dropped. |
| `pins file unreadable ...`, `pins file is not a map ...`, `pins not persisted ...` | See [Where the pins live](#where-the-pins-live). |
| other `dropped a ...` lines | An entry, content item or message frisk could not inspect (the wrong shape, or a request with no id) was dropped. |
| `client gone`, `stopped by a signal` | The client stopped reading, or SIGTERM/SIGINT arrived; the server is stopped. |
| `server exited (<status>); dropped=<n> flagged=<n>` | The session's totals. |

`FRISK_DEBUG=1` adds `[frisk debug]` lines (the server's start and exit, durations) to
stderr.

## Exit status

The proxy exits with the server's status (128 + the signal number when a signal ended
it), or 2 when the usage is wrong, the server command cannot be started, or the `--log`
file cannot be opened. When the client closes the proxy's input, the server gets end of
input and 5 s to exit, then SIGTERM, then SIGKILL after 5 s more.

## What it does not do

The proxy speaks stdio only: a remote (HTTP/SSE) server cannot be wrapped. It reads
messages, not the server's code: pair it with `frisk lock` / `frisk verify` and a scan of
the server's source. Its checks are frisk's patterns, with the limits in
[threat-model.md](threat-model.md).
