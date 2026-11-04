# frisk-mcp: let an agent vet content before it installs it

`frisk-mcp` is a stdio MCP server, installed with frisk, that gives an agent frisk's scanner
as tools, so it can check a skill, a plugin or an MCP server before adding it. It reads and
writes newline-delimited JSON-RPC on standard input and output; it opens no port.

## Add it

Claude Code:

```
claude mcp add frisk -- frisk-mcp
```

Any client with a JSON config (Claude Desktop, Cursor, `.mcp.json`):

```json
{ "mcpServers": { "frisk": { "command": "frisk-mcp" } } }
```

To set the limits below, give the server an environment, for example
`claude mcp add frisk -e FRISK_MCP_ROOTS=/path/to/projects -e FRISK_MCP_NO_NETWORK=1 -- frisk-mcp`,
or an `"env"` object in the JSON config.

## Tools

| Tool | Argument | What it scans |
|---|---|---|
| `scan_text` | `text` | A raw string (a tool description, a skill body, a prompt), with every code and text rule and the hidden-Unicode check (context `default`). |
| `scan_artifact` | `source` | A local path or a git URL: any agent content. |
| `vet_mcp_server` | `repo` | A local path or a git URL of an MCP server, before you add it. The same scan as `scan_artifact`. |

A path is scanned as `frisk PATH` scans it; an MCP config file given as a path is scanned
as a JSON file, not audited server by server (that is `frisk --mcp-config` on the command
line). A git URL is shallow-cloned with git's escape hatches closed, as the CLI does
(README, [Usage](../README.md#usage)); the clone may take up to 120 s.

Each tool answers with one JSON text item:

- `source`, `verdict` (`PASS`, `WARN` or `BLOCK`), `worst_severity` and `counts`;
- `findings`: the first 12, block-level ones first, each with `severity`, `category`,
  `rule`, `where` (`path:line`), `description` and `owasp`. Never an excerpt: the agent
  never gets the scanned text back;
- `advice`: one sentence per verdict, telling the agent what to do;
- when the scan raised any `coverage.*` finding (a limit hit, a file not read or not valid
  UTF-8, text over the limit), `"degraded": true` and `coverage`: `files_scanned`, and the
  `skipped` count per reason. A silently skipped media file does not make a result degraded.

## Limits

`scan_artifact` and `vet_mcp_server` are bounded, so one call cannot hold the server: the
walk stops after 20,000 files, 200 MiB read or 30 seconds (counted from the start of the
walk, after any clone), and files over 2 MiB are not read (each is a block-level
`coverage.too_large` finding). `scan_text` matches a string of up to 2 MiB characters
whole; a longer one has its first and last 1 MiB characters matched and is degraded
(`coverage.truncated`). A stopped walk returns what it found, degraded, with a
`coverage.unscanned` warning.

## Environment

- `FRISK_MCP_ROOTS`: directories (separated by `:`, `;` on Windows) that local paths must
  be inside; a path outside them is refused. Paths are compared with symlinks and `..`
  resolved, so neither can escape a root. Unset, any path is allowed except the three
  below.
- `/`, your home directory itself and `/System` are refused unless one of them is named in
  `FRISK_MCP_ROOTS`.
- `FRISK_MCP_NO_NETWORK=1`: git URLs are refused before git runs. Any other value, or
  unset, allows them.
- `FRISK_DEBUG=1`: `[frisk debug]` lines on stderr for each tool call (name, status,
  duration, result size; never the content), git clones and errors otherwise skipped.

A refusal is an `isError` result with a one-line reason, as is any tool that cannot do its
job (a path that does not exist, a clone that fails, a missing argument).

## Protocol

`frisk-mcp` speaks MCP protocol versions `2024-11-05`, `2025-03-26` and `2025-06-18`:
`initialize` answers with the client's version when it is one of these, else with
`2025-06-18`. It answers `ping`, `tools/list` and `tools/call`, ignores notifications, and
keeps serving after any bad request:

| Code | When |
|---|---|
| `-32700` | A line that is not JSON or not UTF-8 (id `null`). |
| `-32600` | A request that is not an object, or whose `method`, `params` or `arguments` has the wrong type. |
| `-32601` | An unknown method. |
| `-32602` | An unknown tool. |
| `-32603` | Handling the request failed inside frisk (a bug); the next request is still answered. |

It runs until its standard input ends.
