### Fixed: frisk-mcp answers malformed requests instead of crashing (FR-E5 t3)

`frisk-mcp` used to end with a traceback on a request that was valid JSON but not an object
(`[1]`), a non-string `method`, or `tools/call` with list `params`; under a UTF-8 locale one
byte that was not UTF-8 ended it too. A line that was not JSON got no reply at all.

Now every request gets a reply and the server keeps serving:

- `-32700` "parse error" (id `null`) for a line that is not JSON, not UTF-8, or nested too
  deep to read;
- `-32600` "invalid request: ..." for a request that is not an object, whose `method` is
  not a string, or whose `params` or `tools/call` `arguments` is not an object;
- `-32602` "unknown tool: ..." for a `tools/call` naming no frisk tool (it was an `isError`
  result);
- `-32603` "internal error (...)" when handling a request fails inside frisk; a tool that
  cannot do its job (a missing path, a failed clone, a missing argument) still answers with
  an `isError` result.

`ping` answers `{}` (it was "method not found"). `initialize` negotiates the protocol
version: the client's version when it is `2024-11-05`, `2025-03-26` or `2025-06-18`, else
`2025-06-18` (it was always `2024-11-05`).
