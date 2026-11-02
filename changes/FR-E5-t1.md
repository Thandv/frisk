### Fixed: the proxy fails closed (FR-E5 t1, security)

`frisk proxy` used to forward a message exactly as the server sent it whenever inspecting
it raised. One tool entry that was not an object (a string, `null`), or a tool whose
description was not a string, made the inspection of the whole `tools/list` result fail,
so every tool in it, a poisoned one included, reached the client. A JSON-RPC batch (an
array) was never inspected at all, and a server line that was not JSON was passed through
unchanged.

Now:

- each tool is judged on its own: an entry that is not an object with a string `name` and
  a string `description` (a missing or null description counts as empty, as MCP makes it
  optional), or whose inspection raises, is dropped and logged, and the other tools are
  still judged;
- a tool-result content item that is not an object, or a text item whose `text` is not a
  string, is dropped and logged;
- if inspecting a message's `tools` or `content` fails (for example, one of them is not a
  list), the client gets `{"jsonrpc": "2.0", "id": <its id>, "error": {"code": -32603,
  "message": "frisk: inspection failed"}}` instead of the message;
- a batch is inspected message by message (an element that is not an object is dropped);
- a server line that is not JSON, or JSON nested too deep to read, is dropped and logged
  with its length only.

Messages that carry no tools or content, notifications included, are relayed unchanged.
