### Fixed: holes found by the independent review of the MCP config audit (FR-E4)

- A config that holds both `mcpServers` and `servers` is audited whole. Claude Code runs
  `mcpServers` and VS Code runs `servers`; frisk used to read `servers` only when
  `mcpServers` was missing, so an empty `"mcpServers": {}` hid every VS Code server (main
  read `servers` when `mcpServers` was empty, so this was a BLOCK-to-PASS regression). A
  name found in both maps is listed twice, the second as `name (servers)`.
