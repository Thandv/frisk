### Fixed: the MCP config audit no longer prints URL credentials (AUD-S13)

A skipped remote server's `→` line used to print its URL exactly as written in the
config, including a `user:password@` part, the query string and the fragment, which is
where access tokens usually sit. The audit now prints only the scheme, host, port and
path (`https://mcp.example.com/sse`); a remote URL with no scheme or host is shown as
`<unparsable URL>`. A package given as a URL is shortened the same way. Env values and
headers are never read into the audit, so they cannot be printed. All audit output gets
a server's location from one function, `frisk.sources.display_ref`.
