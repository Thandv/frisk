### Fixed: the MCP config audit no longer prints URL credentials (AUD-S13)

A skipped remote server's `→` line used to print its URL exactly as written in the
config, including a `user:password@` part, the query string and the fragment, which is
where access tokens usually sit. The audit now prints only the scheme, host, port and
path (`https://mcp.example.com/sse`). A remote URL with no scheme or host, with a port
that is not a number, or with an `@` after its host part is shown as `<unparsable URL>`:
an unencoded `#`, `?` or `/` in a password makes the parser end the host part early, and
printing what it took for the host would show part of the password. A package given as a URL is shortened the same way. Env values and
headers are never read into the audit, so they cannot be printed. All audit output gets
a server's location from one function, `frisk.sources.display_ref`.
