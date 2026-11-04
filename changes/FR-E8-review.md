### Fixed: text saved under a media name is scanned; the proxy's start line redacts secrets

A file with a media extension (`.png`, `.pdf`, `.woff`, ...) whose first 1,024 bytes are
text (no NUL byte, valid UTF-8) is now scanned like any other file, so a script saved as
`setup.png` gets the code rules (and a `#!` first line makes it a script, as the README
says). Real media, binary from its first bytes, is still skipped silently at any size. A
media file that cannot be read now raises `coverage.unreadable`.

`frisk proxy`'s `started; wrapping:` log line redacts secrets in the server command the way
debug lines do (`token=[REDACTED]`), so a key passed as an argument no longer reaches
the log.
