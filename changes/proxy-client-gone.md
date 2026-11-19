### Fixed: `frisk proxy` no longer hangs when the client stops reading, or lingers after the server exits

When the client stopped reading the proxy's output while keeping its input open, the proxy
logged `client gone` and then waited for the server forever. It now closes the server's input,
waits 5 s for it to exit, then stops it (SIGTERM, then SIGKILL after 5 s more). A server that
exits while a child of its own still holds its output open no longer keeps the proxy relaying
for as long as the child lives: the proxy stops relaying 5 s after the server exits.

After the server exits, the proxy finishes the line it is writing to the client, and the 5 s
limit on relaying starts once it has relayed all the output that existed when the server
exited, however slowly the client reads it: every reply the server wrote before exiting
still reaches a client that closed its input and reads late. Only output that arrives after
that point (from a child still writing) is cut off. On SIGTERM or SIGINT the proxy exits at once, even partway
through a line.

A small reply written to a closed output used to end the proxy with exit code 120 (the flush
at interpreter exit failed). The proxy now always exits with the server's status.

A client that leaves the proxy's output non-blocking now gets every reply whole (a full pipe
used to count as the client being gone), a proxy started with more than 1024 descriptors open
relays again, and `frisk` no longer needs the POSIX-only `fcntl` and `termios` modules to start.

Worth knowing: a client that sends its requests and then closes the proxy's input still gets
the replies that arrive within 5 s; a tool call still running 5 s after the input closed is
stopped, as before.
