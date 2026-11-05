# Walkthrough: from a clone to a pinned MCP config

This takes a new reader from a clone of the repository to an audited, pinned MCP config:
install frisk, scan a sample config, read the result, add a lock. Every
command was run as shown and every output below is pasted from that run. Lines you type
start with `$ `, and continuation lines with `> `.

How it was recorded (2026-11-05, macOS, Python 3.15): in a scratch HOME, with each package
cache frisk reads pointed at an empty directory (`FRISK_NPX_CACHE`, `FRISK_UV_TOOLS`,
`FRISK_UV_CACHE`, `FRISK_PIPX_VENVS`), so nothing read a real config or a real cache. The
clone line was run against a local copy of the same commit; `pip install .` fetched the build
backend (hatchling) from PyPI. You need git and Python 3.9 or later.

## 1. Install from the repository

PyPI has frisk 0.1.0 only until 0.3.0 is released ([STATUS.md](../STATUS.md)), so install the
code on `main` from a clone, into a virtual environment:

```console
$ git clone https://github.com/Thandv/frisk && cd frisk
$ python3 -m venv .venv && . .venv/bin/activate
$ pip install -q .
$ frisk --version
frisk 0.2.0
```

That gives two commands, `frisk` and `frisk-mcp`. Check that the scanner works on the two
examples in the repository, one clean and one built to fail:

```console
$ frisk examples/clean-skill; echo "exit $?"
frisk: clean — no findings in examples/clean-skill

scanned 1 file, skipped 0
verdict:   PASS    0 blocking · 0 warnings · 0 total  (examples/clean-skill)
exit 0
$ frisk examples/malicious-skill -q; echo "exit $?"
frisk: BLOCK  (examples/malicious-skill)
exit 1
```

`-q` prints only the verdict line. Without it you get each finding with its line and an
excerpt, as the README's [first example](../README.md#usage) shows.

## 2. Scan a sample MCP config

Make a working directory holding a small local server and a config that names it, plus one
server of each kind frisk cannot read: an npx package that is not in the local cache, and a
remote URL (`.invalid` never resolves). `$PWD` puts the server's absolute path in the config,
as real configs have it:

```console
$ mkdir -p ~/agent-tools/my-server && cd ~/agent-tools
$ printf 'import sys\nprint("hello", file=sys.stderr)\n' > my-server/server.py
$ cat > sample-mcp.json <<JSON
> {
>   "mcpServers": {
>     "my-server": {"command": "python3", "args": ["$PWD/my-server/server.py"]},
>     "weather": {"command": "npx", "args": ["-y", "some-weather-mcp"]},
>     "remote-docs": {"url": "https://mcp.example.invalid/sse"}
>   }
> }
> JSON
$ frisk --mcp-config sample-mcp.json; echo "exit $?"
MCP config audit: sample-mcp.json

  [PASS ] my-server              local  local source via python3
  [SKIP ] weather                package  not in local cache; frisk does not download
           → some-weather-mcp
  [SKIP ] remote-docs            remote  remote HTTP/SSE server — behavior not statically verifiable
           → https://mcp.example.invalid/…

  2 of 3 servers not scanned

[warn ] coverage       remote-docs::https://mcp.example.invalid/…:1  MCP server not scanned (remote)
[warn ] coverage       weather::some-weather-mcp:1  MCP server not scanned (package)

scanned 1 file, skipped 0
verdict:   WARN    0 blocking · 2 warnings · 2 total  (sample-mcp.json)
exit 0
```

## 3. Read the result

- **One line per server**, in config order: its verdict, its name, how it launches (`local`,
  `package`, `remote`) and why. `my-server` is local source, so frisk read its directory and
  found nothing: `PASS`.
- **`SKIP` means not scanned, never clean.** frisk reads code only from disk: it never
  downloads a package or calls a remote server. `weather` would be scanned from the npx
  cache once it has run on this machine; `remote-docs` cannot be checked statically at all.
- **`2 of 3 servers not scanned`**, and a `coverage` warning for each of them under the
  server's name (`name::what it runs`), so a config with skipped servers is never `PASS`.
  The [coverage section](../README.md#what-was-not-scanned-coverage) lists every reason.
- **The verdict line** is the worst finding: `BLOCK` (a finding that should stop you),
  `WARN` (look before you trust it) or `PASS`, with the counts.
- **The exit code** follows `--fail-on`. By default only a `BLOCK` exits 1, so this `WARN`
  exits 0. To fail on warnings too, as a CI gate might:

```console
$ frisk --mcp-config sample-mcp.json --fail-on warn -q; echo "exit $?"
frisk: WARN  (sample-mcp.json)
exit 1
```

Your own client configs are audited the same way, for example
`frisk --mcp-config ~/.claude.json` ([README](../README.md#audit-everything-youve-already-installed)).

## 4. Add a lock

A PASS today says nothing about tomorrow's auto-update. `frisk lock` pins a fingerprint of
what you approved, and `frisk verify` reports anything that changed since:

```console
$ frisk lock --mcp-config sample-mcp.json; echo "exit $?"
frisk lock: sample-mcp.json::weather: code not pinned, only how it starts (not in local cache; frisk does not download)
frisk lock: sample-mcp.json::weather: unpinned: upstream changes cannot be detected; pin some-weather-mcp@x.y.z
frisk: pinned 4 entries → .frisk-lock.json
exit 0
$ frisk verify; echo "exit $?"
  [ok   ] sample-mcp.json
  [ok   ] sample-mcp.json::my-server
  [ok   ] sample-mcp.json::weather
  [ok   ] sample-mcp.json::remote-docs

verify: no drift  (0 of 4 entries changed)
exit 0
```

The four entries are the config itself and each server. The two `frisk lock:` lines say what
the lock cannot protect: for an uncached package only the launch line is pinned, and with no
version in it a new upstream release would not show. Now change the server, as an update
would:

```console
$ echo '# a later change' >> my-server/server.py
$ frisk verify; echo "exit $?"
  [ok   ] sample-mcp.json
  [DRIFT] sample-mcp.json::my-server
           ~ changed: server.py
  [ok   ] sample-mcp.json::weather
  [ok   ] sample-mcp.json::remote-docs

verify: DRIFT DETECTED  (1 of 4 entries changed)
exit 1
```

`frisk verify` names the server and the file. Scan it again; when you approve the change,
lock again:

```console
$ frisk lock --mcp-config sample-mcp.json && frisk verify; echo "exit $?"
frisk lock: sample-mcp.json::weather: code not pinned, only how it starts (not in local cache; frisk does not download)
frisk lock: sample-mcp.json::weather: unpinned: upstream changes cannot be detected; pin some-weather-mcp@x.y.z
frisk: pinned 4 entries → .frisk-lock.json
  [ok   ] sample-mcp.json
  [ok   ] sample-mcp.json::my-server
  [ok   ] sample-mcp.json::weather
  [ok   ] sample-mcp.json::remote-docs

verify: no drift  (0 of 4 entries changed)
exit 0
```

Here `.frisk-lock.json` sits beside `my-server/`. It can also sit inside a directory it
pins (`frisk lock .`, as [examples/continuous-verify.yml](../examples/continuous-verify.yml)
does): frisk leaves that one file out of what it pins, so it is never drift.

## Next

- Check tools at runtime, between your client and a server: [docs/proxy.md](proxy.md).
- Let your agent vet things before it installs them: [docs/mcp-server.md](mcp-server.md).
- What each rule matches and what to do on a hit: [docs/rules.md](rules.md).
- What frisk does not defend against: [docs/threat-model.md](threat-model.md).
