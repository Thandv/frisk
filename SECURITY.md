# Security policy

## Reporting a vulnerability

If you find a security issue in frisk itself, please report it privately:
open a [GitHub security advisory](https://github.com/Thandv/frisk/security/advisories/new)
rather than a public issue. We aim to respond within a few days.

## Scope & limitations (read this)

frisk is a **static, zero-execution** scanner. It reads files and matches patterns —
it never imports, runs, or evaluates the content it scans. That makes it safe to point
at untrusted code, but it also means:

- A `PASS` means **"no known-bad patterns found,"** not "this is safe." A determined
  attacker can evade regex, and runtime behavior (especially of remote servers and
  un-fetched npm/PyPI packages) is not observed.
- Treat frisk as a **first line of defense and a triage tool**, alongside human review
  and runtime controls — not a guarantee.

## A note on third-party findings

If frisk flags something in someone else's project, that is a prompt for **review**,
not a public accusation. Confirmed vulnerabilities in third-party code should go through
that project's own responsible-disclosure process, privately.
