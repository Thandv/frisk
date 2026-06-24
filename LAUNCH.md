# frisk — launch & distribution plan

The monetization thesis: **adoption first, money second.** A security tool earns
revenue only after it earns trust and reach. So the first job is distribution of
the free tier, not a paywall. This doc is the playbook.

## Positioning (one line)

> **frisk vets MCP servers, skills, and plugins for malicious code *before* you
> install them — fully local, zero-cloud, zero dependencies.**

Against the field:
- **Snyk / Invariant `mcp-scan`** (the leader): cloud API (ships your tool
  descriptions to invariantlabs.ai), MCP-only, *detective* (scans what's already
  installed). → frisk is **local-first, broader-than-MCP, and preventive.**
- **Cisco `mcp-scanner`** (YARA), **mcp-shield**: pattern-only, MCP-config-only.
- frisk also does **rug-pull detection** (`lock`/`verify`) and **OWASP LLM Top 10**
  mapping, with **SARIF** for the GitHub Security tab.

## Credibility proof (calibrated on real servers)

frisk was tuned against real, popular MCP servers so it doesn't cry wolf:
- ✅ `github/github-mcp-server` → **clean (WARN, 0 blocks)**
- ✅ `modelcontextprotocol/servers` → **clean (WARN, 0 blocks)**
- ✅ catches planted pipe-to-shell, secret-file exfiltration, tool-poisoning, and
  hidden-unicode in the bundled `examples/malicious-skill`

> Note on disclosure: do **not** publicly name specific third-party projects as
> "vulnerable" from a regex scan. Frame findings as *calibration* (we pass the
> official servers; we catch planted attacks). Any real vuln in someone's repo →
> private responsible disclosure, never a launch headline.

## 30-second try-it (put this at the top of every post)

```bash
pipx run frisk-scan https://github.com/some/mcp-server   # vet before you install
frisk --mcp-config ~/.../claude_desktop_config.json      # audit what you already run
frisk lock . && frisk verify                             # catch silent "rug pull" updates
```

## Launch sequence

1. **Ship the free tier** (publish to GitHub + PyPI). *Precondition for everything.*
2. **Show HN**: "Show HN: frisk – vet MCP servers/skills before you install them (local, no cloud)."
   Lead with the local-first wedge vs the cloud incumbent.
3. **dev.to / blog**: "I built a local-first scanner for the AI-agent supply chain —
   here's the threat model (tool poisoning, rug pulls) and how it stays quiet on
   legit servers." Maps to OWASP LLM Top 10.
4. **Where the users are**: r/mcp, the MCP Discord, X/Bluesky AI-dev circles,
   claudemarketplaces.com, mcp.so, awesome-mcp lists (submit frisk).
5. **GitHub Action marketplace** listing (the SARIF + CI gate is the sticky hook).

## Monetization ladder (after adoption — note the order)

1. **Free OSS** (now): CLI, Action, local MCP server → reach + trust.
2. **GitHub Sponsors / Polar**: once it has stars/users. Fits the local-first ethos.
3. **Team/CI tier**: org policy, allowlists/baselines, dashboards, scheduled
   `verify` for rug-pull monitoring. Sold to teams, not individuals.
4. **B2B "frisk-verified" badge**: registries/marketplaces (claudemarketplaces,
   mcp.so) and AI platforms (e.g. Archestra) pay to scan submissions at scale.
   *This is the real revenue line* — and it only exists once frisk is the trusted name.

> Deliberately **not** doing: a hosted cloud-scan paywall. It contradicts the
> local-first wedge that differentiates us from Snyk/Invariant.

## Roadmap (post-launch, in priority order)
- Context profiles (skill-vetting vs server-source) to cut WARN noise.
- npm/PyPI fetch-and-scan (resolve `npx`/`uvx` → download tarball → scan, no install).
- Scheduled `verify` GitHub Action for continuous rug-pull monitoring.
- Optional deeper rules (dataflow) without adding runtime deps.
