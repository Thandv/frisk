### Fixed: holes found by the final review of the MCP config audit (FR-E4)

- Every server in a config has a name of its own. A top-level server could be named like a
  project server (`db (~/work/app)`), and two spellings of one project path share a label;
  `frisk lock` pins a server by its name and `frisk verify` finds it by that name, so after
  a project server was locked, changing it and adding a top-level copy of its old entry under
  its name made `frisk verify` report no drift. A name an earlier server already has is now
  followed by ` (2)`, ` (3)`, ..., so the extra server shows as added (DRIFT), and a config
  that really holds such names verifies cleanly right after `frisk lock`.
