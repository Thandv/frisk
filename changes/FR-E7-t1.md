### Changed: `frisk --help` names the proxy subcommand (FR-E7 t1)

The scan help's description now ends "Subcommands: lock, verify, proxy." (it listed only
lock and verify). Colour is now decided each time text is coloured, from whether stdout is a
terminal and whether `NO_COLOR` is set at that moment, not once when frisk is imported; the
output of a run is unchanged.
