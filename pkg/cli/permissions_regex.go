package cli

// Fine-grained operational-command enforcement for `system login class`
// allow-commands / deny-commands (#7172 cut 3).
//
// This runs AFTER checkPermission, never instead of it: Junos authorizes the
// command family with the coarse permission bits first and the regexes narrow
// within that. A caller reaching this without the coarse gate has skipped a
// check rather than replaced one.
//
// WHY dispatchOperational AND NOT dispatch(). dispatch() looks like the
// narrowest entry — it has the untouched line, pipe included — but it is not
// the only one: `case "run"` in dispatchConfig calls dispatchOperational
// DIRECTLY (cli_dispatch.go), so a config-mode `run request system reboot`
// never passes through dispatch() again. Gating at dispatch() would leave that
// path open, and it is reachable by any operator who can enter config mode.
// dispatchOperational is where all five entry paths converge.
//
// THE PIPE IS PART OF THE COMMAND. Junos matches deny regexes against the
// command including its output pipe, and the security argument is independent
// of parity: `show configuration | save /tmp/x` writes a file and
// `| display set` reformats output a deny may be withholding, so a gate that
// cannot see past `|` cannot restrict either. cliterm.SplitPipe strips the
// suffix before dispatchOperational sees the line, so dispatchWithPipe hands it
// back through pendingPipeSuffix for reassembly here.
//
// The pure decision leaf — evaluateCommandRegex and its helpers
// (splitAtPipe, authorizablePipe, and the canonicalForms /
// distinctNarrowerAllowed forwarders) — lives in
// command_regex_leaf_16158.go (#16158), CLI-local by design: it MUST
// NOT move into pkg/authz. The form walk itself moved to
// pkg/cmdtree (#16472) so the remote gates judge the same spellings;
// the leaf file keeps the forwarders. checkCommandRegex,
// checkCommandRegexWith and loginRegexesFor live there too; this file
// remains as the dispatch-side overview so the convergence argument
// stays beside dispatchOperational.
