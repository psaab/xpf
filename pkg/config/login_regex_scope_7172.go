package config

// login_regex_scope_7172.go answers "which command regexes apply to this login
// class", for BOTH enforcement surfaces.
//
// It lives here rather than in pkg/cli because #7172 has two gates — the on-box
// CLI (cut 3) and the gRPC listener (cut 5b) — and the question they must not
// disagree about is not the MATCHING (that is CompiledLoginRegexes.Evaluate,
// already shared) but the ADMISSION: whose regexes are in force, and whether a
// leaf counts as present. A second copy of that decision is how one surface
// comes to enforce a class the other treats as unrestricted, which is a
// bypass rather than a cosmetic drift.
//
// pkg/cli.loginRegexesFrom is now a one-line delegation to this, so the cut-3
// tests keep exercising the same code they always did.

// OperationalLoginRegexesFor compiles the ALLOW and DENY command regexes in
// force for class, and reports whether the class has any at all.
//
// ok=false is the overwhelmingly common case — a class with no fine-grained
// rules — and callers MUST skip evaluation entirely rather than evaluate an
// empty ruleset, because an empty ruleset is not the same object as no
// ruleset: #7172's fail-closed arms (an unresolvable command, an unmappable
// RPC) apply ONLY to a class that configured regexes.
//
// #7172 cut 6 added the ALLOW half. Cuts 3-5b were deny-only on purpose:
// `allow-commands` committed as a documented no-op, and an allow regex is an
// ALLOWLIST, so enforcing it mid-series would have silently narrowed live
// classes on upgrade. It goes live here, with the #6838 gate's retirement and
// one release note, so both leaves change state in the same step.
func OperationalLoginRegexesFor(cfg *Config, class string) (CompiledLoginRegexes, bool, error) {
	return loginRegexesFor(cfg, class, LoginRegexPlainFamily,
		"allow-commands", "deny-commands",
		func(lc *LoginClass) (string, string) { return lc.AllowCommands, lc.DenyCommands })
}

// ConfigurationLoginRegexesFor is the same for the `*-configuration` pair, used
// by the config-mode gate (cut 4).
func ConfigurationLoginRegexesFor(cfg *Config, class string) (CompiledLoginRegexes, bool, error) {
	return loginRegexesFor(cfg, class, LoginRegexPlainFamily,
		"allow-configuration", "deny-configuration",
		func(lc *LoginClass) (string, string) { return lc.AllowConfiguration, lc.DenyConfiguration })
}

// loginRegexesFor is the shared body: find the class, decide leaf PRESENCE for
// both leaves, compile.
//
// PRESENCE, NOT VALUE, FOR BOTH — and the reason differs per leaf, which is why
// this reads two presence lists rather than testing the strings.
//
//   - DENY: `deny-commands ""` and an absent deny-commands mean OPPOSITE
//     things. An empty POSIX regex matches at every position, so an empty deny
//     denies EVERY command — the most restrictive thing an operator can write —
//     while an absent one denies nothing.
//   - ALLOW: an empty allow matches everything, so on its own it is
//     indistinguishable from an absent allow, and testing the value LOOKS
//     sufficient. It is not, and the case that breaks it is the one Juniper
//     documents by name: with `allow-commands ""` beside `deny-commands ""` the
//     two patterns are IDENTICAL, which is precedence tier 1, and allow wins —
//     so the class is allowed everything. Read the empty allow as absent and
//     the same config denies everything instead. Opposite answers, from a value
//     test that looked safe.
func loginRegexesFor(
	cfg *Config,
	class string,
	family LoginRegexFamily,
	allowLeaf, denyLeaf string,
	patterns func(*LoginClass) (allow, deny string),
) (CompiledLoginRegexes, bool, error) {
	if cfg == nil || cfg.System.Login == nil || class == "" {
		return CompiledLoginRegexes{}, false, nil
	}
	for _, lc := range cfg.System.Login.Classes {
		if lc == nil || lc.Name != class {
			continue
		}
		allowSet := containsLoginLeaf(lc.AllowLeavesPresent, allowLeaf)
		denySet := containsLoginLeaf(lc.DenyLeavesPresent, denyLeaf)
		if !allowSet && !denySet {
			return CompiledLoginRegexes{}, false, nil
		}
		allow, deny := patterns(lc)
		compiled, err := CompileLoginRegexes(family, allow, allowSet, deny, denySet)
		if err != nil {
			return CompiledLoginRegexes{}, false, err
		}
		return compiled, true, nil
	}
	return CompiledLoginRegexes{}, false, nil
}

func containsLoginLeaf(list []string, leaf string) bool {
	for _, l := range list {
		if l == leaf {
			return true
		}
	}
	return false
}

// DenySource returns the deny pattern as the operator AUTHORED it, and whether
// a deny leaf was present at all.
//
// The authored text rather than the compiled form: it is what an operator can
// search their config for, and #7172's audit rule keeps operator ARGUMENT
// values out of log lines — a pattern is config the operator wrote, not data a
// caller supplied, so it is safe to echo where a matched command is not.
func (c CompiledLoginRegexes) DenySource() (string, bool) {
	return c.denySrc, c.denySet
}

// AllowSource returns the allow pattern as the operator authored it, and
// whether an allow leaf was present. The #9340 per-alternative answer depends
// on the allow pattern too (the precedence tiers), so a cache of that answer
// is keyed on both sources.
func (c CompiledLoginRegexes) AllowSource() (string, bool) {
	return c.allowSrc, c.allowSet
}
