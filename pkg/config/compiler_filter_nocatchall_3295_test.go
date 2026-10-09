package config

import (
	"strings"
	"testing"
)

// hasNoCatchAllWarn returns the first #3295 no-terminal-catch-all warning that
// names the given filter, or "" if none. The warning text is anchored on
// "no terminal catch-all term".
func hasNoCatchAllWarn(warnings []string, filterName string) string {
	for _, w := range warnings {
		if strings.Contains(w, "no terminal catch-all term") &&
			strings.Contains(w, `"`+filterName+`"`) {
			return w
		}
	}
	return ""
}

// TestFilterNoCatchAllWarnsOnAttachedAllowlist proves #3295: a firewall filter
// ATTACHED to an interface input hook that has no terminal catch-all term (a
// pure allowlist of accept terms) commits successfully but emits a commit
// WARNING — xpf accepts unmatched traffic (implicit-accept) where Junos
// stateless filters imply a final discard.
//
// Fail-on-revert: deleting the validateFilterNoCatchAllWarnings call (or its
// per-hook append) removes the warning and this test fails.
func TestFilterNoCatchAllWarnsOnAttachedAllowlist(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter protect-re term allow-ssh from destination-port 22",
		"set firewall family inet filter protect-re term allow-ssh then accept",
		"set interfaces ge-0-0-0 unit 0 family inet filter input protect-re",
	})

	got := hasNoCatchAllWarn(ValidateConfig(cfg), "protect-re")
	if got == "" {
		t.Fatalf("expected a no-catch-all warning for attached allowlist filter, got: %v", ValidateConfig(cfg))
	}
	for _, want := range []string{"ge-0-0-0", "unit 0", "input", "discard"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q missing substring %q", got, want)
		}
	}
}

// TestFilterNoCatchAllSilentWithFinalAccept confirms a filter whose last term is
// an unconstrained `then accept` (explicit permit-by-default catch-all) does NOT
// warn — the operator made the intent explicit.
func TestFilterNoCatchAllSilentWithFinalAccept(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter allow-some term allow-ssh from destination-port 22",
		"set firewall family inet filter allow-some term allow-ssh then accept",
		"set firewall family inet filter allow-some term default then accept",
		"set interfaces ge-0-0-0 unit 0 family inet filter input allow-some",
	})
	if got := hasNoCatchAllWarn(ValidateConfig(cfg), "allow-some"); got != "" {
		t.Fatalf("unexpected no-catch-all warning for filter with explicit final accept: %q", got)
	}
}

// TestFilterNoCatchAllSilentWithFinalDiscard confirms a filter whose last term
// is an unconstrained `then discard` (Junos-style deny-by-default catch-all)
// does NOT warn — the workaround the warning recommends suppresses it.
func TestFilterNoCatchAllSilentWithFinalDiscard(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter strict term allow-ssh from destination-port 22",
		"set firewall family inet filter strict term allow-ssh then accept",
		"set firewall family inet filter strict term deny-rest then discard",
		"set interfaces ge-0-0-0 unit 0 family inet filter input strict",
	})
	if got := hasNoCatchAllWarn(ValidateConfig(cfg), "strict"); got != "" {
		t.Fatalf("unexpected no-catch-all warning for filter with explicit final discard: %q", got)
	}
}

// TestFilterNoCatchAllScopedToAttached confirms an allowlist filter that is
// DEFINED but NOT attached to any interface/lo0 hook does NOT warn — the pass is
// scoped to attached filters to avoid nagging library/unused filters.
func TestFilterNoCatchAllScopedToAttached(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter unused term allow-ssh from destination-port 22",
		"set firewall family inet filter unused term allow-ssh then accept",
	})
	if got := hasNoCatchAllWarn(ValidateConfig(cfg), "unused"); got != "" {
		t.Fatalf("unexpected no-catch-all warning for an unattached library filter: %q", got)
	}
}

// TestFilterNoCatchAllConstrainedTerminatorStillWarns confirms a terminating
// term whose `from` is CONSTRAINED (e.g. `then discard` on a specific port) is
// NOT a catch-all — it does not govern every packet — so the allowlist still
// warns. This guards the unconstrained-`from` half of the predicate.
func TestFilterNoCatchAllConstrainedTerminatorStillWarns(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter near term allow-ssh from destination-port 22",
		"set firewall family inet filter near term allow-ssh then accept",
		"set firewall family inet filter near term drop-telnet from destination-port 23",
		"set firewall family inet filter near term drop-telnet then discard",
		"set interfaces ge-0-0-0 unit 0 family inet filter input near",
	})
	if got := hasNoCatchAllWarn(ValidateConfig(cfg), "near"); got == "" {
		t.Fatalf("expected a no-catch-all warning: a constrained `then discard` is not a catch-all, warnings: %v", ValidateConfig(cfg))
	}
}

// TestFilterNoCatchAllOutputV6AndLo0 confirms the pass covers the output hook,
// the inet6 family, and the lo0 host-bound hook (lo0 is stored as an ordinary
// interface unit). Each attaches a no-catch-all allowlist and must warn, naming
// the right direction.
func TestFilterNoCatchAllOutputV6AndLo0(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		// inet6 OUTPUT hook on a data interface.
		"set firewall family inet6 filter out6 term allow-https from destination-port 443",
		"set firewall family inet6 filter out6 term allow-https then accept",
		"set interfaces ge-0-0-0 unit 0 family inet6 filter output out6",
		// lo0 host-bound INPUT hook (protect-RE allowlist).
		"set firewall family inet filter lo-allow term allow-bgp from destination-port 179",
		"set firewall family inet filter lo-allow term allow-bgp then accept",
		"set interfaces lo0 unit 0 family inet filter input lo-allow",
	})
	warnings := ValidateConfig(cfg)

	out6 := hasNoCatchAllWarn(warnings, "out6")
	if out6 == "" {
		t.Fatalf("expected a no-catch-all warning for inet6 output filter out6, warnings: %v", warnings)
	}
	if !strings.Contains(out6, "output") {
		t.Errorf("inet6 output warning %q should name the output direction", out6)
	}

	lo := hasNoCatchAllWarn(warnings, "lo-allow")
	if lo == "" {
		t.Fatalf("expected a no-catch-all warning for lo0 input filter lo-allow, warnings: %v", warnings)
	}
	if !strings.Contains(lo, "lo0") {
		t.Errorf("lo0 warning %q should name interface lo0", lo)
	}
}

func TestFilterNoCatchAllSkipsUnenforcedLo0Hooks3295(t *testing.T) {
	filterLines := []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter protect-re term allow-ssh from destination-port 22",
		"set firewall family inet filter protect-re term allow-ssh then accept",
		"set firewall family inet filter output-filter term allow-ssh from destination-port 22",
		"set firewall family inet filter output-filter term allow-ssh then accept",
	}

	t.Run("inert hooks", func(t *testing.T) {
		lines := append([]string(nil), filterLines...)
		lines = append(lines,
			"set interfaces lo0 unit 1 family inet filter input protect-re",
			"set interfaces lo0 unit 0 family inet filter output output-filter",
		)
		cfg := compileSetLinesT(t, lines)
		warnings := ValidateConfig(cfg)
		for _, name := range []string{"protect-re", "output-filter"} {
			if got := hasNoCatchAllWarn(warnings, name); got != "" {
				t.Fatalf("unenforced lo0 hook %q must not receive #3295 advice: %q", name, got)
			}
			found12091 := false
			for _, warning := range warnings {
				if strings.Contains(warning, "#12091") && strings.Contains(warning, `"`+name+`"`) {
					found12091 = true
					break
				}
			}
			if !found12091 {
				t.Errorf("expected #12091 to identify unenforced lo0 filter %q; warnings: %v", name, warnings)
			}
		}
	})

	t.Run("incomplete tunnel stanzas remain inert", func(t *testing.T) {
		cases := []struct {
			name  string
			lines []string
			hooks []string
		}{
			{
				name: "unit mode without endpoints",
				lines: []string{
					"set interfaces lo0 unit 1 tunnel mode gre",
					"set interfaces lo0 unit 1 family inet filter input protect-re",
				},
				hooks: []string{"protect-re"},
			},
			{
				name: "unit source without destination",
				lines: []string{
					"set interfaces lo0 unit 1 tunnel source 192.0.2.1",
					"set interfaces lo0 unit 1 family inet filter input protect-re",
				},
				hooks: []string{"protect-re"},
			},
			{
				name: "interface mode without endpoints",
				lines: []string{
					"set interfaces lo0 tunnel mode gre",
					"set interfaces lo0 unit 0 family inet filter output output-filter",
				},
				hooks: []string{"output-filter"},
			},
			{
				name: "interface source without destination",
				lines: []string{
					"set interfaces lo0 tunnel source 192.0.2.1",
					"set interfaces lo0 unit 0 family inet filter output output-filter",
					"set interfaces lo0 unit 1 family inet filter input protect-re",
				},
				hooks: []string{"output-filter", "protect-re"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				lines := append([]string(nil), filterLines...)
				lines = append(lines, tc.lines...)
				warnings := ValidateConfig(compileSetLinesT(t, lines))
				for _, name := range tc.hooks {
					if got := hasNoCatchAllWarn(warnings, name); got != "" {
						t.Errorf("incomplete tunnel hook %q must not receive #3295 advice: %q", name, got)
					}
					found12091 := false
					for _, warning := range warnings {
						if strings.Contains(warning, "#12091") && strings.Contains(warning, `"`+name+`"`) {
							found12091 = true
							break
						}
					}
					if !found12091 {
						t.Errorf("incomplete tunnel hook %q must receive #12091; warnings: %v", name, warnings)
					}
				}
			})
		}
	})

	t.Run("tunnel-backed hook remains enforced", func(t *testing.T) {
		lines := append([]string(nil), filterLines...)
		lines = append(lines,
			"set interfaces lo0 unit 1 tunnel mode gre",
			"set interfaces lo0 unit 1 tunnel source 192.0.2.1",
			"set interfaces lo0 unit 1 tunnel destination 192.0.2.2",
			"set interfaces lo0 unit 1 family inet filter input protect-re",
		)
		cfg := compileSetLinesT(t, lines)
		warnings := ValidateConfig(cfg)
		if got := hasNoCatchAllWarn(warnings, "protect-re"); got == "" {
			t.Fatalf("tunnel-backed lo0 input hook should retain meaningful #3295 advice; warnings: %v", warnings)
		}
		for _, warning := range warnings {
			if strings.Contains(warning, "#12091") {
				t.Fatalf("tunnel-backed lo0 input hook must not receive #12091 advice: %q", warning)
			}
		}
	})
}

// TestFilterNoCatchAllCommitSucceeds confirms the warning never fails the
// commit: an attached allowlist filter with no catch-all is valid Junos and
// must compile + pass schema validation (warn, never reject), so a
// previously-committed config is never bricked.
func TestFilterNoCatchAllCommitSucceeds(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter protect-re term allow-ssh from destination-port 22",
		"set firewall family inet filter protect-re term allow-ssh then accept",
		"set interfaces ge-0-0-0 unit 0 family inet filter input protect-re",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("no-catch-all allowlist must commit (warn, not reject): %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Fatalf("SchemaValidate rejected a valid allowlist filter: %v", err)
	}
}
