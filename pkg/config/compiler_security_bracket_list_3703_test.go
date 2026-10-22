package config

import (
	"strings"
	"testing"
)

// Tests for #3703: the #2419 bracketed/single-line list-collapse bug recurred on
// four security config surfaces that #2419 never converted — host-inbound
// system-services/protocols, per-policy `then log`, `default-policy-log`, and
// `pre-id-default-policy then log`. Each was modeled as a container (or
// nil-children leaf) rather than a `multi:true` value-tail leaf, so a bracket /
// single-line list dropped every value after the first (mis-nested the tail) and
// the dropped tail — including typos — bypassed strict validation. The fix tags
// each as a multi-value leaf, reads every value via the firewallMatchValues
// SSOT, and rejects unknown tokens at commit (host-inbound via
// validateHostInboundTokensStrict on the compiled slice; the log surfaces via
// SchemaValidate's enum-leaf validator).
//
// Every RED-on-revert case below fails if the schema leaf is reverted to a
// container / nil-children-non-multi leaf (the tail collapses / is silently
// dropped again) or the compiler reader is reverted to Keys[0]/first-child only.
//
// IMPORTANT (per CLAUDE.md): flat-set syntax is built with ParseSetCommand +
// tree.SetPath, never NewParser.

func setTree3703(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	// #4515: zone members below reference ge-0/0/0 and ge-0/0/1; define them so
	// the strict zone-interface-defined gate (validateZoneInterfaceDefinedStrict)
	// is satisfied — this fixture predates that gate and only exercises
	// host-inbound / policy-log grammar, not interface validation.
	cmds = append([]string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	}, cmds...)
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func equalStrs3703(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// host-inbound system-services / protocols
// ---------------------------------------------------------------------------

// TestHostInbound3703KeepsAllListValues is the primary host-inbound RED-on-revert
// guard: a bracket list, a single-line list, repeated lines, and the
// hierarchical block shape must ALL land every value. Reverting the schema
// (children:nil non-multi container) or the reader (Keys[0]-only) drops
// everything after the first token and this goes RED (a dropped host-inbound
// service silently NARROWS admission — can strand SSH/routing).
func TestHostInbound3703KeepsAllListValues(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		svcs  []string
		proto []string
	}{
		{
			name: "bracket list",
			lines: []string{
				"set security zones security-zone trust interfaces ge-0/0/0",
				"set security zones security-zone trust host-inbound-traffic system-services [ ssh http ]",
				"set security zones security-zone trust host-inbound-traffic protocols [ ospf bgp ]",
			},
			svcs:  []string{"ssh", "http"},
			proto: []string{"ospf", "bgp"},
		},
		{
			name: "repeated flat-set lines",
			lines: []string{
				"set security zones security-zone trust interfaces ge-0/0/0",
				"set security zones security-zone trust host-inbound-traffic system-services ssh",
				"set security zones security-zone trust host-inbound-traffic system-services http",
				"set security zones security-zone trust host-inbound-traffic protocols ospf",
				"set security zones security-zone trust host-inbound-traffic protocols bgp",
			},
			svcs:  []string{"ssh", "http"},
			proto: []string{"ospf", "bgp"},
		},
		{
			name: "single value (negative control: not over-collapsed)",
			lines: []string{
				"set security zones security-zone trust interfaces ge-0/0/0",
				"set security zones security-zone trust host-inbound-traffic system-services ssh",
			},
			svcs:  []string{"ssh"},
			proto: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(setTree3703(t, tc.lines...))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			z := cfg.Security.Zones["trust"]
			if z == nil || z.HostInboundTraffic == nil {
				t.Fatalf("trust zone host-inbound-traffic missing")
			}
			if !equalStrs3703(z.HostInboundTraffic.SystemServices, tc.svcs) {
				t.Fatalf("system-services = %v, want %v (bracket/list tail dropped — #3703)",
					z.HostInboundTraffic.SystemServices, tc.svcs)
			}
			if !equalStrs3703(z.HostInboundTraffic.Protocols, tc.proto) {
				t.Fatalf("protocols = %v, want %v (bracket/list tail dropped — #3703)",
					z.HostInboundTraffic.Protocols, tc.proto)
			}
		})
	}
}

// TestHostInbound3703HierarchicalBlockShape confirms the hierarchical
// `host-inbound-traffic { system-services { ssh; http; } }` block shape still
// lands every value (the reader reads .Children too), so the multi-leaf change
// does not regress the block spelling.
func TestHostInbound3703HierarchicalBlockShape(t *testing.T) {
	tree := parseHierText(t, `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces ge-0/0/0;
            host-inbound-traffic {
                system-services { ssh; http; }
                protocols { ospf; bgp; }
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if !equalStrs3703(z.HostInboundTraffic.SystemServices, []string{"ssh", "http"}) {
		t.Fatalf("hierarchical system-services = %v, want [ssh http]", z.HostInboundTraffic.SystemServices)
	}
	if !equalStrs3703(z.HostInboundTraffic.Protocols, []string{"ospf", "bgp"}) {
		t.Fatalf("hierarchical protocols = %v, want [ospf bgp]", z.HostInboundTraffic.Protocols)
	}
}

// TestHostInbound3703PerInterfaceOverrideKeepsAllValues covers the #3362
// per-interface override — its bracket list must also keep every value.
func TestHostInbound3703PerInterfaceOverrideKeepsAllValues(t *testing.T) {
	cfg, err := CompileConfig(setTree3703(t,
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services [ ssh ping ]",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic protocols [ ospf bgp ]",
	))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	hib := cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0"]
	if hib == nil {
		t.Fatalf("per-interface host-inbound missing")
	}
	if !equalStrs3703(hib.SystemServices, []string{"ssh", "ping"}) {
		t.Fatalf("per-iface system-services = %v, want [ssh ping] (#3703)", hib.SystemServices)
	}
	if !equalStrs3703(hib.Protocols, []string{"ospf", "bgp"}) {
		t.Fatalf("per-iface protocols = %v, want [ospf bgp] (#3703)", hib.Protocols)
	}
}

// TestHostInbound3703UnknownTokenRejectedAtCommit is the fail-fast RED-on-revert
// guard: a typo in a bracket list is REJECTED at commit. Before #3703 the tail
// (incl. the typo) was dropped before the compiled slice, so
// validateHostInboundTokensStrict never saw it and the config committed narrower
// than authored. With the collapse fixed, the typo reaches the compiled slice
// and is rejected. Reverting the fix makes both cases compile clean and this
// goes RED.
func TestHostInbound3703UnknownTokenRejectedAtCommit(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		bad  string
	}{
		{"system-services typo in bracket", "set security zones security-zone trust host-inbound-traffic system-services [ ssh sssh ]", "sssh"},
		{"protocols typo in bracket", "set security zones security-zone trust host-inbound-traffic protocols [ ospf notaproto ]", "notaproto"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(setTree3703(t,
				"set security zones security-zone trust interfaces ge-0/0/0",
				tc.line,
			))
			if err == nil {
				t.Fatalf("CompileConfig accepted an unknown host-inbound token; want a strict reject (#3703)")
			}
			if !strings.Contains(err.Error(), tc.bad) {
				t.Fatalf("reject error %q does not name the offending token %q", err.Error(), tc.bad)
			}
		})
	}
}

// TestHostInbound3703LenientDowngradesUnknownToken confirms the #1960 no-brick
// doctrine: on the tolerant load path the unknown token (now visible after the
// collapse fix) downgrades to a warning instead of failing the load.
func TestHostInbound3703LenientDowngradesUnknownToken(t *testing.T) {
	cfg, err := CompileConfigLenient(setTree3703(t,
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone trust host-inbound-traffic system-services [ ssh sssh ]",
	))
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on an unknown host-inbound token (#1960 no-brick): %v", err)
	}
	// The known token still landed (collapse is fixed on both paths).
	if got := cfg.Security.Zones["trust"].HostInboundTraffic.SystemServices; len(got) == 0 || got[0] != "ssh" {
		t.Fatalf("lenient compile lost the valid token: %v", got)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "sssh") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile should warn about the unknown token, warnings=%v", cfg.Warnings)
	}
}

// ---------------------------------------------------------------------------
// per-policy `then log`
// ---------------------------------------------------------------------------

// TestPolicyThenLog3703KeepsBothModes is the primary RED-on-revert guard for
// per-policy `then log`: a bracket list, a two-line spelling, and the deny-
// collapsed form must all set BOTH session flags. Reverting drops session-close
// (audit records lost despite valid syntax).
func TestPolicyThenLog3703KeepsBothModes(t *testing.T) {
	base := []string{
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone untrust interfaces ge-0/0/1",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	}
	cases := []struct {
		name string
		log  []string
	}{
		{"bracket list", []string{"set security policies from-zone trust to-zone untrust policy p1 then log [ session-init session-close ]"}},
		{"two lines", []string{
			"set security policies from-zone trust to-zone untrust policy p1 then log session-init",
			"set security policies from-zone trust to-zone untrust policy p1 then log session-close",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(setTree3703(t, append(append([]string(nil), base...), tc.log...)...))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			log := cfg.Security.Policies[0].Policies[0].Log
			if log == nil || !log.SessionInit || !log.SessionClose {
				t.Fatalf("then log dropped a mode: %+v (want both true — #3703)", log)
			}
		})
	}
}

// TestPolicyThenDenyLog3703BracketKeepsBothModes covers the deny-collapsed
// bracket form `then deny log [ session-init session-close ]` (#3141 path).
func TestPolicyThenDenyLog3703BracketKeepsBothModes(t *testing.T) {
	cfg, err := CompileConfig(setTree3703(t,
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone untrust interfaces ge-0/0/1",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then deny log [ session-init session-close ]",
	))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pol := cfg.Security.Policies[0].Policies[0]
	if pol.Action != PolicyDeny {
		t.Fatalf("Action = %v, want PolicyDeny", pol.Action)
	}
	if pol.Log == nil || !pol.Log.SessionInit || !pol.Log.SessionClose {
		t.Fatalf("then deny log dropped a mode: %+v (want both true — #3703)", pol.Log)
	}
}

// TestPolicyThenLog3703UnknownModeRejected is the fail-fast guard: a typo in the
// `then log` bracket list is rejected at commit-check by SchemaValidate's
// enum-leaf validator (the bracket tail no longer hides it). Reverting the multi
// enum leaf back to a container makes the typo a silent no-op and this goes RED.
func TestPolicyThenLog3703UnknownModeRejected(t *testing.T) {
	tree := setTree3703(t,
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone untrust interfaces ge-0/0/1",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
		"set security policies from-zone trust to-zone untrust policy p1 then log [ session-init boguslog ]",
	)
	if err := SchemaValidate(tree); err == nil {
		t.Fatalf("SchemaValidate accepted an unknown then-log mode; want a strict reject (#3703)")
	} else if !strings.Contains(err.Error(), "boguslog") {
		t.Fatalf("reject error %q does not name the offending token", err.Error())
	}
	// The valid form must still pass (no over-reject).
	ok := setTree3703(t,
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone untrust interfaces ge-0/0/1",
		"set security policies from-zone trust to-zone untrust policy p1 then log [ session-init session-close ]",
	)
	if err := SchemaValidate(ok); err != nil {
		t.Fatalf("SchemaValidate rejected a valid then-log list (over-reject): %v", err)
	}
}

// ---------------------------------------------------------------------------
// default-policy-log
// ---------------------------------------------------------------------------

// TestDefaultPolicyLog3703KeepsBothModes is the RED-on-revert guard for the
// most security-relevant fallback path: `default-policy-log [ session-init
// session-close ]` must set BOTH flags.
func TestDefaultPolicyLog3703KeepsBothModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		line []string
	}{
		{"bracket list", []string{"set security policies default-policy-log [ session-init session-close ]"}},
		{"two lines", []string{
			"set security policies default-policy-log session-init",
			"set security policies default-policy-log session-close",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(setTree3703(t, append([]string{"set security policies default-policy permit-all"}, tc.line...)...))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			if !cfg.Security.DefaultPolicyLogSessionInit || !cfg.Security.DefaultPolicyLogSessionClose {
				t.Fatalf("default-policy-log dropped a mode: init=%v close=%v (want both — #3703)",
					cfg.Security.DefaultPolicyLogSessionInit, cfg.Security.DefaultPolicyLogSessionClose)
			}
		})
	}
}

// TestDefaultPolicyLog3703UnknownModeRejected is the fail-fast guard: an unknown
// token in the default-policy-log list is rejected at commit-check (there was NO
// strict validator for this surface before #3703 — only a warning).
func TestDefaultPolicyLog3703UnknownModeRejected(t *testing.T) {
	tree := setTree3703(t,
		"set security policies default-policy permit-all",
		"set security policies default-policy-log [ session-init bogusmode ]",
	)
	if err := SchemaValidate(tree); err == nil {
		t.Fatalf("SchemaValidate accepted an unknown default-policy-log mode; want a strict reject (#3703)")
	} else if !strings.Contains(err.Error(), "bogusmode") {
		t.Fatalf("reject error %q does not name the offending token", err.Error())
	}
}

// ---------------------------------------------------------------------------
// pre-id-default-policy then log
// ---------------------------------------------------------------------------

// TestPreIDDefaultPolicyLog3703KeepsBothModes is the RED-on-revert guard for
// `pre-id-default-policy then log [ session-init session-close ]`.
func TestPreIDDefaultPolicyLog3703KeepsBothModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		line []string
	}{
		{"bracket list", []string{"set security pre-id-default-policy then log [ session-init session-close ]"}},
		{"two lines", []string{
			"set security pre-id-default-policy then log session-init",
			"set security pre-id-default-policy then log session-close",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(setTree3703(t, tc.line...))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			p := cfg.Security.PreIDDefaultPolicy
			if p == nil || !p.LogSessionInit || !p.LogSessionClose {
				t.Fatalf("pre-id-default-policy log dropped a mode: %+v (want both — #3703)", p)
			}
		})
	}
}

// TestPreIDDefaultPolicyLog3703UnknownModeRejected is the fail-fast guard for the
// pre-id surface (also had NO strict validator before #3703).
func TestPreIDDefaultPolicyLog3703UnknownModeRejected(t *testing.T) {
	tree := setTree3703(t,
		"set security pre-id-default-policy then log [ session-init bogusmode ]",
	)
	if err := SchemaValidate(tree); err == nil {
		t.Fatalf("SchemaValidate accepted an unknown pre-id-default-policy log mode; want a strict reject (#3703)")
	} else if !strings.Contains(err.Error(), "bogusmode") {
		t.Fatalf("reject error %q does not name the offending token", err.Error())
	}
}

// TestSessionLogModeCompletion3703 pins the value-slot completion: dropping the
// container children (session-init/session-close) must NOT lose `?` completion —
// the multi enum leaf surfaces both via valueExamples on every log surface.
func TestSessionLogModeCompletion3703(t *testing.T) {
	paths := [][]string{
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p1", "then", "log"},
		{"security", "policies", "default-policy-log"},
		{"security", "pre-id-default-policy", "then", "log"},
	}
	for _, p := range paths {
		results := CompleteSetPathWithValues(p, nil)
		for _, want := range []string{"session-init", "session-close"} {
			if !containsCompletionName(results, want) {
				t.Fatalf("completion for %v missing %q; got %v", p, want, completionNames(results))
			}
		}
	}
}
