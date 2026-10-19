// #5818: NPTv6 (RFC 6296) rule-sets accept the full static-NAT match scope in
// the config model — rule-set `from interface` / `from routing-instance` and
// per-rule `match source-address` — but the NPTv6 snapshot/wire/dataplane carry
// ONLY `from zone` (buildNptv6Snapshots + Nptv6RuleSnapshot). An NPTv6 rule
// scoped to a specific logical interface, VRF, or client source prefix was
// therefore installed as a broader zone/global prefix rewrite: traffic that
// CANNOT match the configured rule (wrong interface/VRF/source) was still
// translated and routed — the same security-widening class #5176 fixed for
// `from zone`, for the remaining scope dimensions.
//
// Until the wire+dataplane carry and evaluate those dimensions (a substantial
// change deferred to a /research follow-up), the fix REJECTS an NPTv6 rule
// carrying an unsupported scope dimension at strict commit and FAILS CLOSED on
// the tolerant/lenient load path (downgraded to a warning; the snapshot builder
// independently EXCLUDES the scope-carrying rule so it installs nothing rather
// than an over-broad rewrite). Mirrors the #5859 static-nat `then inet` and
// #5819 persistent-nat + no-translation fail-closed patterns.
//
// A `from zone`-only (or fully-unscoped/global) NPTv6 rule is UNAFFECTED — that
// is the #5176-correct path. An ordinary (non-NPTv6) static-NAT rule carrying
// from-interface / from-routing-instance scope (#3096) or match source-address
// (#3435) is ALSO unaffected: those dimensions ARE honored for static NAT.
//
// RED-on-revert:
//   - remove validateNPTv6ScopeStrict (or its dispatch): the scoped NPTv6 rule
//     compiles clean at strict commit and the lenient path emits no scope
//     warning — both RED.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath (buildTree), never
// NewParser (the flat-set gotcha in CLAUDE.md).
package config

import (
	"strings"
	"testing"
)

// nptv6ScopeRuleSet builds an NPTv6 static rule-set. scopeLine is the rule-set
// `from ...` clause (e.g. "from interface ge-0/0/1.0"); extraRuleLines are
// appended verbatim (used to add a per-rule `match source-address`). The trust
// zone is defined so a `from zone trust` scope does not emit undefined-zone
// noise.
func nptv6ScopeRuleSet(scopeLine string, extraRuleLines ...string) []string {
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set security zones security-zone trust",
		"set security nat static rule-set rs1 " + scopeLine,
		"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
		"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:1::/48",
	}
	return append(lines, extraRuleLines...)
}

// TestNPTv6ScopeRejectedAtCommit_5818: an NPTv6 rule carrying a scope dimension
// the dataplane does not honor (from-interface, from-routing-instance, or a
// per-rule match source-address) hard-rejects at strict commit with an error
// naming the rule-set/rule and the unsupported constraint. RED-on-revert
// (validator/dispatch removed): CompileConfig accepts the widened rule.
func TestNPTv6ScopeRejectedAtCommit_5818(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		// want substrings that must appear in the reject error.
		want []string
	}{
		{
			name:  "from-interface",
			lines: nptv6ScopeRuleSet("from interface ge-0/0/1.0"),
			want:  []string{"rs1", "interface", "5818"},
		},
		{
			name:  "from-routing-instance",
			lines: nptv6ScopeRuleSet("from routing-instance blue"),
			want:  []string{"rs1", "routing-instance", "5818"},
		},
		{
			name: "match-source-address-single",
			lines: nptv6ScopeRuleSet("from zone trust",
				"set security nat static rule-set rs1 rule r1 match source-address 2001:db8:100::/64"),
			want: []string{"rs1", "r1", "source-address", "5818"},
		},
		{
			name: "match-source-address-bracket-list",
			lines: nptv6ScopeRuleSet("from zone trust",
				"set security nat static rule-set rs1 rule r1 match source-address [ 2001:db8:100::/64 2001:db8:200::/64 ]"),
			want: []string{"rs1", "r1", "source-address", "5818"},
		},
		{
			// #5818 review residual: `match destination-port` is schema-permitted
			// on an NPTv6 rule and recorded by the compiler, but dropped by the
			// snapshot — the same security-widening class as the source match.
			name: "match-destination-port",
			lines: nptv6ScopeRuleSet("from zone trust",
				"set security nat static rule-set rs1 rule r1 match destination-port 443"),
			want: []string{"rs1", "r1", "destination-port", "5818"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil {
				t.Fatalf("CompileConfig accepted a scope-carrying NPTv6 rule (want reject) — security-widening #5818")
			}
			msg := err.Error()
			for _, want := range tc.want {
				if !strings.Contains(msg, want) {
					t.Fatalf("reject error missing %q: %v", want, msg)
				}
			}
		})
	}
}

// TestNPTv6ScopeLenientFailClosed_5818: on the tolerant / lenient load path a
// scope-carrying NPTv6 rule does NOT hard-reject the whole config (a config
// persisted before this gate existed still boots — #1960), but the violation is
// SURFACED as a warning naming the rule-set. RED-on-revert: no scope warning is
// produced (the rule would ship silently as a broader rewrite). The snapshot
// builder independently EXCLUDES the rule (fail closed); that is asserted in the
// pkg/dataplane/userspace suite.
func TestNPTv6ScopeLenientFailClosed_5818(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{"from-interface", nptv6ScopeRuleSet("from interface ge-0/0/1.0")},
		{"from-routing-instance", nptv6ScopeRuleSet("from routing-instance blue")},
		{"match-source-address", nptv6ScopeRuleSet("from zone trust",
			"set security nat static rule-set rs1 rule r1 match source-address 2001:db8:100::/64")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Strict must reject.
			if _, err := CompileConfig(buildTree(t, tc.lines)); err == nil {
				t.Fatalf("strict CompileConfig must reject the scoped NPTv6 rule")
			}
			// Lenient must NOT hard-fail, and must surface an nptv6 warning.
			cfg, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("CompileConfigLenient must NOT fail (brick-on-restart), got: %v", err)
			}
			if !hasWarningContaining(cfg.Warnings, "nptv6") {
				t.Fatalf("lenient load must emit an nptv6 scope warning, warnings=%v", cfg.Warnings)
			}
			if !hasWarningContaining(cfg.Warnings, "5818") {
				t.Fatalf("lenient scope warning must reference #5818, warnings=%v", cfg.Warnings)
			}
		})
	}
}

// TestNPTv6FromZoneOnlyStillCompiles_5818 is the no-false-reject guard: a
// from-zone-only NPTv6 rule (the #5176-correct path) still compiles cleanly with
// no scope warning.
func TestNPTv6FromZoneOnlyStillCompiles_5818(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, nptv6ScopeRuleSet("from zone trust")))
	if err != nil {
		t.Fatalf("from-zone-only NPTv6 rule must compile, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "5818") {
			t.Fatalf("from-zone-only NPTv6 rule must not emit a #5818 scope warning, got: %q", w)
		}
	}
}

// TestNPTv6UnscopedGlobalStillCompiles_5818: a fully-unscoped (global, no `from`
// clause) NPTv6 rule is NOT rejected by the scope gate — only the specific
// unsupported dimensions (interface / routing-instance / source-address) are.
func TestNPTv6UnscopedGlobalStillCompiles_5818(t *testing.T) {
	lines := []string{
		"set security nat static rule-set rs1 rule r1 match destination-address 2001:db8:1::/48",
		"set security nat static rule-set rs1 rule r1 then static-nat nptv6-prefix fd00:1::/48",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("fully-unscoped NPTv6 rule must compile, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "5818") {
			t.Fatalf("unscoped NPTv6 rule must not emit a #5818 scope warning, got: %q", w)
		}
	}
}

// TestStaticNATInterfaceScopeNotRejected_5818 is the regression guard for the
// non-NPTv6 path: an ordinary static-NAT (host 1:1) rule scoped `from interface`
// AND carrying `match source-address` still compiles — those dimensions ARE
// honored for ordinary static NAT (#3096 / #3435), so the #5818 gate must not
// touch them.
func TestStaticNATInterfaceScopeNotRejected_5818(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security nat static rule-set rt from interface ge-0/0/1.0",
		"set security nat static rule-set rt rule r1 match destination-address 198.51.100.5/32",
		"set security nat static rule-set rt rule r1 match source-address 203.0.113.0/24",
		"set security nat static rule-set rt rule r1 then static-nat prefix 10.0.0.5/32",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("interface-scoped static NAT with source-address must compile (honored, not NPTv6): %v", err)
	}
	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("got %d static rule-sets, want 1", len(cfg.Security.NAT.Static))
	}
	rs := cfg.Security.NAT.Static[0]
	if rs.FromInterface != "ge-0/0/1.0" {
		t.Fatalf("FromInterface = %q, want ge-0/0/1.0", rs.FromInterface)
	}
}
