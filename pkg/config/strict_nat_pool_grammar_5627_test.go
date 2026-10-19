package config

import (
	"strings"
	"testing"
)

// Tests for #5627 (codex-review-181 M15 / A3-b00-F02): the Go strict-commit
// path validated a source-NAT pool's `port range` but left its ADDRESS members
// unchecked, so a pool referenced by a pool-mode `then source-nat pool <name>`
// rule that carried a malformed member, an over-capacity prefix (host count >
// MaxSourceNATPoolPrefixHosts), or no addresses at all committed green — then
// the live Rust allocator (expand_pool_address, userspace-dp/src/nat/source.rs)
// marked the pool InvalidPool/EmptyPool and DROPPED the rule at runtime, a
// persistent NAT outage visible only after apply. The fix
// (validateSourceNATPoolAddressGrammarStrict) makes the Go strict grammar
// equivalent to the live grammar: strict commit rejects the same shapes the
// dataplane rejects; the tolerant load / peer-sync path warns-and-loads (#1960
// no-brick), the snapshot builder independently marking the pool unusable.
//
// FAIL-ON-REVERT: dropping the `if err :=
// validateSourceNATPoolAddressGrammarStrict(cfg); ...` dispatch in
// compiler_uniformgates.go (or making the validator `return nil`) turns every
// reject case GREEN and so RED here.

// snat5627Tree builds a config with one source-NAT rule-set whose single rule
// references pool `p1` in pool-mode, prefixed by the caller's pool `set` lines.
// Mirrors the #3906 snatPoolTree pattern (ParseSetCommand + SetPath, never
// NewParser — the flat-set testing gotcha).
func snat5627Tree(t *testing.T, poolCmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	cmds := append([]string{}, poolCmds...)
	cmds = append([]string{"set security zones security-zone trust", "set security zones security-zone untrust"}, cmds...)
	cmds = append(cmds,
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool p1",
	)
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

// TestSourceNATPoolBadGrammarRejected covers every diverging pool shape named in
// the codex-review-181 report: malformed token, malformed mask, over-cap /8,
// over-cap /15, empty pool, v6 over-cap /111, and mixed valid+invalid. Each must
// be REJECTED at strict commit — the reject assertions FAIL against the
// unpatched validator (the fail-on-revert proof).
func TestSourceNATPoolBadGrammarRejected(t *testing.T) {
	cases := []struct {
		name string
		pool []string
		want string // substring the diagnostic must contain
	}{
		{
			name: "malformed-token",
			pool: []string{"set security nat source pool p1 address not-an-ip"},
			want: "not a valid IP address",
		},
		{
			name: "malformed-mask",
			pool: []string{"set security nat source pool p1 address 203.0.113.1/garbage"},
			want: "not a valid CIDR",
		},
		{
			name: "over-cap-slash8",
			pool: []string{"set security nat source pool p1 address 10.0.0.0/8"},
			want: "over the pool cap",
		},
		{
			name: "over-cap-slash15",
			pool: []string{"set security nat source pool p1 address 10.0.0.0/15"},
			want: "over the pool cap",
		},
		{
			name: "v6-over-cap-slash111",
			pool: []string{"set security nat source pool p1 address 2001:db8::/111"},
			want: "over the pool cap",
		},
		{
			name: "empty-pool",
			pool: []string{"set security nat source pool p1 port range 5000 to 6000"},
			want: "no pool addresses",
		},
		{
			name: "mixed-valid-invalid",
			pool: []string{
				"set security nat source pool p1 address 203.0.113.5/32",
				"set security nat source pool p1 address 203.0.113.1/garbage",
			},
			want: "not a valid CIDR",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(snat5627Tree(t, tc.pool...))
			if err == nil {
				t.Fatalf("expected strict commit to reject pool shape %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
			// Every reject must name the offending pool so the diagnostic is
			// actionable.
			if !strings.Contains(err.Error(), "p1") {
				t.Fatalf("error %q does not name the offending pool", err.Error())
			}
		})
	}
}

// TestSourceNATPoolValidGrammarCompiles asserts VALID pools still compile clean
// on the strict path — no false-positive. Covers bare IP, /32, a small subnet,
// the /16 boundary (exactly MaxSourceNATPoolPrefixHosts hosts — at the cap, NOT
// over), a bracket list, a range, and a v6 /112 boundary.
func TestSourceNATPoolValidGrammarCompiles(t *testing.T) {
	cases := []struct {
		name string
		pool []string
	}{
		{"bare-ip", []string{"set security nat source pool p1 address 203.0.113.10"}},
		{"host-cidr", []string{"set security nat source pool p1 address 203.0.113.10/32"}},
		{"small-subnet", []string{"set security nat source pool p1 address 203.0.113.0/24"}},
		{"slash16-boundary", []string{"set security nat source pool p1 address 100.64.0.0/16"}},
		{"bracket-list", []string{"set security nat source pool p1 address [ 203.0.113.1/32 203.0.113.2/32 ]"}},
		{"range", []string{"set security nat source pool p1 address 203.0.113.1/32 to 203.0.113.3/32"}},
		{"v6-host", []string{"set security nat source pool p1 address 2001:db8::1/128"}},
		{"v6-slash112-boundary", []string{"set security nat source pool p1 address 2001:db8::/112"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(snat5627Tree(t, tc.pool...)); err != nil {
				t.Fatalf("valid pool shape %q must compile clean on the strict path: %v", tc.name, err)
			}
		})
	}
}

// TestSourceNATPoolBadGrammarLenientWarns asserts the tolerant load / peer-sync
// path (#1960 no-brick) does NOT fail-closed on a malformed/over-cap/empty pool:
// it records a warning and boots (the snapshot builder independently marks the
// pool unusable). Covers a malformed member and an empty pool.
func TestSourceNATPoolBadGrammarLenientWarns(t *testing.T) {
	cases := []struct {
		name string
		pool []string
	}{
		{"malformed", []string{"set security nat source pool p1 address not-an-ip"}},
		{"empty", []string{"set security nat source pool p1 port range 5000 to 6000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(snat5627Tree(t, tc.pool...))
			if err != nil {
				t.Fatalf("lenient compile must not brick on a bad pool: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "source-nat pool address") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient compile must record a source-nat pool address warning; warnings = %v", cfg.Warnings)
			}
		})
	}
}

// TestSourceNATPoolUnreferencedBadPoolNotRejected pins the scoping decision:
// the gate closes the Go-vs-LIVE grammar divergence, and the live dataplane only
// expands pools that a pool-mode rule references. A defined-but-UNREFERENCED
// malformed pool never reaches the Rust grammar, so it is not rejected here —
// the gate stays grammar-EQUIVALENT with live rather than Go-stricter. (The port
// leaf keeps the pool syntactically well-formed for the compiler.)
func TestSourceNATPoolUnreferencedBadPoolNotRejected(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security nat source pool orphan address not-an-ip",
		"set security nat source pool orphan port range 5000 to 6000",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("an unreferenced pool with a bad address must not be rejected (grammar-equivalence with live, which never expands it): %v", err)
	}
}
