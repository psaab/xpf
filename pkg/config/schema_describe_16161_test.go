package config

import "testing"

// #16161: every former cmdtree `set system dataplane` overlay knob must
// resolve a non-empty description through the schema path. The expected
// strings are the schema's own descs AFTER the overlay's better strings
// were upstreamed (claim-host-tunables, coalescence rx/tx-usecs); the
// deliberate deltas from the deleted overlay are pinned in
// TestDescribeSetPathOverlayDeltas16161 below.
func TestDescribeSetPathFormerOverlayKnobs16161(t *testing.T) {
	cases := []struct {
		tokens []string
		name   string
		want   string
	}{
		{[]string{"system"}, "dataplane", "Dataplane configuration"},
		{[]string{"system", "dataplane"}, "rss-indirection", "RSS indirection reshaping (enable|disable)"},
		{[]string{"system", "dataplane"}, "claim-host-tunables", "Allow xpfd to write host-scope tunables (true|false; default false)"},
		{[]string{"system", "dataplane"}, "cpu-governor", "Host cpufreq governor (performance|schedutil|default; other governors pass through verbatim)"},
		{[]string{"system", "dataplane"}, "netdev-budget", "net.core.netdev_budget value"},
		{[]string{"system", "dataplane"}, "coalescence", "NIC interrupt-coalescence tuning (mlx5)"},
		{[]string{"system", "dataplane", "coalescence"}, "adaptive", "Adaptive coalescing (enable|disable)"},
		{[]string{"system", "dataplane", "coalescence"}, "rx-usecs", "RX coalescing microseconds"},
		{[]string{"system", "dataplane", "coalescence"}, "tx-usecs", "TX coalescing microseconds"},
	}
	for _, tc := range cases {
		got, ok := DescribeSetPath(tc.tokens, tc.name)
		if !ok || got != tc.want {
			t.Errorf("DescribeSetPath(%v, %q) = (%q, %v), want (%q, true)",
				tc.tokens, tc.name, got, ok, tc.want)
		}
		if got == "" {
			t.Errorf("DescribeSetPath(%v, %q): empty description for former overlay knob",
				tc.tokens, tc.name)
		}
	}
}

// The knob-diff deltas of #16161, pinned so a future description edit
// is a deliberate change: the schema's cpu-governor desc is BETTER
// than the overlay's (it documents the verbatim pass-through), so it
// was kept and the overlay string dropped; claim-host-tunables and
// the coalescence usec leaves took the overlay's plainer strings.
func TestDescribeSetPathOverlayDeltas16161(t *testing.T) {
	if got, _ := DescribeSetPath([]string{"system", "dataplane"}, "cpu-governor"); got == "Host cpufreq governor (performance|schedutil|default)" {
		t.Error("cpu-governor kept the overlay string; the schema's pass-through note must win (#16161 knob diff)")
	}
}

// Abbreviated consumed words expand by unique prefix, mirroring
// ResolveConsumedSetPathTokens; ambiguous prefixes and unknown
// paths describe nothing rather than guessing.
func TestDescribeSetPathPrefixAndMisses16161(t *testing.T) {
	if got, ok := DescribeSetPath([]string{"sys", "dataplane"}, "rss-indirection"); !ok || got == "" {
		t.Errorf("abbreviated path: got (%q, %v), want a description", got, ok)
	}
	// "data" prefixes both dataplane and dataplane-type: ambiguous, no guess.
	if got, ok := DescribeSetPath([]string{"system", "data"}, "rss-indirection"); ok || got != "" {
		t.Errorf("ambiguous prefix: got (%q, %v), want (\"\", false)", got, ok)
	}
	for _, tc := range []struct {
		tokens []string
		name   string
	}{
		{[]string{"system", "dataplane"}, "no-such-knob"},
		{[]string{"no-such-top"}, "dataplane"},
		{[]string{"system", "dataplane", "coalescence", "bogus"}, "adaptive"},
		{[]string{"system", "dataplane", "rss-indirection", "enable"}, "adaptive"},
		{nil, ""},
	} {
		if got, ok := DescribeSetPath(tc.tokens, tc.name); ok || got != "" {
			t.Errorf("DescribeSetPath(%v, %q) = (%q, %v), want (\"\", false)",
				tc.tokens, tc.name, got, ok)
		}
	}
}

// Identity (args) tokens are consumed as values, so a description
// lookup past a named instance still lands on the right children.
func TestDescribeSetPathConsumesArgs16161(t *testing.T) {
	// system login user <name> class — `user` takes one identity token.
	if got, ok := DescribeSetPath([]string{"system", "login", "user", "alice"}, "class"); !ok || got == "" {
		t.Errorf("past identity token: got (%q, %v), want the class description", got, ok)
	}
}
