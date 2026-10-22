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

// Review fold (#16161): at a level that has BOTH child keywords and
// a wildcard slot, an ambiguous candidate prefix must describe
// NOTHING — not the wildcard's text. `system syslog host <host>`
// carries match/match-strings children plus the facility wildcard
// ("Syslog facility (value is the severity threshold)"); the old
// code returned that wildcard text for `ma`, contradicting the
// documented "any ambiguity yields (\"\", false)". Exact keywords
// keep their own text, a unique prefix still expands, and a
// non-keyword instance name still borrows the wildcard's.
func TestDescribeSetPathAmbiguousPrefixAtWildcardLevel16161(t *testing.T) {
	host := []string{"system", "syslog", "host", "10.0.0.1"}
	if got, ok := DescribeSetPath(host, "ma"); ok || got != "" {
		t.Errorf("DescribeSetPath(%v, \"ma\") = (%q, %v), want (\"\", false): ambiguous prefix of match/match-strings must not borrow the wildcard description",
			host, got, ok)
	}
	if got, ok := DescribeSetPath(host, "mat"); ok || got != "" {
		t.Errorf("DescribeSetPath(%v, \"mat\") = (%q, %v), want (\"\", false)",
			host, got, ok)
	}
	if got, ok := DescribeSetPath(host, "match"); !ok || got != "Regular-expression message filter" {
		t.Errorf("DescribeSetPath(%v, \"match\") = (%q, %v), want the match description",
			host, got, ok)
	}
	if got, ok := DescribeSetPath(host, "match-"); !ok || got != "Message string filter" {
		t.Errorf("DescribeSetPath(%v, \"match-\") = (%q, %v), want the match-strings description (unique prefix)",
			host, got, ok)
	}
	if got, ok := DescribeSetPath(host, "kern"); !ok || got != "Syslog facility (value is the severity threshold)" {
		t.Errorf("DescribeSetPath(%v, \"kern\") = (%q, %v), want the facility wildcard description for an instance name",
			host, got, ok)
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
