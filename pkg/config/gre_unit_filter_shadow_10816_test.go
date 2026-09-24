package config

import (
	"strings"
	"testing"
)

// #10816: inheriting GRE units with different input filters warn at commit:
// decap attributes every inbound frame to the first-sorting unit row, so a
// sibling unit's input filter never sees a packet. Uniform filters,
// single-unit, non-tunnel, and per-unit-stanza (separate-bucket) shapes
// stay silent, as does a #7509-contested parent (deny dominates there).
// Fail-on-revert: unhook the advisory and the firing assertions go RED.
func TestGreUnitFilterShadowAdvisory10816(t *testing.T) {
	compile := func(t *testing.T, lines []string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range lines {
			p, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return cfg
	}
	filters := []string{
		"set firewall family inet filter F1 term t1 then accept",
		"set firewall family inet filter F2 term t1 then accept",
	}
	tunnel := []string{
		"set interfaces gr-0/0/0 tunnel source 10.1.1.1",
		"set interfaces gr-0/0/0 tunnel destination 10.1.1.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.255.192.42/30",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.255.193.42/30",
	}

	// (a) differing input filters across inheriting units → exactly one
	// #10816 warning naming the attributed row and the shadowed unit.
	cfgA := compile(t, append(append(append([]string{}, filters...), tunnel...),
		"set interfaces gr-0/0/0 unit 0 family inet filter input F2",
		"set interfaces gr-0/0/0 unit 1 family inet filter input F1",
	))
	gotA := warningsMentioning(cfgA, "#10816")
	if len(gotA) != 1 {
		t.Fatalf("(a) shadowed filter must warn once, got %d of %d warnings: %v",
			len(gotA), len(cfgA.Warnings), cfgA.Warnings)
	}
	for _, want := range []string{"gr-0/0/0.0", "gr-0/0/0.1", "never"} {
		if !strings.Contains(gotA[0], want) {
			t.Errorf("(a) warning must name %q, got: %s", want, gotA[0])
		}
	}

	// (b) uniform input filters → silent (one filter, nothing shadowed).
	cfgB := compile(t, append(append(append([]string{}, filters...), tunnel...),
		"set interfaces gr-0/0/0 unit 0 family inet filter input F1",
		"set interfaces gr-0/0/0 unit 1 family inet filter input F1",
	))
	if got := warningsMentioning(cfgB, "#10816"); len(got) != 0 {
		t.Fatalf("(b) uniform filters must be silent, got: %v", got)
	}

	// (c) no filters anywhere → silent (nothing to shadow).
	cfgC := compile(t, append(append([]string{}, filters...), tunnel...))
	if got := warningsMentioning(cfgC, "#10816"); len(got) != 0 {
		t.Fatalf("(c) filter-less units must be silent, got: %v", got)
	}

	// (d) sibling with its OWN tunnel stanza (distinct key) and its own
	// filter → silent: it decaps into its own bucket where its filter
	// applies normally (#10654 composition).
	cfgD := compile(t, append(append([]string{}, filters...),
		"set interfaces gr-0/0/0 tunnel source 10.1.1.1",
		"set interfaces gr-0/0/0 tunnel destination 10.1.1.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.255.192.42/30",
		"set interfaces gr-0/0/0 unit 0 family inet filter input F2",
		"set interfaces gr-0/0/0 unit 1 tunnel key 11",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.255.193.42/30",
		"set interfaces gr-0/0/0 unit 1 family inet filter input F1",
	))
	if got := warningsMentioning(cfgD, "#10816"); len(got) != 0 {
		t.Fatalf("(d) per-unit-stanza sibling must be silent, got: %v", got)
	}

	// (e) non-tunnel cross-filter units → silent (no decap fan-out).
	cfgE := compile(t, append(append([]string{}, filters...),
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet filter input F2",
		"set interfaces ge-0/0/0 unit 1 family inet address 192.0.2.2/24",
		"set interfaces ge-0/0/0 unit 1 family inet filter input F1",
	))
	if got := warningsMentioning(cfgE, "#10816"); len(got) != 0 {
		t.Fatalf("(e) non-tunnel parent must be silent, got: %v", got)
	}
}
