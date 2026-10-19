package config

import (
	"strings"
	"testing"
)

// #15139 — the #14343 "braced body cannot land on a leaf" decline also
// caught value leaves whose braced body IS their value. The partially
// elided host-inbound spelling admitted by #8850
// (`host-inbound-traffic system-services { ping; }`) was rejected at
// strict commit and silently lost its services/protocols on tolerant
// load; the elided policer `then loss-priority { high; }` failed commit.
//
// The fix declines only when the packed statement already consumed its
// own value (`screen my-screen { ... }`, `description x { ... }`); a
// bare keyword (no value token yet) folds and the body becomes the
// leaf's value children, exactly as the braced spelling parses.

func compile15139BothPaths(t *testing.T, txt string) (strict *Config, lenient *Config) {
	t.Helper()
	parse := func() *ConfigTree {
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", txt, errs)
		}
		return tree
	}
	var err error
	strict, err = CompileConfig(parse())
	if err != nil {
		t.Fatalf("strict compile %q: %v", txt, err)
	}
	lenient, err = CompileConfigLenient(parse())
	if err != nil {
		t.Fatalf("lenient compile %q: %v", txt, err)
	}
	return strict, lenient
}

func zoneHIB15139(t *testing.T, cfg *Config, txt string) *HostInboundTraffic {
	t.Helper()
	z := cfg.Security.Zones["z1"]
	if z == nil {
		t.Fatalf("%q compiled to no zone z1: %+v", txt, cfg.Security.Zones)
	}
	return z.HostInboundTraffic
}

func TestCompactLeafBareValueBody15139(t *testing.T) {
	// Value leaf, bare keyword: the body supplies the value(s). Both the
	// strict and the lenient (boot / HA sync) path must compile the
	// partially-elided spelling to the same admission as the braced one.
	for _, tc := range []struct {
		name       string
		braced     string
		elided     string
		get        func(*HostInboundTraffic) []string
		wantBraced []string
	}{
		{
			name:       "system-services",
			braced:     "security { zones { security-zone z1 { host-inbound-traffic { system-services { ssh; } } } } }",
			elided:     "security { zones { security-zone z1 { host-inbound-traffic system-services { ssh; } } } }",
			get:        func(h *HostInboundTraffic) []string { return h.SystemServices },
			wantBraced: []string{"ssh"},
		},
		{
			name:       "protocols",
			braced:     "security { zones { security-zone z1 { host-inbound-traffic { protocols { ospf; } } } } }",
			elided:     "security { zones { security-zone z1 { host-inbound-traffic protocols { ospf; } } } }",
			get:        func(h *HostInboundTraffic) []string { return h.Protocols },
			wantBraced: []string{"ospf"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bracedStrict, _ := compile15139BothPaths(t, tc.braced)
			if got := tc.get(zoneHIB15139(t, bracedStrict, tc.braced)); strings.Join(got, ",") != strings.Join(tc.wantBraced, ",") {
				t.Fatalf("braced reference compiled to %v, want %v; the elided comparison would be vacuous", got, tc.wantBraced)
			}
			strict, lenient := compile15139BothPaths(t, tc.elided)
			for path, cfg := range map[string]*Config{"strict": strict, "lenient": lenient} {
				hib := zoneHIB15139(t, cfg, tc.elided)
				if hib == nil {
					t.Fatalf("%s: %q compiled with no host-inbound-traffic", path, tc.elided)
				}
				if got := tc.get(hib); strings.Join(got, ",") != strings.Join(tc.wantBraced, ",") {
					t.Errorf("%s: %q compiled to %v, braced gave %v", path, tc.elided, got, tc.wantBraced)
				}
			}
		})
	}

	// Policer value leaf: `then loss-priority { high; }` is the value in
	// braced form and must keep marking on the strict path.
	t.Run("policer loss-priority block value", func(t *testing.T) {
		txt := "firewall { policer p1 { if-exceeding { bandwidth-limit 10m; burst-size-limit 15k; } then loss-priority { high; } } }"
		strict, lenient := compile15139BothPaths(t, txt)
		for path, cfg := range map[string]*Config{"strict": strict, "lenient": lenient} {
			p := cfg.Firewall.Policers["p1"]
			if p == nil {
				t.Fatalf("%s: no policer p1", path)
			}
			if p.ThenAction != "loss-priority high" {
				t.Errorf("%s: ThenAction = %q, want %q", path, p.ThenAction, "loss-priority high")
			}
		}
	})

	// Controls: a statement that already consumed its value still
	// declines, so the stranded body is rejected (strict) rather than
	// silently dropped — the #14343 behaviour is unchanged.
	for _, tc := range []struct{ name, txt string }{
		{
			"valued screen leaf keeps declining",
			`security { screen { ids-option my-screen { icmp { ping-death; } } } zones { security-zone trust screen my-screen { interfaces { ge-0/0/0.0; } } } } interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } } }`,
		},
		{
			"valued description leaf keeps declining",
			`security { zones { security-zone trust description hello { interfaces { ge-0/0/0.0; } } } } interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } } }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.txt).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Errorf("strict compile accepted a braced body stranded on a valued leaf; want the #14343 rejection")
			}
		})
	}
}
