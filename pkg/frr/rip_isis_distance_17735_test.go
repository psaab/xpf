package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17735: Junos orders IS-IS (L1 15 / L2 18) ahead of RIP (100), but FRR
// has no IS-IS distance knob — zebra keeps IS-IS at its fixed 115 while
// #16620 pins RIP to 100, so in zebra a same-prefix RIP route BEAT the
// IS-IS route, the exact reverse of Junos. The honest mechanism (no
// invented IS-IS knob exists) is fail-closed divergence: a table whose
// RIP and IS-IS are both active must not silently install the inverted
// ordering. Strict commit rejects it; the tolerant renderer withholds
// RIP (the protocol whose Junos pin created the inversion) and keeps
// IS-IS, so the surviving protocol is the one Junos prefers.
//
// The expected values below are INDEPENDENT Junos literals (IS-IS L1
// 15, L2 18, RIP 100, static default 5) — deliberately NOT the
// production constants, so a drift in the render table cannot make
// both sides of the comparison drift together (the #16620 test's
// same-constant defect).

func TestRIPISISInversionRejectedStrict17735(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want bool // true = strict commit must reject
	}{
		{"global rip+isis", []string{
			"set protocols rip neighbor ge-0/0/0",
			"set protocols isis net 49.0001.0100.0000.0001.00",
			"set protocols isis interface ge-0/0/1",
		}, true},
		{"global static 50+isis", []string{
			"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1 preference 50",
			"set protocols isis net 49.0001.0100.0000.0001.00",
			"set protocols isis interface ge-0/0/1",
		}, true},
		{"global static 5+isis", []string{
			"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1 preference 5",
			"set protocols isis net 49.0001.0100.0000.0001.00",
			"set protocols isis interface ge-0/0/1",
		}, false},
		{"global static 115+isis", []string{
			"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1 preference 115",
			"set protocols isis net 49.0001.0100.0000.0001.00",
			"set protocols isis interface ge-0/0/1",
		}, false},
		{"vrf rip+isis", []string{
			"set routing-instances V instance-type virtual-router",
			"set routing-instances V interface ge-0-0-0",
			"set routing-instances V protocols rip neighbor ge-0-0-0",
			"set routing-instances V protocols isis net 49.0001.0100.0000.0001.00",
			"set routing-instances V protocols isis interface ge-0-0-0",
		}, true},
		{"vrf static 50+isis", []string{
			"set routing-instances V instance-type virtual-router",
			"set routing-instances V interface ge-0-0-0",
			"set routing-instances V routing-options static route 203.0.113.0/24 next-hop 192.0.2.1 preference 50",
			"set routing-instances V protocols isis net 49.0001.0100.0000.0001.00",
			"set routing-instances V protocols isis interface ge-0-0-0",
		}, true},
		// Controls: a single protocol, or a disabled peer, is legal.
		{"rip only", []string{
			"set protocols rip neighbor ge-0/0/0",
		}, false},
		{"isis only", []string{
			"set protocols isis net 49.0001.0100.0000.0001.00",
			"set protocols isis interface ge-0/0/1",
		}, false},
		{"rip disabled + isis", []string{
			"set protocols rip disable",
			"set protocols rip neighbor ge-0/0/0",
			"set protocols isis net 49.0001.0100.0000.0001.00",
			"set protocols isis interface ge-0/0/1",
		}, false},
		{"isis disabled + rip", []string{
			"set protocols isis disable",
			"set protocols isis net 49.0001.0100.0000.0001.00",
			"set protocols isis interface ge-0/0/1",
			"set protocols rip neighbor ge-0/0/0",
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := &config.ConfigTree{}
			for _, c := range tc.cmds {
				path, err := config.ParseSetCommand(c)
				if err != nil {
					t.Fatalf("parse %q: %v", c, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("set %q: %v", c, err)
				}
			}
			_, err := config.CompileConfig(tree)
			if tc.want && err == nil {
				t.Fatalf("strict commit accepted a Junos/FRR distance inversion (#17735)")
			}
			if tc.want && err != nil && !strings.Contains(err.Error(), "#17735") {
				t.Fatalf("rejection must name #17735: %v", err)
			}
			if !tc.want && err != nil {
				t.Fatalf("control rejected: %v", err)
			}
		})
	}
}

// The current FRR renderer cannot represent a Junos static distance between
// IS-IS (15/18) and RIP (100): FRR fixes IS-IS at 115 while RIP is pinned at
// 100, leaving no distance for a static that loses to IS-IS but beats RIP.
// The renderer therefore withholds a conflicting static on tolerant loads.
func TestISISStaticDistanceConflictRenderFailsClosed17735(t *testing.T) {
	m := New()
	isis := &config.ISISConfig{
		NET:        "49.0001.0100.0000.0001.00",
		Interfaces: []*config.ISISInterface{{Name: "ge-0-0-1"}},
	}
	for _, tc := range []struct {
		name        string
		pref        int
		hopPref     int
		wantOmitted bool
	}{
		{"below-isis", 5, 0, false},
		{"inside-l1-l2-window", 50, 0, true},
		{"at-frr-isis-boundary", 115, 0, false},
		{"qualified-hop-window", 5, 50, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hop := config.NextHopEntry{Address: "192.0.2.1"}
			if tc.hopPref != 0 {
				hop.Preference, hop.HasPreference = tc.hopPref, true
			}
			sr := &config.StaticRoute{
				Destination: "203.0.113.0/24",
				NextHops:    []config.NextHopEntry{hop},
				Preference:  tc.pref,
			}
			got := m.buildManagedSection(&FullConfig{
				ISIS:         isis,
				StaticRoutes: []*config.StaticRoute{sr},
				DeclaredNetdevs: map[string]string{
					"ge-0-0-1": "ge-0-0-1",
				},
			})
			rendered := strings.Contains(got, "ip route 203.0.113.0/24")
			if rendered != !tc.wantOmitted {
				t.Fatalf("static pref %d (qualified %d) omission=%t, want %t:\n%s",
					tc.pref, tc.hopPref, !rendered, tc.wantOmitted, got)
			}
		})
	}
}

// Independent Junos expected values prevent renderer and expectation from
// drifting together. The helper-FIB representation uses Junos IS-IS preference
// 15, the more-preferred level, because rtnetlink does not identify L1 vs L2;
// this is conservative for fail-closed route selection.
func TestRIPvsISISArbitrationIndependent17735(t *testing.T) {
	const junosRIP, frrISIS, junosStatic = 100, 115, 5
	cases := []struct {
		name       string
		junosISIS  int
		helperISIS int
	}{
		{"level-1", 15, 15},
		{"level-2", 18, 15},
	}
	ripDist, ok := JunosProtocolDistance("rip")
	if !ok || ripDist != junosRIP {
		t.Fatalf("RIP rendered distance = %d,%v; want Junos 100", ripDist, ok)
	}
	renderedISIS := frrISISFixedDistance
	if renderedISIS != frrISIS {
		t.Fatalf("zebra IS-IS distance = %d; want FRR fixed 115", renderedISIS)
	}
	helperISIS, ok := JunosProtocolDistance("isis")
	if !ok {
		t.Fatal("helper-FIB must recognize IS-IS")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.junosISIS >= junosRIP {
				t.Fatalf("Junos premise broken: IS-IS %d must beat RIP %d", tc.junosISIS, junosRIP)
			}
			if junosStatic >= tc.junosISIS {
				t.Fatalf("Junos premise broken: static %d must beat IS-IS %d", junosStatic, tc.junosISIS)
			}
			if helperISIS != tc.helperISIS {
				t.Fatalf("helper-FIB IS-IS distance = %d; want conservative Junos-scale %d", helperISIS, tc.helperISIS)
			}
			if got := zebraWinner16620(50, helperISIS); got != "protocol" {
				t.Fatalf("helper-FIB must keep IS-IS ahead of static preference 50, got %s", got)
			}
			if got := zebraWinner16620(junosStatic, helperISIS); got != "static" {
				t.Fatalf("Junos static preference 5 must beat helper-FIB IS-IS, got %s", got)
			}
			// Without the config gate, zebra would install RIP at 100 over
			// IS-IS at 115. Junos chooses IS-IS for both levels.
			if ripDist >= renderedISIS {
				t.Fatalf("test premise broken: zebra RIP %d must incorrectly beat IS-IS %d", ripDist, renderedISIS)
			}
		})
	}
	// The cross-field config validation is the only honest way to close this
	// render-level inversion: no IS-IS distance knob exists, and assigning a
	// static a value between 100 and 115 cannot both beat RIP and lose to
	// IS-IS. Tolerant rendering keeps IS-IS and withholds RIP.
	got := New().generateProtocolsCluster15158(nil, nil, nil,
		&config.RIPConfig{Interfaces: []string{"ge-0-0-0"}},
		&config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Interfaces: []*config.ISISInterface{{Name: "ge-0-0-1"}}},
		"", 0, nil, nil, nil, false)
	if strings.Contains(got, "router rip") {
		t.Fatalf("tolerant render kept RIP beside IS-IS; Junos chooses IS-IS:\n%s", got)
	}
	if !strings.Contains(got, "router isis") {
		t.Fatalf("tolerant render dropped IS-IS (the Junos winner):\n%s", got)
	}
	gotV := New().generateProtocolsCluster15158(nil, nil, nil,
		&config.RIPConfig{Interfaces: []string{"ge-0-0-0"}},
		&config.ISISConfig{NET: "49.0001.0100.0000.0002.00", Interfaces: []*config.ISISInterface{{Name: "ge-0-0-1"}}},
		"vrf-BLUE", 0, nil, nil, nil, false)
	if strings.Contains(gotV, "router rip") || !strings.Contains(gotV, "router isis xpf vrf vrf-BLUE") {
		t.Fatalf("per-VRF tolerant render did not keep the Junos winner:\n%s", gotV)
	}
	// Controls: each protocol alone remains renderable at its established
	// distance.
	gotRIP := New().generateProtocolsCluster15158(nil, nil, nil,
		&config.RIPConfig{Interfaces: []string{"ge-0-0-0"}}, nil,
		"", 0, nil, nil, nil, false)
	if !strings.Contains(gotRIP, "router rip") || !strings.Contains(gotRIP, " distance 100\n") {
		t.Fatalf("RIP-only control must render at distance 100:\n%s", gotRIP)
	}
	gotISIS := New().generateProtocolsCluster15158(nil, nil, nil, nil,
		&config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Interfaces: []*config.ISISInterface{{Name: "ge-0-0-1"}}},
		"", 0, nil, nil, nil, false)
	if !strings.Contains(gotISIS, "router isis") {
		t.Fatalf("IS-IS-only control must render:\n%s", gotISIS)
	}
}

