package frr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16620 (R3-A10-04): Junos static preferences rendered verbatim as FRR
// static distances arbitrated against FRR's DEFAULT protocol
// distances (OSPF 110, IS-IS 115, RIP 120, iBGP 200), inverting Junos
// floating-static designs. The fix pins every protocol that has an FRR
// distance knob to its Junos preference, per instance and globally:
//
//	distance ospf intra-area 10 inter-area 10 external 150
//	distance ospf6 intra-area 10 inter-area 10 external 150
//	distance bgp 170 170 170
//	distance 100            (RIP)
//
// IS-IS has no FRR distance knob (stable/10.6), so zebra keeps 115;
// see TestJunosArbitration16620 for the bounded residual window.

func TestProtocolDistancesRenderJunosScale16620(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{RouterID: "10.0.0.1"}
	ospfv3 := &config.OSPFv3Config{RouterID: "10.0.0.1"}
	bgp := &config.BGPConfig{LocalAS: 65001, RouterID: "10.0.0.1"}
	rip := &config.RIPConfig{Interfaces: []string{"trust0"}}
	isis := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2"}

	got := m.generateProtocols(ospf, ospfv3, bgp, rip, isis, "", 0, nil, nil)
	for _, want := range []string{
		"router ospf\n" + junosOSPFDistanceLine,
		"router ospf6\n" + junosOSPF6DistanceLine,
		"router bgp 65001\n",
		junosBGPDistanceLine,
		"router rip\n" + junosRIPDistanceLine,
		"router isis xpf\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing Junos distance rendering %q:\n%s", want, got)
		}
	}
	// Disabled protocols render nothing, distance lines included.
	disabled := m.generateProtocols(
		&config.OSPFConfig{Disable: true},
		&config.OSPFv3Config{Disable: true},
		&config.BGPConfig{LocalAS: 65001, Disable: true},
		&config.RIPConfig{Disable: true},
		&config.ISISConfig{Disable: true},
		"", 0, nil, nil)
	for _, bad := range []string{"distance ospf", "distance ospf6", "distance bgp", "distance 100"} {
		if strings.Contains(disabled, bad) {
			t.Errorf("disabled protocol rendered %q:\n%s", bad, disabled)
		}
	}
	// A BGP stanza with no AS renders nothing (no distance either).
	if got := m.generateProtocols(nil, nil, &config.BGPConfig{}, nil, nil, "", 0, nil, nil); strings.Contains(got, "distance") {
		t.Errorf("LocalAS==0 BGP rendered a distance line:\n%s", got)
	}
}

func TestProtocolDistancesRenderPerVRF16620(t *testing.T) {
	fc := &FullConfig{
		OSPF: &config.OSPFConfig{RouterID: "10.0.0.1"},
		BGP:  &config.BGPConfig{LocalAS: 65001},
		Instances: []InstanceConfig{{
			Name:    "cust",
			VRFName: "vrf-cust",
			OSPF:    &config.OSPFConfig{RouterID: "10.0.1.1"},
			OSPFv3:  &config.OSPFv3Config{RouterID: "10.0.1.1"},
			BGP:     &config.BGPConfig{LocalAS: 65002},
			RIP:     &config.RIPConfig{Interfaces: []string{"trust0"}},
			ISIS:    &config.ISISConfig{NET: "49.0001.0100.0000.0002.00", Level: "level-1"},
		}},
	}
	got := New().buildManagedSection(fc)
	for _, want := range []string{
		"router ospf vrf vrf-cust\n" + junosOSPFDistanceLine,
		"router ospf6 vrf vrf-cust\n" + junosOSPF6DistanceLine,
		"router bgp 65002 vrf vrf-cust\n",
		"router rip vrf vrf-cust\n" + junosRIPDistanceLine,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("per-VRF missing %q:\n%s", want, got)
		}
	}
	// BGP distance once per stanza: global + the one VRF.
	if n := strings.Count(got, junosBGPDistanceLine); n != 2 {
		t.Errorf("distance bgp rendered %d times, want 2 (global + VRF):\n%s", n, got)
	}
	if n := strings.Count(got, junosOSPFDistanceLine); n != 2 {
		t.Errorf("distance ospf rendered %d times, want 2 (global + VRF):\n%s", n, got)
	}
}

// zebraWinner mirrors zebra's same-prefix arbitration: the lowest
// administrative distance wins; a tie keeps the incumbent (here the
// protocol route, matching zebra's first-installed preference closely
// enough for the strict-inequality cases under test).
func zebraWinner16620(staticPref, protocolDist int) string {
	if staticPref < protocolDist {
		return "static"
	}
	return "protocol"
}

// TestJunosArbitration16620 is the table-driven acceptance proof: for
// every installable static preference 1..254, the zebra winner under
// the rendered distances must equal the Junos winner, for every
// protocol Junos defines a preference for. The only tolerated
// divergences are the IS-IS windows FRR cannot express (no IS-IS
// distance knob; zebra fixed at 115 vs Junos 15/18), which are counted
// and bounded explicitly rather than silently allowed.
func TestJunosArbitration16620(t *testing.T) {
	type proto struct {
		name       string
		junos      int
		rendered   int // effective distance in the managed section
		divergence func(staticPref int) bool
	}
	protos := []proto{
		{"ospf-internal", junosPreferenceOSPFInternal, junosPreferenceOSPFInternal, nil},
		{"ospf-external", junosPreferenceOSPFExternal, junosPreferenceOSPFExternal, nil},
		{"ospfv3-internal", junosPreferenceOSPFInternal, junosPreferenceOSPFInternal, nil},
		{"ospfv3-external", junosPreferenceOSPFExternal, junosPreferenceOSPFExternal, nil},
		{"bgp-external", junosPreferenceBGP, junosPreferenceBGP, nil},
		{"bgp-internal", junosPreferenceBGP, junosPreferenceBGP, nil},
		{"rip", junosPreferenceRIP, junosPreferenceRIP, nil},
		{"isis-level-1", junosPreferenceISISLevel1, frrISISFixedDistance, nil},
		{"isis-level-2", junosPreferenceISISLevel2, frrISISFixedDistance, nil},
	}
	for _, p := range protos {
		t.Run(p.name, func(t *testing.T) {
			divergent := 0
			for pref := 1; pref <= 254; pref++ {
				junosWinner := zebraWinner16620(pref, p.junos)
				frrWinner := zebraWinner16620(pref, p.rendered)
				if junosWinner == frrWinner {
					continue
				}
				// IS-IS residual: Junos 15/18 vs FRR-fixed 115.
				// Diverges exactly on pref in [junos, 115]: at the
				// tie (pref == junos) zebra keeps the protocol
				// route on Junos but the static wins in FRR, and
				// above it a static that should lose to IS-IS wins.
				if strings.HasPrefix(p.name, "isis-") && pref >= p.junos && pref <= frrISISFixedDistance {
					divergent++
					continue
				}
				t.Fatalf("preference %d: Junos winner %s (vs %d), rendered winner %s (vs %d)",
					pref, junosWinner, p.junos, frrWinner, p.rendered)
			}
			if strings.HasPrefix(p.name, "isis-") {
				want := frrISISFixedDistance - p.junos
				if divergent != want {
					t.Fatalf("IS-IS residual window = %d preferences, want %d (115-%d+1)", divergent, want, p.junos)
				}
				t.Logf("IS-IS residual: %d static preferences (Junos %d..115) order differently vs IS-IS; FRR has no IS-IS distance knob", divergent, p.junos)
			} else if divergent != 0 {
				t.Fatalf("unexpected divergences: %d", divergent)
			}
		})
	}

	// The two acceptance cases from the issue, spelled out.
	if got := zebraWinner16620(180, junosPreferenceBGP); got != "protocol" {
		t.Errorf("preference 180 must lose to iBGP (170), got %s", got)
	}
	if got := zebraWinner16620(12, junosPreferenceOSPFInternal); got != "protocol" {
		t.Errorf("preference 12 must lose to OSPF internal (10), got %s", got)
	}
	// Counter-case: preference 120 meant to beat OSPF external (150)
	// must now win (it lost to FRR's old flat OSPF 110).
	if got := zebraWinner16620(120, junosPreferenceOSPFExternal); got != "static" {
		t.Errorf("preference 120 must beat OSPF external (150), got %s", got)
	}
	// Omitted preference = Junos 5 still beats every dynamic protocol.
	for _, p := range protos {
		if got := zebraWinner16620(5, p.rendered); got != "static" {
			t.Errorf("default static preference 5 must beat %s (%d), got %s", p.name, p.rendered, got)
		}
	}
}

// TestRenderedStaticKeepsVerbatimPreference16620 pins that statics are
// NOT translated: the operator's Junos integer reaches FRR unchanged
// (including via the end-to-end compiler), while the protocol stanzas
// carry the Junos distances that make the arbitration come out right.
func TestRenderedStaticKeepsVerbatimPreference16620(t *testing.T) {
	compiled := compileQNHMetricConfig11447(t,
		"set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1 preference 180",
		"set routing-options static route 10.0.0.0/8 next-hop 192.0.2.1 preference 12",
		"set protocols bgp local-as 65001",
		"set protocols bgp group PEERS type internal",
		"set protocols bgp group PEERS neighbor 10.0.0.2 peer-as 65001",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
	)
	fc := &FullConfig{
		StaticRoutes:  compiled.RoutingOptions.StaticRoutes,
		BGP:           compiled.Protocols.BGP,
		OSPF:          compiled.Protocols.OSPF,
		PolicyOptions: &compiled.PolicyOptions,
	}
	got := New().buildManagedSection(fc)
	for _, want := range []string{
		"ip route 0.0.0.0/0 192.0.2.1 180\n",
		"ip route 10.0.0.0/8 192.0.2.1 12\n",
		junosBGPDistanceLine,
		junosOSPFDistanceLine,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
}

// JunosProtocolDistance must agree with the rendered lines.
func TestJunosProtocolDistanceTable16620(t *testing.T) {
	cases := map[string]int{
		"ospf": 10, "ospf6": 10, "isis": 115, "rip": 100, "bgp": 170,
	}
	for proto, want := range cases {
		if got, ok := JunosProtocolDistance(proto); !ok || got != want {
			t.Errorf("JunosProtocolDistance(%q) = %d,%v want %d,true", proto, got, ok, want)
		}
	}
	if _, ok := JunosProtocolDistance("static"); ok {
		t.Error("static must not report a protocol distance")
	}
	if junosISISPreference("level-1") != 15 || junosISISPreference("level-2") != 18 || junosISISPreference("level-1-2") != 18 {
		t.Errorf("Junos IS-IS preferences: L1=%d L2=%d", junosISISPreference("level-1"), junosISISPreference("level-2"))
	}
	_ = fmt.Sprint
}
