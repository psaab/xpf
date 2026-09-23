package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// junosHostTwoIfaceZoneConfig builds an `untrust` ingress zone with TWO
// non-lifeline dataplane interfaces (netdevs ge-0-0-1 and ge-0-0-2) that
// coarse-admit only `ping` at the zone level, plus a static address book and
// the lifeline mgmt zone. Callers add a per-interface host-inbound override on
// ge-0/0/1.0 and a `to-zone junos-host` deny, so the #5565 per-interface
// exemption scoping can be exercised against a sibling (ge-0/0/2.0) that
// configured no exception.
func junosHostTwoIfaceZoneConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.2.10/24"}},
		}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.3.10/24"}},
		}},
		// fxp0 is a lifeline — never scoped by a junos-host deny.
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.10/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {
			Name:               "untrust",
			Interfaces:         []string{"ge-0/0/1.0", "ge-0/0/2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ping"}},
		},
		"mgmt": {
			Name:               "mgmt",
			Interfaces:         []string{"fxp0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping"}},
		},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"bad-host": {Name: "bad-host", Value: "10.0.0.5/32"},
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-bad", "src:bad-host", "app:any")},
	}
	return cfg
}

// junosHostShieldLines returns the fine-window exemption lines matching `match`
// (e.g. the retained ident RST). #10524 deliberately removes the IKE ACCEPT,
// so IKE callers now expect this helper to return no matching lines.
func junosHostShieldLines(payload, match string) []string {
	var out []string
	for _, l := range junosHostSection(payload) {
		if strings.Contains(l, match) {
			out = append(out, l)
		}
	}
	return out
}

// TestJunosHostIKEExemptionScopedToConfiguringInterface is the #5565/#10524
// guard: the projection still computes the IKE-exempt subset for the
// per-interface coarse admission, but the daemon MUST NOT render a terminal
// IKE accept that bypasses the zone-wide fine DROP. The sibling remains part of
// the zone jump and DROP scope, while the subset metadata stays ge-0-0-1.
func TestJunosHostIKEExemptionScopedToConfiguringInterface(t *testing.T) {
	cfg := junosHostTwoIfaceZoneConfig()
	cfg.Security.Zones["untrust"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
		"ge-0/0/1.0": {SystemServices: []string{"ike"}},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d: %+v", len(programs), programs)
	}
	p := programs[0]
	if !p.CoarseAdmitsIKE {
		t.Fatal("zone coarse-admits ike on ge-0/0/1.0, so the program must set CoarseAdmitsIKE")
	}
	if got := strings.Join(p.IKEExemptNetdevs, ","); got != "ge-0-0-1" {
		t.Fatalf("IKEExemptNetdevs = %q, want ge-0-0-1 (only the interface that configured ike)", got)
	}
	// #10524: no IKE ACCEPT remains in the fine window; the old expected
	// shield was a pin of the explicit-deny bypass. The subset is retained in
	// the projection for the commit advisory and coarse-gate safety reasoning.
	shields := junosHostShieldLines(payload, "udp dport { 500, 4500 } accept")
	if len(shields) != 0 {
		t.Fatalf("IKE shield must be deleted, got %d:\n%s", len(shields), strings.Join(shields, "\n"))
	}
	// The zone-wide `application any` DROP still covers BOTH interfaces.
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	// #9504: the zone-wide scope is the jump's iifname set; the drop itself lives
	// in the subchain and carries only the authored source.
	wantJump := `iifname { "ge-0-0-1", "ge-0-0-2" } jump ` + xnft.HostInboundJunosHostChainName(0, "untrust")
	if !strings.Contains(payload, wantJump) {
		t.Fatalf("zone-wide jump missing (the deny must still apply to both interfaces):\nwant %q\n%s", wantJump, payload)
	}
	wantDrop := `meta nfproto ipv4 ip saddr 10.0.0.5/32 counter name "` + cn + `" drop`
	if !strings.Contains(payload, wantDrop) {
		t.Fatalf("zone-wide DROP missing from the subchain:\nwant %q\n%s", wantDrop, payload)
	}
}

// TestJunosHostIdentResetScopedToConfiguringInterface: a per-INTERFACE
// `ident-reset` override on ge-0/0/1.0 RSTs TCP/113 only on ge-0-0-1; the
// sibling ge-0/0/2.0 (no ident-reset) is NOT RST-shielded (it silently denies).
// Reverting widens the RST shield to the whole zone — the sibling assertion
// FAILS.
func TestJunosHostIdentResetScopedToConfiguringInterface(t *testing.T) {
	cfg := junosHostTwoIfaceZoneConfig()
	cfg.Security.Zones["untrust"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
		"ge-0/0/1.0": {SystemServices: []string{"ident-reset"}},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d: %+v", len(programs), programs)
	}
	p := programs[0]
	if !p.CoarseIdentResets {
		t.Fatal("zone resets ident on ge-0/0/1.0, so the program must set CoarseIdentResets")
	}
	if got := strings.Join(p.IdentResetNetdevs, ","); got != "ge-0-0-1" {
		t.Fatalf("IdentResetNetdevs = %q, want ge-0-0-1", got)
	}
	shields := junosHostShieldLines(payload, "tcp dport 113 reject with tcp reset")
	if len(shields) != 1 {
		t.Fatalf("want exactly 1 ident RST shield line, got %d:\n%s", len(shields), strings.Join(shields, "\n"))
	}
	if want := `iifname "ge-0-0-1" tcp dport 113 reject with tcp reset`; strings.TrimSpace(shields[0]) != want {
		t.Fatalf("ident shield = %q, want %q", strings.TrimSpace(shields[0]), want)
	}
	if strings.Contains(shields[0], "ge-0-0-2") {
		t.Fatalf("per-interface ident-reset widened to sibling ge-0-0-2:\n%s", shields[0])
	}
}

// TestJunosHostZoneLevelIKEExemptionStaysZoneWide is the #5565 projection
// peer after the #10524 fix: a zone-level IKE exception still computes the
// full IKEExemptNetdevs subset, but no terminal IKE ACCEPT is rendered. The
// zone-wide application-any DROP therefore governs denied IKE on both
// interfaces; the subset remains available to the overlap advisory.
func TestJunosHostZoneLevelIKEExemptionStaysZoneWide(t *testing.T) {
	cfg := junosHostTwoIfaceZoneConfig()
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ping", "ike"}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d: %+v", len(programs), programs)
	}
	p := programs[0]
	if got := strings.Join(p.IKEExemptNetdevs, ","); got != "ge-0-0-1,ge-0-0-2" {
		t.Fatalf("IKEExemptNetdevs = %q, want ge-0-0-1,ge-0-0-2 (zone-level ike covers every interface)", got)
	}
	shields := junosHostShieldLines(payload, "udp dport { 500, 4500 } accept")
	if len(shields) != 0 {
		t.Fatalf("zone-level IKE shield must be deleted, got %d:\n%s", len(shields), strings.Join(shields, "\n"))
	}
}
