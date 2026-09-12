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

// junosHostShieldLines returns the junos-host DROP-subchain lines that render an
// exemption shield matching `match` (e.g. "udp dport { 500, 4500 } accept").
func junosHostShieldLines(payload, match string) []string {
	var out []string
	for _, l := range junosHostSection(payload) {
		if strings.Contains(l, match) {
			out = append(out, l)
		}
	}
	return out
}

// TestJunosHostIKEExemptionScopedToConfiguringInterface is the #5565 fail-on-
// revert guard: a per-INTERFACE `ike` host-inbound override on ONE interface
// (ge-0/0/1.0) must render the IKE 500/4500 exemption shield scoped to THAT
// interface's netdev only (ge-0-0-1) — never the whole zone iifname set. The
// sibling ge-0/0/2.0, which configured no `ike`, must NOT be exempted. The
// zone-wide `application any` DROP still applies to BOTH netdevs (the deny is a
// zone policy). Revert the fix (zone-wide CoarseAdmitsIKE + whole-zone iif) and
// the shield widens to `{ "ge-0-0-1", "ge-0-0-2" }`, admitting IKE on the
// sibling — the sibling-not-exempted assertion FAILS.
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
	// Exactly one IKE shield, scoped to ge-0-0-1 alone.
	shields := junosHostShieldLines(payload, "udp dport { 500, 4500 } accept")
	if len(shields) != 1 {
		t.Fatalf("want exactly 1 IKE shield line, got %d:\n%s", len(shields), strings.Join(shields, "\n"))
	}
	if want := `iifname "ge-0-0-1" udp dport { 500, 4500 } accept`; strings.TrimSpace(shields[0]) != want {
		t.Fatalf("IKE shield = %q, want %q", strings.TrimSpace(shields[0]), want)
	}
	// The sibling ge-0-0-2 must NOT appear on any IKE shield (the #5565 leak).
	if strings.Contains(shields[0], "ge-0-0-2") {
		t.Fatalf("per-interface ike override widened to sibling ge-0-0-2:\n%s", shields[0])
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

// TestJunosHostZoneLevelIKEExemptionStaysZoneWide is the no-regression peer: an
// exception authored at ZONE scope (on the zone's own host-inbound-traffic,
// applying to every interface) must keep the shield zone-wide — scoped to the
// full iifname set { ge-0-0-1, ge-0-0-2 } — because every interface genuinely
// admits IKE. #5565 narrows only a PER-INTERFACE override, never a zone-level
// one.
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
	if len(shields) != 1 {
		t.Fatalf("want exactly 1 IKE shield line, got %d:\n%s", len(shields), strings.Join(shields, "\n"))
	}
	want := `iifname { "ge-0-0-1", "ge-0-0-2" } udp dport { 500, 4500 } accept`
	if strings.TrimSpace(shields[0]) != want {
		t.Fatalf("zone-level IKE shield = %q, want zone-wide %q", strings.TrimSpace(shields[0]), want)
	}
}
