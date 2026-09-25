package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11011: lenient StableZoneID collision quarantine must cover the host-inbound
// enforcement surfaces, not just AF_XDP zones/interfaces/policies. The
// quarantine contract says a colliding zone's interfaces are unzoned and denied;
// before this fix the kernel host-inbound builders still consumed the raw
// configuration (views + VIP handling seeded from cfg.Security.Zones) and the
// AF_XDP per-interface host-inbound stamp survived the unzone — so listed host
// services on the quarantined zone stayed admitted on both the kernel-nft
// primary path and the userspace-dp secondary path (a stale per-interface stamp
// takes precedence over the #5659 empty-zone deny sentinel in Rust
// populate_interfaces).
//
// Fixture: the verified colliding pair z174 (survivor) / z214 (quarantined)
// with an addressed interface and a per-interface override on each side, plus a
// VRRP VIP on the quarantined side. Every cell is fail-on-revert: revert the
// corresponding exclusion and the quarantined zone's addr/VIP/stamp/admit
// reappears below. The survivor assertions in each cell pin that
// non-colliding configs (and the surviving side) are unchanged.
func quarantineHostInboundCfg11011(t *testing.T) *config.Config {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.10/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.10/24 vrrp-group 1 virtual-address 192.0.2.1/32",
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.10/24",
		"set security zones security-zone z174 interfaces ge-0/0/1.0",
		"set security zones security-zone z174 host-inbound-traffic system-services ssh",
		"set security zones security-zone z174 interfaces ge-0/0/1.0 host-inbound-traffic system-services https",
		"set security zones security-zone z214 interfaces ge-0/0/0.0",
		"set security zones security-zone z214 host-inbound-traffic system-services ping",
		"set security zones security-zone z214 interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must accept the reachable StableZoneID collision with a warning: %v", err)
	}
	requireCollisionPremise11011(t)
	return cfg
}

func requireCollisionPremise11011(t *testing.T) {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	excl := config.ZoneQuarantineExclusions([]string{"z174", "z214"})
	if len(excl) != 1 {
		t.Fatalf("test premise broken: quarantine set = %v, want exactly {z214}", excl)
	}
	if _, drop := excl["z214"]; !drop {
		t.Fatalf("test premise broken: quarantine set = %v, want exactly {z214}", excl)
	}
}

func viewCarriesAddr11011(views []ZoneHostInboundView, addr string) (zone string, ok bool) {
	for _, v := range views {
		for _, a := range v.V4Addrs {
			if a == addr {
				return v.Zone, true
			}
		}
		for _, a := range v.V6Addrs {
			if a == addr {
				return v.Zone, true
			}
		}
	}
	return "", false
}

// TestQuarantinedZoneHasNoHostInboundView_11011: the kernel host-inbound views
// must exclude the quarantined zone — no view for it, none of its addresses
// (interface addr or VIP) scoped by any view, and no classifier accept for it.
func TestQuarantinedZoneHasNoHostInboundView_11011(t *testing.T) {
	cfg := quarantineHostInboundCfg11011(t)

	views := BuildZoneHostInboundViews(cfg)
	for _, v := range views {
		if v.Zone == "z214" {
			t.Errorf("quarantined zone z214 still has a host-inbound view: %+v", v)
		}
	}
	for _, addr := range []string{"192.0.2.10", "192.0.2.1"} {
		if zone, ok := viewCarriesAddr11011(views, addr); ok {
			t.Errorf("quarantined-zone address %s still scoped by zone %q's host-inbound view, want unzoned", addr, zone)
		}
	}
	if got := ClassifyHostInbound(cfg, "z214", config.HostInboundProtoTCP, true, 22, nil, "ip"); got.Status == HostInboundTokenAdmit {
		t.Errorf("quarantined zone z214 tcp/22 = %+v, want no token-admit (its ssh override is quarantined)", got)
	}

	// Survivor control: z174 keeps its effective (override) view on its own
	// address, and the classifier still admits https there.
	var survivorScoped bool
	for _, v := range views {
		if v.Zone != "z174" {
			continue
		}
		for _, a := range v.V4Addrs {
			if a == "198.51.100.10" {
				survivorScoped = true
				var https bool
				for _, s := range v.SystemServices {
					if s == "https" {
						https = true
					}
				}
				if !https {
					t.Errorf("survivor view services = %v, want the [https] override set", v.SystemServices)
				}
			}
		}
	}
	if !survivorScoped {
		t.Errorf("survivor z174 lost its 198.51.100.10 host-inbound scope: %+v", views)
	}
	if got := ClassifyHostInboundForInterface(cfg, "z174", "ge-0/0/1.0", config.HostInboundProtoTCP, true, 443, nil, "ip"); got.Status != HostInboundTokenAdmit {
		t.Errorf("survivor z174 ge-0/0/1.0 tcp/443 = %+v, want token-admit via its https override", got)
	}
}

// TestQuarantinedZoneVIPExcludedFromViews_11011: VRRP VIP handling uses the same
// quarantine exclusion set — a VIP on a quarantined-zone interface must not be
// scoped by any zone view (on the master it is also live in the snapshot; on
// the backup only this config-derived walk covers it).
func TestQuarantinedZoneVIPExcludedFromViews_11011(t *testing.T) {
	cfg := quarantineHostInboundCfg11011(t)

	for _, v := range BuildZoneHostInboundViews(cfg) {
		for _, a := range append(append([]string{}, v.V4Addrs...), v.V6Addrs...) {
			if a == "192.0.2.1" {
				t.Errorf("quarantined-zone VIP 192.0.2.1 still in zone %q's host-inbound view: %+v", v.Zone, v)
			}
		}
	}
	v4, v6 := BuildUnzonedHostInboundAddrs(cfg)
	if !containsStr(v4, "192.0.2.1") && !containsStr(v6, "192.0.2.1") {
		t.Errorf("quarantined-zone VIP 192.0.2.1 missing from the unzoned catch-all drop set: v4=%v v6=%v", v4, v6)
	}
}

// TestQuarantinedZoneAddrsInUnzonedDropSet_11011: the quarantined interface's
// addresses move to the unzoned catch-all deny — the same fail-closed posture
// as an interface assigned to no zone (#4420 HI-2).
func TestQuarantinedZoneAddrsInUnzonedDropSet_11011(t *testing.T) {
	cfg := quarantineHostInboundCfg11011(t)

	v4, _ := BuildUnzonedHostInboundAddrs(cfg)
	var quarantinedScoped bool
	for _, a := range v4 {
		if a == "192.0.2.10" {
			quarantinedScoped = true
		}
		if a == "198.51.100.10" {
			t.Errorf("survivor address 198.51.100.10 leaked into the unzoned drop set: %v", v4)
		}
	}
	if !quarantinedScoped {
		t.Errorf("quarantined address 192.0.2.10 missing from the unzoned drop set: %v", v4)
	}
	// No duplicate/conflicting scope: the address must be denied in exactly one
	// place (unzoned), never also admitted/scoped by a zone view.
	if zone, ok := viewCarriesAddr11011(BuildZoneHostInboundViews(cfg), "192.0.2.10"); ok {
		t.Errorf("quarantined address 192.0.2.10 is ALSO scoped by zone %q's view — conflicting scopes", zone)
	}
}

// TestQuarantineClearsHostInboundStamp_11011: the published AF_XDP snapshot must
// carry no per-interface host-inbound stamp for a quarantined-zone interface —
// the stamp is what the Rust picker enforces first, ahead of the #5659
// empty-zone deny sentinel, so leaving it publishes an admit for a zone the
// quarantine says is unzoned and denied.
func TestQuarantineClearsHostInboundStamp_11011(t *testing.T) {
	cfg := quarantineHostInboundCfg11011(t)

	var raw InterfaceSnapshot
	var foundRaw bool
	for _, row := range buildInterfaceSnapshotsFrom(cfg, nil) {
		if row.Name == "ge-0/0/0.0" {
			raw, foundRaw = row, true
			break
		}
	}
	if !foundRaw || raw.Zone != "z214" || !raw.HostInboundConfigured ||
		!containsStr(raw.HostInboundSystemServices, "ssh") {
		t.Fatalf("precondition: the pre-quarantine AF_XDP row must carry z214's ssh override, got %+v", raw)
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.zoneIDCollisions) != 1 {
		t.Fatalf("snap.zoneIDCollisions = %v, want exactly one collision", snap.zoneIDCollisions)
	}
	byName := map[string]InterfaceSnapshot{}
	for _, s := range snap.Interfaces {
		byName[s.Name] = s
	}
	quarantined, ok := byName["ge-0/0/0.0"]
	if !ok {
		t.Fatalf("fixture produced no ge-0/0/0.0 snapshot row: %+v", snap.Interfaces)
	}
	if quarantined.Zone != "" {
		t.Errorf("ge-0/0/0.0 Zone = %q, want unzoned (quarantined)", quarantined.Zone)
	}
	if quarantined.HostInboundConfigured || len(quarantined.HostInboundSystemServices) != 0 ||
		len(quarantined.HostInboundProtocols) != 0 {
		t.Errorf("ge-0/0/0.0 host-inbound stamp survives quarantine: configured=%v services=%v protocols=%v, want none",
			quarantined.HostInboundConfigured, quarantined.HostInboundSystemServices, quarantined.HostInboundProtocols)
	}
	// Survivor control: the surviving zone's overridden interface keeps its
	// zone AND its effective stamp.
	survivor, ok := byName["ge-0/0/1.0"]
	if !ok {
		t.Fatalf("fixture produced no ge-0/0/1.0 snapshot row: %+v", snap.Interfaces)
	}
	if survivor.Zone != "z174" {
		t.Errorf("survivor ge-0/0/1.0 Zone = %q, want z174", survivor.Zone)
	}
	if !survivor.HostInboundConfigured {
		t.Errorf("survivor ge-0/0/1.0 lost its host-inbound stamp (HostInboundConfigured=false)")
	}
	var https bool
	for _, s := range survivor.HostInboundSystemServices {
		if s == "https" {
			https = true
		}
	}
	if !https {
		t.Errorf("survivor ge-0/0/1.0 services = %v, want the [https] override set", survivor.HostInboundSystemServices)
	}
}
