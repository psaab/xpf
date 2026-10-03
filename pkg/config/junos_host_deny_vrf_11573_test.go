package config

import (
	"net/netip"
	"slices"
	"testing"
)

// junos_host_deny_vrf_11573_test.go pins #11573: a VRF-member fine DENY must be
// scoped by the LOCAL_IN-visible VRF master instead of dropped as Unscopable.
// At LOCAL_IN iifname names the master, so a member-netdev-keyed rule matches
// nothing (#6619) — but dropping the candidate emits NO rule while the coarse
// service-only gate still admits the service. The fix rescopes uniquely-owned
// masters into Scoped (preserving per-member zone/VRF identity via the
// effective-target claim check); a master shared by multiple zones stays
// Unscopable as cross-zone-ambiguous (operator-fixable by re-zoning).

// vrf11573Config is one VRF-member ingress zone (untrust on ge-0/0/1.0,
// enslaved to virtual-router tenant) with a source-scoped application-any
// deny, so scope — not representability — decides emission.
func vrf11573Config() *Config {
	cfg := jhTestConfig()
	cfg.RoutingInstances = []*RoutingInstanceConfig{{
		Name: "tenant", InstanceType: "virtual-router", Interfaces: []string{"ge-0/0/1.0"},
	}}
	cfg.Security.Policies = []*ZonePairPolicies{{
		FromZone: "untrust", ToZone: "junos-host",
		Policies: []*Policy{jhDeny("block-vrf", []string{"bad-net"}, []string{"any"})},
	}}
	return cfg
}

// vrf11573Program returns the projection program for zone, failing when absent.
func vrf11573Program(t *testing.T, cfg *Config, zone string) JunosHostDenyProgram {
	t.Helper()
	for _, p := range BuildJunosHostDenyProjection(cfg).Programs {
		if p.Zone == zone {
			return p
		}
	}
	t.Fatalf("no junos-host program for zone %q", zone)
	return JunosHostDenyProgram{}
}

// vrf11573Verdict hermetically evaluates one v4 packet (LOCAL_IN iifname plus
// source) against the program's first-match v4 rules. It mirrors the nft
// rendering: the iifname scope gates entry to the zone subchain, then rules
// apply in order. Reported verdicts are drop=true (a DROP rule matched),
// allow (no rule matched — the packet falls through to the coarse gate).
func vrf11573Verdict(t *testing.T, prog JunosHostDenyProgram, iifname, src string) (drop bool) {
	t.Helper()
	if !slices.Contains(prog.IngressNetdevs, iifname) {
		t.Fatalf("packet iifname %q not in program scope %v — the rule cannot fire there", iifname, prog.IngressNetdevs)
	}
	addr, err := netip.ParseAddr(src)
	if err != nil {
		t.Fatalf("bad test source %q: %v", src, err)
	}
	matchNets := func(nets []string) bool {
		for _, n := range nets {
			pfx, err := netip.ParsePrefix(n)
			if err != nil {
				t.Fatalf("bad test prefix %q: %v", n, err)
			}
			if pfx.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, r := range prog.RulesV4 {
		if r.Family != "ip" {
			continue
		}
		var srcHit bool
		switch {
		case r.SrcAny:
			srcHit = true
		case r.SrcExcluded:
			srcHit = !matchNets(r.Src)
		default:
			srcHit = matchNets(r.Src)
		}
		if !srcHit || !r.DstAny || len(r.L4) != 0 {
			continue
		}
		return r.Verdict == JunosHostDrop
	}
	return false
}

// TestJunosHostVRFMemberDenyScopedByMaster11573 is the DROP half: the
// VRF-member deny is scoped by vrf-tenant (the LOCAL_IN-visible master), the
// denied source matches the emitted DROP, and the warning is suppressed.
func TestJunosHostVRFMemberDenyScopedByMaster11573(t *testing.T) {
	cfg := vrf11573Config()
	cov := junosHostZoneNetdevCoverageMap(cfg)["untrust"]
	if !slices.Equal(cov.Scoped, []string{"vrf-tenant"}) || len(cov.Unscopable) != 0 {
		t.Fatalf("VRF-member coverage = %+v, want Scoped=[vrf-tenant] with no gap", cov)
	}
	prog := vrf11573Program(t, cfg, "untrust")
	if !prog.Representable {
		t.Fatalf("VRF-member program must be representable: %+v", prog)
	}
	if !slices.Equal(prog.IngressNetdevs, []string{"vrf-tenant"}) {
		t.Fatalf("program scope = %v, want [vrf-tenant] — the iifname set is the mechanism", prog.IngressNetdevs)
	}
	drops := 0
	for _, r := range prog.RulesV4 {
		if r.Verdict == JunosHostDrop && slices.Contains(r.Src, "10.0.0.0/8") {
			drops++
		}
	}
	if drops == 0 {
		t.Fatalf("no emitted v4 DROP covers denied source 10.0.0.0/8: %+v", prog.RulesV4)
	}
	if !vrf11573Verdict(t, prog, "vrf-tenant", "10.1.2.3") {
		t.Fatalf("denied-source packet (iif vrf-tenant, src 10.1.2.3) must DROP")
	}
	key := JunosHostZonePairPolicyKey("untrust", "block-vrf")
	if !BuildJunosHostDenyProjection(cfg).RenderedPolicyKeys[key] {
		t.Fatalf("fully-scoped VRF-member deny must suppress its #4168 warning")
	}
	if warnings := validateJunosHostDirectDeliveryWarnings(cfg); len(warnings) != 0 {
		t.Fatalf("fully-scoped VRF-member deny must not retain a direct-path warning: %v", warnings)
	}
}

// TestJunosHostVRFMemberPermitSourceAllowed11573 is the ALLOW half: a source
// outside the deny still falls through to the coarse gate, which admits the
// zone's configured control service on the member's effective set.
func TestJunosHostVRFMemberPermitSourceAllowed11573(t *testing.T) {
	cfg := vrf11573Config()
	prog := vrf11573Program(t, cfg, "untrust")
	if vrf11573Verdict(t, prog, "vrf-tenant", "192.0.2.7") {
		t.Fatalf("permitted-source packet (iif vrf-tenant, src 192.0.2.7) must NOT drop")
	}
	svc, _, _ := cfg.Security.Zones["untrust"].InterfaceHostInboundEffective("ge-0/0/1.0")
	if !slices.Contains(svc, "ssh") {
		t.Fatalf("member effective services = %v, want ssh admitted so permitted-source control is allowed", svc)
	}
}

// TestJunosHostSharedVRFMasterStaysUnscopable11573 pins ownership boundaries:
// a master claimed by multiple zones or by an unzoned co-member cannot scope a
// zone's deny without over-firing. Distinct VRFs keep distinct master scopes.
func TestJunosHostSharedVRFMasterStaysUnscopable11573(t *testing.T) {
	t.Run("shared master is ambiguous for both zones", func(t *testing.T) {
		cfg := jhTestConfig()
		cfg.Interfaces.Interfaces["ge-0/0/2"] = &InterfaceConfig{
			Name: "ge-0/0/2", Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.3.10/24"}}},
		}
		cfg.Security.Zones["trust"] = &ZoneConfig{
			Name: "trust", Interfaces: []string{"ge-0/0/2.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
		}
		cfg.RoutingInstances = []*RoutingInstanceConfig{{
			Name: "tenant", InstanceType: "virtual-router",
			Interfaces: []string{"ge-0/0/1.0", "ge-0/0/2.0"},
		}}
		cfg.Security.Policies = []*ZonePairPolicies{
			{FromZone: "untrust", ToZone: "junos-host",
				Policies: []*Policy{jhDeny("block-vrf", []string{"bad-net"}, []string{"any"})}},
			{FromZone: "trust", ToZone: "junos-host",
				Policies: []*Policy{jhDeny("block-vrf", []string{"bad-net"}, []string{"any"})}},
		}
		for _, zone := range []string{"untrust", "trust"} {
			cov := junosHostZoneNetdevCoverageMap(cfg)[zone]
			if slices.Contains(cov.Scoped, "vrf-tenant") {
				t.Fatalf("%s: shared master must not scope: %+v", zone, cov)
			}
			if len(cov.Unscopable) != 1 || cov.Unscopable[0].Netdev != "vrf-tenant" ||
				cov.Unscopable[0].Reason != junosHostNetdevAmbiguous {
				t.Fatalf("%s: want one ambiguous gap on vrf-tenant, got %+v", zone, cov)
			}
			key := JunosHostZonePairPolicyKey(zone, "block-vrf")
			if BuildJunosHostDenyProjection(cfg).RenderedPolicyKeys[key] {
				t.Fatalf("%s: ambiguous-master deny must keep its warning", zone)
			}
		}
	})
	t.Run("distinct VRFs keep distinct master scopes", func(t *testing.T) {
		cfg := jhTestConfig()
		cfg.Interfaces.Interfaces["ge-0/0/2"] = &InterfaceConfig{
			Name: "ge-0/0/2", Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.3.10/24"}}},
		}
		cfg.Security.Zones["trust"] = &ZoneConfig{
			Name: "trust", Interfaces: []string{"ge-0/0/2.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
		}
		cfg.RoutingInstances = []*RoutingInstanceConfig{
			{Name: "tenant-a", InstanceType: "virtual-router", Interfaces: []string{"ge-0/0/1.0"}},
			{Name: "tenant-b", InstanceType: "virtual-router", Interfaces: []string{"ge-0/0/2.0"}},
		}
		for zone, want := range map[string]string{"untrust": "vrf-tenant-a", "trust": "vrf-tenant-b"} {
			cov := junosHostZoneNetdevCoverageMap(cfg)[zone]
			if !slices.Equal(cov.Scoped, []string{want}) || len(cov.Unscopable) != 0 {
				t.Fatalf("%s: coverage = %+v, want Scoped=[%s] with no gap", zone, cov, want)
			}
		}
	})
	t.Run("unowned VRF co-member keeps master unscopable", func(t *testing.T) {
		cfg := vrf11573Config()
		cfg.Interfaces.Interfaces["ge-0/0/2"] = &InterfaceConfig{
			Name: "ge-0/0/2", Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.3.10/24"}}},
		}
		cfg.RoutingInstances[0].Interfaces = append(cfg.RoutingInstances[0].Interfaces, "ge-0/0/2.0")
		cov := junosHostZoneNetdevCoverageMap(cfg)["untrust"]
		if len(cov.Scoped) != 0 || len(cov.Unscopable) != 1 ||
			cov.Unscopable[0].Netdev != "vrf-tenant" ||
			cov.Unscopable[0].Reason != junosHostNetdevAmbiguous {
			t.Fatalf("unowned VRF member shares LOCAL_IN master, so the zone's deny must remain unscopable: %+v", cov)
		}
		key := JunosHostZonePairPolicyKey("untrust", "block-vrf")
		if BuildJunosHostDenyProjection(cfg).RenderedPolicyKeys[key] {
			t.Fatalf("deny on a master shared with unzoned ingress must keep its warning")
		}
	})
}

// stanza11573Config is one stanza-owned tunnel ingress zone (untrust on
// gr-0/0/0.0, bound to virtual-router tenant by the tunnel's explicit
// routing-instance stanza instead of an RI interface list) with the same
// source-scoped application-any deny shape as vrf11573Config.
func stanza11573Config() *Config {
	cfg := jhTestConfig()
	cfg.Interfaces.Interfaces["gr-0/0/0"] = &InterfaceConfig{
		Name: "gr-0/0/0",
		Tunnel: &TunnelConfig{
			Name: "gr-0-0-0", Mode: "gre",
			Source: "192.0.2.1", Destination: "192.0.2.2",
			RoutingInstance: "tenant",
		},
		Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.10.10.1/30"}}},
	}
	cfg.Security.Zones["untrust"].Interfaces = []string{"gr-0/0/0.0"}
	cfg.RoutingInstances = []*RoutingInstanceConfig{{
		Name: "tenant", InstanceType: "virtual-router",
	}}
	cfg.Security.Policies = []*ZonePairPolicies{{
		FromZone: "untrust", ToZone: "junos-host",
		Policies: []*Policy{jhDeny("block-tunnel", []string{"bad-net"}, []string{"any"})},
	}}
	return cfg
}

// TestJunosHostStanzaOwnedTunnelDenyScopedByMaster11573 pins the #11310
// overlap: a tunnel with an explicit routing-instance stanza is bound to that
// VRF by the tunnel manager (BindInterfaceToVRF in pkg/routing/tunnel.go), not
// by the RI interface-list walk, so LOCAL_IN reports the stanza VRF master.
// The fine DENY must scope to it; leaving the tunnel raw-scoped would match
// nothing at LOCAL_IN while suppressing the #4168 warning.
func TestJunosHostStanzaOwnedTunnelDenyScopedByMaster11573(t *testing.T) {
	t.Run("stanza-owned tunnel scoped by stanza master", func(t *testing.T) {
		cfg := stanza11573Config()
		cov := junosHostZoneNetdevCoverageMap(cfg)["untrust"]
		if !slices.Equal(cov.Scoped, []string{"vrf-tenant"}) || len(cov.Unscopable) != 0 {
			t.Fatalf("stanza-owned tunnel coverage = %+v, want Scoped=[vrf-tenant] with no gap", cov)
		}
		prog := vrf11573Program(t, cfg, "untrust")
		if !prog.Representable {
			t.Fatalf("stanza-owned tunnel program must be representable: %+v", prog)
		}
		if !slices.Equal(prog.IngressNetdevs, []string{"vrf-tenant"}) {
			t.Fatalf("program scope = %v, want [vrf-tenant] — the iifname set is the mechanism", prog.IngressNetdevs)
		}
		drops := 0
		for _, r := range prog.RulesV4 {
			if r.Verdict == JunosHostDrop && slices.Contains(r.Src, "10.0.0.0/8") {
				drops++
			}
		}
		if drops == 0 {
			t.Fatalf("no emitted v4 DROP covers denied source 10.0.0.0/8: %+v", prog.RulesV4)
		}
		if !vrf11573Verdict(t, prog, "vrf-tenant", "10.1.2.3") {
			t.Fatalf("denied-source packet (iif vrf-tenant, src 10.1.2.3) must DROP")
		}
		if vrf11573Verdict(t, prog, "vrf-tenant", "192.0.2.7") {
			t.Fatalf("permitted-source packet (iif vrf-tenant, src 192.0.2.7) must NOT drop")
		}
		key := JunosHostZonePairPolicyKey("untrust", "block-tunnel")
		if !BuildJunosHostDenyProjection(cfg).RenderedPolicyKeys[key] {
			t.Fatalf("fully-scoped stanza-owned tunnel deny must suppress its #4168 warning")
		}
		if warnings := validateJunosHostDirectDeliveryWarnings(cfg); len(warnings) != 0 {
			t.Fatalf("fully-scoped stanza-owned tunnel deny must not retain a direct-path warning: %v", warnings)
		}
	})
	t.Run("RI list claim in another instance conflicts with stanza claim", func(t *testing.T) {
		cfg := stanza11573Config()
		cfg.RoutingInstances = append(cfg.RoutingInstances, &RoutingInstanceConfig{
			Name: "other", InstanceType: "virtual-router", Interfaces: []string{"gr-0/0/0.0"},
		})
		cov := junosHostZoneNetdevCoverageMap(cfg)["untrust"]
		if len(cov.Scoped) != 0 || len(cov.Unscopable) != 1 ||
			cov.Unscopable[0].Netdev != "gr-0-0-0" ||
			cov.Unscopable[0].Reason != junosHostNetdevVRFEnslaved {
			t.Fatalf("same device claimed by stanza tenant and list other must stay unresolved: %+v", cov)
		}
		key := JunosHostZonePairPolicyKey("untrust", "block-tunnel")
		if BuildJunosHostDenyProjection(cfg).RenderedPolicyKeys[key] {
			t.Fatalf("conflicting-master deny must keep its warning")
		}
	})
}
