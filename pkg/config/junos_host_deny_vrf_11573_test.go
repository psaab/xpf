package config

import (
	"net/netip"
	"slices"
	"testing"
)

// junos_host_deny_vrf_11573_test.go pins #11573: a VRF-member fine DENY uses
// the LOCAL_IN-visible master plus the member's sdifname rather than a broad
// master rule or an unmatchable slave-only iifname rule. Shared masters remain
// enforceable for uniquely-owned members without affecting sibling ingress.

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

func requireSingleVRFScope11573(t *testing.T, scopes []HostInboundVRFIngressScope, master, slave string) {
	t.Helper()
	if len(scopes) != 1 || scopes[0].Master != master || !slices.Equal(scopes[0].Slaves, []string{slave}) {
		t.Fatalf("VRF scopes = %+v, want %s -> [%s]", scopes, master, slave)
	}
}

// vrf11573Verdict hermetically evaluates one v4 packet (LOCAL_IN iifname,
// sdifname, and source) against the program's first-match v4 rules. It mirrors
// the nft rendering: the paired ingress scope gates entry to the zone subchain,
// then rules apply in order.
func vrf11573Verdict(t *testing.T, prog JunosHostDenyProgram, iifname, sdifname, src string) (drop bool) {
	t.Helper()
	scoped := slices.Contains(prog.IngressNetdevs, iifname)
	for _, scope := range prog.IngressVRFScopes {
		if scope.Master == iifname && slices.Contains(scope.Slaves, sdifname) {
			scoped = true
			break
		}
	}
	if !scoped {
		t.Fatalf("packet scope (iifname %q, sdifname %q) not in program scope: direct=%v vrf=%+v",
			iifname, sdifname, prog.IngressNetdevs, prog.IngressVRFScopes)
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

// TestJunosHostVRFMemberDenyScopedBySdifname11573 proves the fine deny's
// master+member scope and the warning is suppressed for complete coverage.
func TestJunosHostVRFMemberDenyScopedBySdifname11573(t *testing.T) {
	cfg := vrf11573Config()
	cov := junosHostZoneNetdevCoverageMap(cfg)["untrust"]
	if len(cov.Scoped) != 0 || len(cov.Unscopable) != 0 {
		t.Fatalf("VRF-member coverage = %+v, want no direct scope or coverage gap", cov)
	}
	const slave = "ge-0-0-1"
	requireSingleVRFScope11573(t, cov.VRFScopes, "vrf-tenant", slave)
	prog := vrf11573Program(t, cfg, "untrust")
	if !prog.Representable {
		t.Fatalf("VRF-member program must be representable: %+v", prog)
	}
	if len(prog.IngressNetdevs) != 0 {
		t.Fatalf("VRF master cannot be a broad direct scope: %v", prog.IngressNetdevs)
	}
	requireSingleVRFScope11573(t, prog.IngressVRFScopes, "vrf-tenant", slave)
	drops := 0
	for _, r := range prog.RulesV4 {
		if r.Verdict == JunosHostDrop && slices.Contains(r.Src, "10.0.0.0/8") {
			drops++
		}
	}
	if drops == 0 {
		t.Fatalf("no emitted v4 DROP covers denied source 10.0.0.0/8: %+v", prog.RulesV4)
	}
	if !vrf11573Verdict(t, prog, "vrf-tenant", "ge-0-0-1", "10.1.2.3") {
		t.Fatalf("denied-source packet (iif vrf-tenant, sdif ge-0-0-1, src 10.1.2.3) must DROP")
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
	if vrf11573Verdict(t, prog, "vrf-tenant", "ge-0-0-1", "192.0.2.7") {
		t.Fatalf("permitted-source packet (iif vrf-tenant, sdif ge-0-0-1, src 192.0.2.7) must NOT drop")
	}
	svc, _, _ := cfg.Security.Zones["untrust"].InterfaceHostInboundEffective("ge-0/0/1.0")
	if !slices.Contains(svc, "ssh") {
		t.Fatalf("member effective services = %v, want ssh admitted so permitted-source control is allowed", svc)
	}
}

// TestJunosHostSharedVRFMasterScopedByMembers11573 pins ownership boundaries:
// each zone scopes only its own member of a shared LOCAL_IN master. Unowned
// co-members likewise remain outside the zoned member scope.
func TestJunosHostSharedVRFMasterScopedByMembers11573(t *testing.T) {
	t.Run("shared master scopes each zone to its own member", func(t *testing.T) {
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
		projection := BuildJunosHostDenyProjection(cfg)
		for zone, slave := range map[string]string{"untrust": "ge-0-0-1", "trust": "ge-0-0-2"} {
			cov := junosHostZoneNetdevCoverageMap(cfg)[zone]
			if len(cov.Scoped) != 0 || len(cov.Unscopable) != 0 {
				t.Fatalf("%s: shared master must use member scope, got %+v", zone, cov)
			}
			requireSingleVRFScope11573(t, cov.VRFScopes, "vrf-tenant", slave)
			key := JunosHostZonePairPolicyKey(zone, "block-vrf")
			if !projection.RenderedPolicyKeys[key] {
				t.Fatalf("%s: exact member scope must suppress its deny warning", zone)
			}
		}
	})
	t.Run("distinct VRFs keep distinct member scopes", func(t *testing.T) {
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
		for zone, want := range map[string]HostInboundVRFIngressScope{
			"untrust": {Master: "vrf-tenant-a", Slaves: []string{"ge-0-0-1"}},
			"trust":   {Master: "vrf-tenant-b", Slaves: []string{"ge-0-0-2"}},
		} {
			cov := junosHostZoneNetdevCoverageMap(cfg)[zone]
			if len(cov.Scoped) != 0 || len(cov.Unscopable) != 0 ||
				len(cov.VRFScopes) != 1 || cov.VRFScopes[0].Master != want.Master ||
				!slices.Equal(cov.VRFScopes[0].Slaves, want.Slaves) {
				t.Fatalf("%s: coverage = %+v, want VRF scope %+v with no gap", zone, cov, want)
			}
		}
	})
	t.Run("unowned VRF co-member remains outside member scope", func(t *testing.T) {
		cfg := vrf11573Config()
		cfg.Interfaces.Interfaces["ge-0/0/2"] = &InterfaceConfig{
			Name: "ge-0/0/2", Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.3.10/24"}}},
		}
		cfg.RoutingInstances[0].Interfaces = append(cfg.RoutingInstances[0].Interfaces, "ge-0/0/2.0")
		cov := junosHostZoneNetdevCoverageMap(cfg)["untrust"]
		if len(cov.Scoped) != 0 || len(cov.Unscopable) != 0 {
			t.Fatalf("unowned VRF member must not make the zone-owned slave unscopable: %+v", cov)
		}
		requireSingleVRFScope11573(t, cov.VRFScopes, "vrf-tenant", "ge-0-0-1")
		key := JunosHostZonePairPolicyKey("untrust", "block-vrf")
		if !BuildJunosHostDenyProjection(cfg).RenderedPolicyKeys[key] {
			t.Fatalf("deny scoped to the owned VRF member must suppress its warning")
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

// TestJunosHostStanzaOwnedTunnelDenyScopedBySdifname11573 pins the #11310
// overlap: a stanza-owned VRF tunnel's deny uses the master/member pair.
func TestJunosHostStanzaOwnedTunnelDenyScopedBySdifname11573(t *testing.T) {
	t.Run("stanza-owned tunnel scoped by stanza master and member", func(t *testing.T) {
		cfg := stanza11573Config()
		cov := junosHostZoneNetdevCoverageMap(cfg)["untrust"]
		if len(cov.Scoped) != 0 || len(cov.Unscopable) != 0 {
			t.Fatalf("stanza-owned tunnel coverage = %+v, want no direct scope or gap", cov)
		}
		const slave = "gr-0-0-0"
		requireSingleVRFScope11573(t, cov.VRFScopes, "vrf-tenant", slave)
		prog := vrf11573Program(t, cfg, "untrust")
		if !prog.Representable {
			t.Fatalf("stanza-owned tunnel program must be representable: %+v", prog)
		}
		if len(prog.IngressNetdevs) != 0 {
			t.Fatalf("VRF tunnel master cannot be a broad direct scope: %v", prog.IngressNetdevs)
		}
		requireSingleVRFScope11573(t, prog.IngressVRFScopes, "vrf-tenant", slave)
		drops := 0
		for _, r := range prog.RulesV4 {
			if r.Verdict == JunosHostDrop && slices.Contains(r.Src, "10.0.0.0/8") {
				drops++
			}
		}
		if drops == 0 {
			t.Fatalf("no emitted v4 DROP covers denied source 10.0.0.0/8: %+v", prog.RulesV4)
		}
		if !vrf11573Verdict(t, prog, "vrf-tenant", slave, "10.1.2.3") {
			t.Fatalf("denied-source packet (iif vrf-tenant, sdif %s, src 10.1.2.3) must DROP", slave)
		}
		if vrf11573Verdict(t, prog, "vrf-tenant", slave, "192.0.2.7") {
			t.Fatalf("permitted-source packet (iif vrf-tenant, sdif %s, src 192.0.2.7) must NOT drop", slave)
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
