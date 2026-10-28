package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17086 parity census: every daemon consumer of "which RG owns
// interface ref X" must agree with config.InterfaceRefRG on one
// config. The source probe (TestQ33RGResolverCensus) measured three
// different answers (SSOT 2, raw-field 0, RPM name-test 1) for the
// member ref ge-0/0/1.0 on this shape:
//
//	reth0 RG1 (member ge-0/0/2) · bond0 RG2 (member ge-0/0/1) ·
//	ge-0/0/5 stray RG1 on a plain interface · reth9 RG0
//
// FAIL-ON-REVERT: restoring any hand-rolled resolver (first-dot split
// + raw RedundancyGroup, or the RPM `reth*` name test) turns the
// bond0/member/stray cells below red against the SSOT.
func rgParity17086Config(t *testing.T) *config.Config {
	t.Helper()
	mk := func(name string, rg int, parent string) *config.InterfaceConfig {
		return &config.InterfaceConfig{Name: name, RedundancyGroup: rg, RedundantParent: parent}
	}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0":    mk("reth0", 1, ""),
		"bond0":    mk("bond0", 2, ""),
		"ge-0/0/1": mk("ge-0/0/1", 0, "bond0"),
		"ge-0/0/2": mk("ge-0/0/2", 0, "reth0"),
		"ge-0/0/5": mk("ge-0/0/5", 1, ""), // stray RG, plain interface
		"reth9":    mk("reth9", 0, ""),
		"lo0":      mk("lo0", 0, ""),
	}
	// Units carrying the addresses the RPM VIP map and DDNS scopes key on.
	cfg.Interfaces.Interfaces["bond0"].Units = map[int]*config.InterfaceUnit{
		50: {Number: 50, Addresses: []string{"10.0.50.1/24"}},
		// #17049 merge: the RA stable-source cells below need a stable-LL
		// placement on the RETH itself — an IPv6-bearing unit with no
		// configured link-local. Unit 0 carries only a global IPv6
		// address, so StableRethLinkLocalPlacements(2) installs the
		// stable address there and the member RA may bind it.
		0: {Number: 0, Addresses: []string{"2001:db8:b0::1/64"}},
	}
	cfg.Interfaces.Interfaces["reth0"].Units = map[int]*config.InterfaceUnit{
		0: {Number: 0, Addresses: []string{"10.0.0.1/24", "2001:db8:10::1/64"}},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:        1,
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0}, {ID: 1}, {ID: 2}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0/0/1.0"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth0.0"}},
		"stray":   {Name: "stray", Interfaces: []string{"ge-0/0/5.0"}},
	}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"P": {Name: "P", Tests: map[string]*config.RPMTest{
			"bond-iface":   {Name: "bond-iface", Target: "1.1.1.1", DestinationInterface: "bond0.50"},
			"member-iface": {Name: "member-iface", Target: "2.2.2.2", DestinationInterface: "ge-0/0/1.0"},
			"bond-src":     {Name: "bond-src", Target: "3.3.3.3", SourceAddress: "10.0.50.1"},
			"stray-iface":  {Name: "stray-iface", Target: "4.4.4.4", DestinationInterface: "ge-0/0/5.0"},
		}},
	}}
	cfg.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan": {Name: "wan", MatchRPMProbe: "P"},
	}}
	return cfg
}

// TestRGResolverParity17086 is the census rewritten as a parity test:
// for every ref in the matrix, every consumer that answers the ref→RG
// question must return RefRG's answer (the positive-group form).
func TestRGResolverParity17086(t *testing.T) {
	cfg := rgParity17086Config(t)
	owners := cfg.RethRGOwners()
	refs := []string{
		"reth0.0", "reth0", "bond0.50", "bond0",
		"ge-0/0/1.0", "ge-0/0/1", "ge-0/0/2", "ge-0/0/5", "ge-0/0/5.0",
		"reth9.0", "lo0", "nonexistent.0",
	}
	for _, ref := range refs {
		want := cfg.RefRG(ref)
		consumers := map[string]int{
			"proxyARPRedundancyGroupFor": proxyARPRedundancyGroupFor(cfg, ref),
			"relayInterfaceRG":           relayInterfaceRG(cfg, ref),
			"rgForInterfaces":            rgForInterfaces(cfg, []string{ref}),
		}
		if rg, ok := dhcpLeaseRGForInterface(cfg, ref, owners); ok {
			consumers["dhcpLeaseRGForInterface"] = rg
		} else {
			consumers["dhcpLeaseRGForInterface"] = 0
		}
		for name, got := range consumers {
			if got != want {
				t.Errorf("ref %q: %s = %d, SSOT RefRG = %d — consumers diverged (#17086)",
					ref, name, got, want)
			}
		}
	}

	// IPsec: a VPN whose gateway external-interface is the member ref.
	vpnCfg := rgParity17086Config(t)
	vpnCfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{
		"gw": {Name: "gw", ExternalIface: "ge-0/0/1.0"},
	}
	vpn := &config.IPsecVPN{Name: "v", Gateway: "gw"}
	if got, want := ipsecVPNRedundancyGroup(vpnCfg, vpn), cfg.RefRG("ge-0/0/1.0"); got != want {
		t.Errorf("ipsecVPNRedundancyGroup(member external) = %d, SSOT = %d", got, want)
	}

	// Zone map: the member's zone carries bond0's RG; the stray
	// interface's zone carries nothing.
	zoneRG := buildZoneRGMap(cfg, map[string]uint32{"trust": 2, "untrust": 3, "stray": 4})
	if got := zoneRG[2]; !reflect.DeepEqual(got, []int{2}) {
		t.Errorf("buildZoneRGMap[trust via ge-0/0/1.0] = %v, want [2] (bond0's RG via the member)", got)
	}
	if got := zoneRG[3]; !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("buildZoneRGMap[untrust via reth0.0] = %v, want [1]", got)
	}
	if got, ok := zoneRG[4]; ok {
		t.Errorf("buildZoneRGMap[stray via ge-0/0/5.0] = %v, want absent — a stray group owns nothing", got)
	}

	// RPM gating: bond0's tests gate on RG2 (the name test gated them
	// on the lowest data RG, 1); the stray interface's test is not
	// RETH-bound, so as an ip-monitoring-referenced test it falls back
	// to the lowest data RG.
	gating := rpmProbeTestGating(cfg)
	for key, want := range map[probeTestKey]int{
		{"P", "bond-iface"}:   2,
		{"P", "member-iface"}: 2,
		{"P", "bond-src"}:     2,
		{"P", "stray-iface"}:  1, // unbound → lowest data RG fallback
	} {
		if got := gating[key]; got != want {
			t.Errorf("rpmProbeTestGating[%v] = %d, want %d", key, got, want)
		}
	}

	// userspaceRGConfigured: RG2 is configured via bond0; a group only
	// a stray interface carries is NOT configured. RG1 is carried by
	// both reth0 and the stray — the stray must not be what configures
	// it, so use a stray-only variant.
	if !userspaceRGConfigured(userspaceParityCfg(cfg, 2), 2) {
		t.Error("userspaceRGConfigured(RG2 via bond0) = false, want true")
	}
	strayOnly := rgParity17086Config(t)
	delete(strayOnly.Interfaces.Interfaces, "reth0")
	delete(strayOnly.Interfaces.Interfaces, "ge-0/0/2")
	if userspaceRGConfigured(userspaceParityCfg(strayOnly, 1), 1) {
		t.Error("userspaceRGConfigured(RG1 via stray ge-0/0/5 only) = true, want false — stray owns nothing")
	}
}

// userspaceParityCfg marks cfg as a userspace-dataplane config for
// userspaceRGConfigured's type gate. rgID is unused; it keeps the two
// call sites visually paired with the group they assert on.
func userspaceParityCfg(cfg *config.Config, _ int) *config.Config {
	cfg.System.DataplaneType = "userspace"
	return cfg
}

// TestSurfaceARGScopeOwnerParity17086: a DDNS binding on the member
// interface is owned by the RETH's group; on the stray interface, by
// nothing (0).
func TestSurfaceARGScopeOwnerParity17086(t *testing.T) {
	cfg := rgParity17086Config(t)
	for ref, want := range map[string]int{
		"bond0":    2,
		"ge-0/0/1": 2, // member binding owned by bond0's RG (raw field: 0)
		"reth0":    1,
		"ge-0/0/5": 0, // stray (raw field: 1)
		"lo0":      0,
	} {
		if got := surfaceARGScopeOwner(cfg, ref); got != want {
			t.Errorf("surfaceARGScopeOwner(%q) = %d, want %d (SSOT)", ref, got, want)
		}
	}
	// The scope built from a member binding carries the RETH's RG.
	d := &Daemon{}
	bind := &config.InterfaceDynamicDNSConfig{Hostname: "m.example.net", Provider: "p"}
	cfg.System.Services = &config.SystemServicesConfig{DynamicDNS: &config.DDNSServicesConfig{
		Providers: map[string]*config.DDNSProvider{"p": {Name: "p", Backend: "rfc2136", RFC2136Endpoint: config.RFC2136Endpoint{UpdateServer: "192.0.2.53"}}},
	}}
	cfg.Interfaces.Interfaces["ge-0/0/1"].Units = map[int]*config.InterfaceUnit{
		0: {Number: 0, DynamicDNSInet: bind},
	}
	scopes, _ := d.buildSurfaceAScopes(cfg)
	found := false
	for _, s := range scopes {
		if s.Key.Interface == "ge-0/0/1" {
			found = true
			if s.Key.RGOwner != 2 {
				t.Errorf("member scope RGOwner = %d, want 2 (bond0)", s.Key.RGOwner)
			}
		}
	}
	if !found {
		t.Fatal("no scope built for the member binding")
	}
}

// TestRAStableLinkLocalParity17086: an RA on the member interface
// binds its RETH's stable link-local (the raw-field reader bound
// nothing — the member's own group is 0); an RA on the stray
// interface binds nothing (the raw-field reader bound RG1's stable
// address on a plain interface).
func TestRAStableLinkLocalParity17086(t *testing.T) {
	cfg := rgParity17086Config(t)
	// RA refs name the member / owner interfaces BARE: the bare member
	// resolves (via ResolveKernelIfName) to the member's bare kernel
	// device, which is exactly where the owner's unit-0 placement
	// installs the stable LL. (A unit-qualified member ref such as
	// ge-0/0/1.50 would name bond0's unit 50 — IPv4-only in this
	// fixture, hence no placement and correctly no stable bind.)
	cfg.Protocols.RouterAdvertisement = []*config.RAInterfaceConfig{
		{Interface: "ge-0/0/1"},
		{Interface: "ge-0/0/5"},
		{Interface: "reth0"},
	}
	d := &Daemon{}
	ras := d.buildRAConfigs(cfg)
	// buildRAConfigs resolves ra.Interface to the kernel name before
	// returning (member ge-0/0/1 → ge-0-0-1; reth0 → its member
	// ge-0-0-2), so index by the resolved names.
	byIface := map[string]string{}
	for _, ra := range ras {
		byIface[ra.Interface] = ra.SourceLinkLocal
	}
	if byIface["ge-0-0-1"] == "" {
		t.Error("RA on member ge-0/0/1 bound no stable link-local, want bond0 RG2's")
	}
	if byIface["ge-0-0-5"] != "" {
		t.Errorf("RA on stray ge-0/0/5 bound %q, want empty — stray owns nothing", byIface["ge-0-0-5"])
	}
	if byIface["ge-0-0-2"] == "" {
		t.Error("RA on reth0 (member ge-0-0-2) bound no stable link-local, want RG1's")
	}
	if byIface["ge-0-0-1"] != "" && byIface["ge-0-0-1"] == byIface["ge-0-0-2"] {
		t.Error("member (RG2) and reth0 (RG1) bound the same stable link-local — wrong RG")
	}
}
