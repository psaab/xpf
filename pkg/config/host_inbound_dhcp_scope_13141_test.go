package config

import (
	"strings"
	"testing"
)

// #13141 (D2-10): zone-level dhcp/bootp withholding and the #6519/#7490
// advisory must agree per unit, and a DHCPv6-only server must not withhold
// the IPv4 dhcp/bootp tokens.

func TestDHCPScopeBareZoneMemberUnitParity13141(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 vlan-id 10",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 50 vlan-id 50",
		"set interfaces ge-0/0/0 unit 50 family inet dhcp",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set security zones security-zone trust host-inbound-traffic system-services dhcpv6",
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set system services dhcp-local-server group g4 interface ge-0/0/0.0",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil {
		t.Fatal("trust zone missing")
	}
	if !z.WithholdsZoneLevelDHCPFor("ge-0/0/0.0") {
		t.Fatal("fixture: unit 0 runs the DHCP server and has no client unit under it; it must be withheld")
	}
	if z.WithholdsZoneLevelDHCPFor("ge-0/0/0.50") {
		t.Error("unit 50 runs only the firewall client (and no server); zone dhcp must be retained there")
	}
	// The bare zone member must not produce a single retained entry that
	// claims ge-0/0/0 is retained while unit 0 is withheld. The advisory
	// must expand to units (or otherwise name withheld unit 0).
	warns := validateHostInboundZoneLevelDHCPWarnings(cfg)
	if len(warns) != 1 {
		t.Fatalf("want one advisory, got %d: %v", len(warns), warns)
	}
	w := warns[0]
	if strings.Contains(w, "still authorizes DHCP/BOOTP on ge-0/0/0 (DHCP server and client)") {
		t.Errorf("advisory falsely reports bare ge-0/0/0 as retained (server and client) while ge-0/0/0.0 is withheld: %s", w)
	}
	if !strings.Contains(w, "NO LONGER authorizes DHCP/BOOTP on ge-0/0/0.0 (DHCP server)") {
		t.Errorf("advisory must name ge-0/0/0.0 as withheld: %s", w)
	}
	if !strings.Contains(w, "still authorizes DHCP/BOOTP on ge-0/0/0.50 (DHCP client)") {
		t.Errorf("advisory must name ge-0/0/0.50 as retained client: %s", w)
	}
}

func TestDHCPv6ServerDoesNotWithholdIPv4DHCP13141(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8:1::1/64",
		"set security zones security-zone v6only host-inbound-traffic system-services dhcp",
		"set security zones security-zone v6only host-inbound-traffic system-services dhcpv6",
		"set security zones security-zone v6only interfaces ge-0/0/1.0",
		"set system services dhcpv6-local-server group g6 interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["v6only"]
	if z == nil {
		t.Fatal("v6only zone missing")
	}
	if z.WithholdsZoneLevelDHCPFor("ge-0/0/1.0") {
		t.Error("dhcpv6-local-server alone must not withhold IPv4 dhcp/bootp (#7490 withholds only dhcp/bootp for v4 server/relay)")
	}
	if svc, _, _ := z.InterfaceHostInboundEffective("ge-0/0/1.0"); !hasTok(svc, "dhcp") {
		t.Errorf("IPv4 dhcp must remain effective on v6-only server interface: %v", svc)
	}
	roles := hostInboundDHCPRolesFor(cfg, hostInboundDHCPServerRefs(cfg), "ge-0/0/1.0")
	if roles.server {
		t.Errorf("dhcpv6-local-server must not classify as the IPv4 dhcp server role: %+v", roles)
	}
}

func TestBareDHCPServerRefMatchesOnlyUnitZero13141(t *testing.T) {
	// A bare dhcp-local-server ref means unit 0, not every sibling unit.
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/2 unit 50 vlan-id 50",
		"set interfaces ge-0/0/2 unit 50 family inet address 10.0.52.1/24",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set security zones security-zone trust interfaces ge-0/0/2",
		"set system services dhcp-local-server group g interface ge-0/0/2",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if !z.WithholdsZoneLevelDHCPFor("ge-0/0/2.0") {
		t.Error("bare server ref must withhold on unit 0")
	}
	if z.WithholdsZoneLevelDHCPFor("ge-0/0/2.50") {
		t.Error("bare server ref must not withhold on sibling unit 50")
	}
	for _, tc := range []struct {
		ref        string
		wantServer bool
	}{
		{ref: "ge-0/0/2.0", wantServer: true},
		{ref: "ge-0/0/2.50", wantServer: false},
	} {
		roles := hostInboundDHCPRolesFor(cfg, hostInboundDHCPServerRefs(cfg), tc.ref)
		if roles.server != tc.wantServer {
			t.Errorf("server role for %s = %v, want %v", tc.ref, roles.server, tc.wantServer)
		}
	}
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"ge-0/0/2", "ge-0/0/2.0", true},
		{"ge-0/0/2", "ge-0/0/2.50", false},
	} {
		if got := hostInboundSameInterface(cfg, tc.a, tc.b); got != tc.want {
			t.Errorf("hostInboundSameInterface(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
	// A dotted declared physical name remains a parent interface, preserving
	// the declared-aware #9821 interpretation.
	dotted := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
	}}}
	if !hostInboundSameInterface(dotted, "p.0", "p.0.0") {
		t.Error("declared dotted bare ref must match its unit 0")
	}
	if !hostInboundSameInterface(dotted, "p.0", "p.0.1") {
		t.Error("declared dotted bare interface must remain a parent of unit 1")
	}
	if !hostInboundSameInterface(nil, "reth1", "reth1.0") {
		t.Error("nil-config bare/unit-0 equivalence must be preserved")
	}
	if hostInboundSameInterface(nil, "reth1", "reth1.50") {
		t.Error("nil-config bare refs must not match sibling unit 50")
	}
}

func TestDHCPScopeWarningExcludesQuarantinedZonesAndInterfaces13141(t *testing.T) {
	newZone := func(name, iface string) *ZoneConfig {
		return &ZoneConfig{
			Name:               name,
			Interfaces:         []string{iface},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"dhcp"}},
		}
	}
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
			"ge-0/0/4": {Name: "ge-0/0/4", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"junos-global": newZone("junos-global", "ge-0/0/3.0"),
			"trust":        newZone("trust", "ge-0/0/4.0"),
			"untrust":      newZone("untrust", "ge-0/0/4.0"),
		}},
	}
	warnings := validateHostInboundZoneLevelDHCPWarnings(cfg)
	if len(warnings) != 0 {
		t.Errorf("reserved and duplicate-bound quarantined zones/interfaces must not produce DHCP advisories: %v", warnings)
	}
}
