package config

import (
	"strings"
	"testing"
)

func hasWarn6460(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// mkDHCPGroups builds a one-group DHCPLocalServerConfig bound to the given
// interfaces.
func mkDHCPGroups(name string, ifaces ...string) *DHCPLocalServerConfig {
	return &DHCPLocalServerConfig{
		Groups: map[string]*DHCPServerGroup{
			name: {Name: name, Interfaces: ifaces},
		},
	}
}

// TestDHCPServerHostInboundBypassWarnings covers the #6460 advisory: a
// dhcp-local-server / dhcpv6-local-server group bound to an interface whose
// zone's effective host-inbound-traffic system-services set omits the matching
// DHCP token warns; supplying the token (or `all`, or `any-service`, or a
// per-interface override) silences it; and there is no false warning for an
// out-of-zone interface or a config with no DHCP server.
func TestDHCPServerHostInboundBypassWarnings(t *testing.T) {
	mkZone := func(iface string, services []string) *ZoneConfig {
		z := &ZoneConfig{Interfaces: []string{iface}}
		if services != nil {
			z.HostInboundTraffic = &HostInboundTraffic{SystemServices: services}
		}
		return z
	}

	// (a) v4 server on an interface whose zone omits `dhcp` → warns, naming the
	// group, the interface, the zone, and the AF_PACKET mechanism.
	cfgA := &Config{}
	cfgA.Security.Zones = map[string]*ZoneConfig{"untrust": mkZone("ge-0/0/1.0", []string{"ssh"})}
	cfgA.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/1.0")
	wA := validateDHCPServerHostInboundBypassWarnings(cfgA)
	if !hasWarn6460(wA, `system services dhcp-local-server group "g1" serves interface "ge-0/0/1.0" (security zone "untrust")`) {
		t.Fatalf("(a) expected v4 bypass warning, got %v", wA)
	}
	if !hasWarn6460(wA, "AF_PACKET raw socket") {
		t.Fatalf("(a) v4 warning must name the AF_PACKET mechanism, got %v", wA)
	}
	// The remedy must lead with removing the interface, NOT with adding the
	// token — adding the token cannot enforce anything on the v4 path, so
	// presenting it as the fix would restate the same false signal.
	if !hasWarn6460(wA, `remove "ge-0/0/1.0" from group "g1"`) {
		t.Fatalf("(a) v4 warning must offer the group-removal remedy, got %v", wA)
	}

	// (b) the token present → silent.
	cfgB := &Config{}
	cfgB.Security.Zones = map[string]*ZoneConfig{"untrust": mkZone("ge-0/0/1.0", []string{"ssh", "dhcp"})}
	cfgB.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/1.0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgB); len(w) != 0 {
		t.Fatalf("(b) expected no warning when the zone admits dhcp, got %v", w)
	}

	// (c) `system-services all` expands to the concrete service union (#3226),
	// which includes dhcp → silent. A naive string compare would warn here.
	cfgC := &Config{}
	cfgC.Security.Zones = map[string]*ZoneConfig{"untrust": mkZone("ge-0/0/1.0", []string{"all"})}
	cfgC.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/1.0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgC); len(w) != 0 {
		t.Fatalf("(c) expected no warning under `system-services all`, got %v", w)
	}

	// (d) `any-service` is the full-admit token — it is not a per-service union,
	// so it must be recognised separately from the `all` expansion.
	cfgD := &Config{}
	cfgD.Security.Zones = map[string]*ZoneConfig{"untrust": mkZone("ge-0/0/1.0", []string{"any-service"})}
	cfgD.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/1.0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgD); len(w) != 0 {
		t.Fatalf("(d) expected no warning under `any-service`, got %v", w)
	}

	// (e) interface in no zone → no host-inbound dimension → no warning.
	cfgE := &Config{}
	cfgE.Security.Zones = map[string]*ZoneConfig{"untrust": mkZone("ge-0/0/1.0", []string{"ssh"})}
	cfgE.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/9.0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgE); len(w) != 0 {
		t.Fatalf("(e) expected no warning for an out-of-zone interface, got %v", w)
	}

	// (f) no DHCP server configured at all → silent.
	cfgF := &Config{}
	cfgF.Security.Zones = map[string]*ZoneConfig{"untrust": mkZone("ge-0/0/1.0", []string{"ssh"})}
	if w := validateDHCPServerHostInboundBypassWarnings(cfgF); len(w) != 0 {
		t.Fatalf("(f) expected no warning with no DHCP server, got %v", w)
	}

	// (g) the v6 family uses the `dhcpv6` token and the MULTICAST mechanism, not
	// AF_PACKET — a shared message would misdescribe one of the two families and
	// send the operator after the wrong remedy.
	cfgG := &Config{}
	cfgG.Security.Zones = map[string]*ZoneConfig{"untrust": mkZone("ge-0/0/1.0", []string{"dhcp"})}
	cfgG.System.DHCPServer.DHCPv6LocalServer = mkDHCPGroups("g6", "ge-0/0/1.0")
	wG := validateDHCPServerHostInboundBypassWarnings(cfgG)
	if !hasWarn6460(wG, `system services dhcpv6-local-server group "g6"`) {
		t.Fatalf("(g) expected v6 bypass warning (the v4 token does not admit dhcpv6), got %v", wG)
	}
	if !hasWarn6460(wG, "ff02::1:2 multicast group") {
		t.Fatalf("(g) v6 warning must name the multicast mechanism, got %v", wG)
	}
	if hasWarn6460(wG, "AF_PACKET") {
		t.Fatalf("(g) v6 warning must NOT claim the AF_PACKET mechanism, got %v", wG)
	}

	// (h) BARE zone member claims configured units: the zone lists physical
	// `reth0`, the group binds unit `reth0.80` — in-zone at runtime via the
	// zoneIfaceLogicalKeys bare-member expansion, so a missing token must warn.
	// An exact-string zone map would miss this entirely.
	cfgH := &Config{}
	cfgH.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*InterfaceUnit{80: {}}},
	}
	cfgH.Security.Zones = map[string]*ZoneConfig{"untrust": {Interfaces: []string{"reth0"}}}
	cfgH.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "reth0.80")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgH); !hasWarn6460(w, `serves interface "reth0.80" (security zone "untrust")`) {
		t.Fatalf("(h) expected warning for a unit under a bare zone member, got %v", w)
	}

	// (i) PHYSICAL-PARENT override inheritance (#3720): a per-interface override
	// on the parent `reth0` admitting dhcp covers unit `reth0.80` — no FALSE
	// warning. An exact InterfaceHostInbound["reth0.80"] lookup would miss it.
	cfgI := &Config{}
	cfgI.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*InterfaceUnit{80: {}}},
	}
	zi := &ZoneConfig{Interfaces: []string{"reth0"}}
	zi.InterfaceHostInbound = map[string]*HostInboundTraffic{"reth0": {SystemServices: []string{"dhcp"}}}
	cfgI.Security.Zones = map[string]*ZoneConfig{"untrust": zi}
	cfgI.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "reth0.80")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgI); len(w) != 0 {
		t.Fatalf("(i) expected no warning: parent override admits dhcp, got %v", w)
	}

	// (j) A per-interface override REPLACES the zone-level set (#6515): the zone
	// admits dhcp but the interface override does not, so the effective set for
	// that interface omits it and the advisory must fire. Reading the zone-level
	// set instead of InterfaceHostInboundEffective would silently pass.
	cfgJ := &Config{}
	zj := &ZoneConfig{Interfaces: []string{"ge-0/0/1.0"}}
	zj.HostInboundTraffic = &HostInboundTraffic{SystemServices: []string{"dhcp"}}
	zj.InterfaceHostInbound = map[string]*HostInboundTraffic{"ge-0/0/1.0": {SystemServices: []string{"ssh"}}}
	cfgJ.Security.Zones = map[string]*ZoneConfig{"untrust": zj}
	cfgJ.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/1.0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgJ); !hasWarn6460(w, `serves interface "ge-0/0/1.0" (security zone "untrust")`) {
		t.Fatalf("(j) expected warning: the interface override replaces the zone set and omits dhcp, got %v", w)
	}

	// (k) REGISTRATION PIN: the advisory must be wired into ValidateConfig, not
	// merely callable in isolation — deleting the append registration line in
	// compiler_validate_warn.go must make a real commit-warn assertion go red
	// (none of the direct-helper cases above would catch that).
	if w := ValidateConfig(cfgA); !hasWarn6460(w, `system services dhcp-local-server group "g1" serves interface "ge-0/0/1.0" (security zone "untrust")`) {
		t.Fatalf("(k) ValidateConfig must surface the #6460 advisory (registration), got %v", w)
	}
}

func TestDHCPServerHostInboundBypassWarningsCanonicalUnitRef12843(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{1: {Number: 1}}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"untrust": {Interfaces: []string{"ge-0/0/1.1"}, HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	cfg.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/1.01")

	if w := validateDHCPServerHostInboundBypassWarnings(cfg); !hasWarn6460(w, `serves interface "ge-0/0/1.01" (security zone "untrust")`) {
		t.Fatalf("padded DHCP unit alias must resolve to the configured zone and warn, got %v", w)
	}
	// Keep effective-policy lookup on the authored ref so an override keyed by
	// the same spelling still applies for hand-built configs without compile stamps.
	cfg.Security.Zones["untrust"].InterfaceHostInbound = map[string]*HostInboundTraffic{
		"ge-0/0/1.01": {SystemServices: []string{"dhcp"}},
	}
	if w := validateDHCPServerHostInboundBypassWarnings(cfg); len(w) != 0 {
		t.Fatalf("padded group ref's exact interface override must still admit dhcp, got %v", w)
	}
}

func TestDHCPServerHostInboundBypassWarningsConfigScopedZoneQuarantine12843(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{1: {Number: 1}}},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"z214": {Interfaces: []string{"ge-0/0/1.1"}, HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	// This collision exists only in the recorded node/group runtime view, not
	// among the effective zone keys in Security.Zones.
	cfg.ZoneQuarantineNames = []string{"z174", "z214"}
	cfg.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/1.1")

	if w := validateDHCPServerHostInboundBypassWarnings(cfg); len(w) != 0 {
		t.Fatalf("runtime-quarantined zone must not be attributed by advisory, got %v", w)
	}
}
func TestDHCPServerHostInboundBypassWarningsBareRef13143(t *testing.T) {
	// (A) Bare group ref vs unit-qualified zone member: zone lists
	// ge-0/0/0.0 omitting dhcp, group binds bare ge-0/0/0 (which binds
	// unit 0). The advisory must fire.
	cfgA := &Config{}
	cfgA.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	zA := &ZoneConfig{Interfaces: []string{"ge-0/0/0.0"}, HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}}
	cfgA.Security.Zones = map[string]*ZoneConfig{"trust": zA}
	cfgA.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgA); !hasWarn6460(w, `serves interface "ge-0/0/0" (security zone "trust")`) {
		t.Fatalf("(A) bare group ref against unit-qualified zone member must warn, got %v", w)
	}

	// (B) Bare group and zone member, but unit 0 override admits dhcp:
	// the effective unit-0 set admits dhcp, so no warning.
	cfgB := &Config{}
	cfgB.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	zB := &ZoneConfig{Interfaces: []string{"ge-0/0/0", "ge-0/0/0.0"}, HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}}
	zB.InterfaceHostInbound = map[string]*HostInboundTraffic{"ge-0/0/0.0": {SystemServices: []string{"ssh", "dhcp"}}}
	cfgB.Security.Zones = map[string]*ZoneConfig{"trust": zB}
	cfgB.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgB); len(w) != 0 {
		t.Fatalf("(B) unit 0 override admitting dhcp must not warn for bare ref, got %v", w)
	}

	// (B2) Control: same as (B) but unit 0 override omits dhcp -> warn.
	cfgB2 := &Config{}
	cfgB2.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	zB2 := &ZoneConfig{Interfaces: []string{"ge-0/0/0", "ge-0/0/0.0"}, HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}}
	zB2.InterfaceHostInbound = map[string]*HostInboundTraffic{"ge-0/0/0.0": {SystemServices: []string{"ssh"}}}
	cfgB2.Security.Zones = map[string]*ZoneConfig{"trust": zB2}
	cfgB2.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgB2); len(w) == 0 {
		t.Fatalf("(B2) unit 0 override omitting dhcp must warn for bare ref")
	}

	// (C) Lifeline: fxp0 is always a lifeline; a DHCP group on fxp0 in a
	// zone omitting dhcp must not warn (lifelines are NEVER denied).
	cfgC := &Config{}
	cfgC.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"fxp0": {Name: "fxp0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	zC := &ZoneConfig{Interfaces: []string{"fxp0.0"}, HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}}
	cfgC.Security.Zones = map[string]*ZoneConfig{"mgmt": zC}
	cfgC.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "fxp0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgC); len(w) != 0 {
		t.Fatalf("(C) lifeline fxp0 must not warn, got %v", w)
	}

	// (D) Negative: bare ref whose unit 0 is in no zone must not warn and
	// must not be attributed to a sibling unit's zone.
	cfgD := &Config{}
	cfgD.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
	}
	zD := &ZoneConfig{Interfaces: []string{"ge-0/0/0.1"}, HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}}}
	cfgD.Security.Zones = map[string]*ZoneConfig{"trust": zD}
	cfgD.System.DHCPServer.DHCPLocalServer = mkDHCPGroups("g1", "ge-0/0/0")
	if w := validateDHCPServerHostInboundBypassWarnings(cfgD); len(w) != 0 {
		t.Fatalf("(D) bare ref binding only unzoned unit 0 must not warn via sibling unit 1, got %v", w)
	}
}
