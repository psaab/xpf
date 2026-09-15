package config

import (
	"strings"
	"testing"
)

// #6519 stage 1.5 — the advisory names WHY the zone-level token is load-bearing
// on each interface it reaches.
//
// The role is not decoration. The deferred enforcement flip turns on exactly
// this discriminator: a DHCP SERVER interface is the case the vendor sentence
// covers ("the server must know the incoming interface"), so migrating it
// matches Junos; the firewall's OWN client is a case that sentence does not
// reach, and there the token is holding up the interface's address; and an
// interface running neither is pure over-admission that can be removed today at
// no risk. Stage 1 reported all three identically, so an operator could not tell
// which one they were in, and neither could the release decision.

func roleZone(t *testing.T, cfg *Config) string {
	t.Helper()
	got := validateHostInboundZoneLevelDHCPWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly one advisory, got %d: %v", len(got), got)
	}
	return got[0]
}

// baseRoleCfg is a zone whose ZONE-level stanza admits dhcp, with one member.
func baseRoleCfg(ref string) *Config {
	cfg := &Config{}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{ref},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ping", "dhcp"}},
		},
	}
	return cfg
}

// TestAdvisoryNamesTheDHCPServerRole6519 — an interface in a dhcp-local-server
// group is the vendor-covered case.
func TestAdvisoryNamesTheDHCPServerRole6519(t *testing.T) {
	cfg := baseRoleCfg("reth1")
	cfg.System.DHCPServer.DHCPLocalServer = &DHCPLocalServerConfig{
		Groups: map[string]*DHCPServerGroup{
			"lan": {Name: "lan", Interfaces: []string{"reth1.0"}},
		},
	}
	msg := roleZone(t, cfg)
	if !strings.Contains(msg, "reth1 (DHCP server)") {
		t.Fatalf("a dhcp-local-server member must be labelled a DHCP server — that is the case "+
			"the vendor sentence covers, so migrating it matches Junos: %s", msg)
	}
	if strings.Contains(msg, "no DHCP configured") || strings.Contains(msg, "DHCP client") {
		t.Fatalf("a server-only interface must not draw the client or idle clause: %s", msg)
	}
}

// TestAdvisoryNamesTheDHCPRelayRole6519 — a relay receives client DISCOVER on
// udp/67 for the same reason a server does, so it is the same role.
func TestAdvisoryNamesTheDHCPRelayRole6519(t *testing.T) {
	cfg := baseRoleCfg("ge-0/0/5.0")
	cfg.ForwardingOptions.DHCPRelay = &DHCPRelayConfig{
		Groups: map[string]*DHCPRelayGroup{
			"r": {Name: "r", Interfaces: []string{"ge-0/0/5.0"}},
		},
	}
	if msg := roleZone(t, cfg); !strings.Contains(msg, "ge-0/0/5.0 (DHCP server)") {
		t.Fatalf("a dhcp-relay member also receives client DISCOVER on the incoming interface "+
			"and must classify as the server role: %s", msg)
	}
}

// TestAdvisoryNamesTheDHCPClientRoleAndItsStakes6519 is the cell that matters
// most: the firewall's OWN client is the case the vendor rationale does NOT
// reach, and the message must say the token is holding up an ADDRESS.
func TestAdvisoryNamesTheDHCPClientRoleAndItsStakes6519(t *testing.T) {
	cfg := baseRoleCfg("ge-0/0/3.0")
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*InterfaceUnit{0: {Number: 0, DHCP: true}}},
	}
	msg := roleZone(t, cfg)
	if !strings.Contains(msg, "ge-0/0/3.0 (DHCP client)") {
		t.Fatalf("an interface running `family inet { dhcp; }` must be labelled a DHCP client: %s", msg)
	}
	if !strings.Contains(msg, "ADDRESS") {
		t.Fatalf("the client clause must say the token holds up the interface's ADDRESS, not "+
			"merely a service — that asymmetry is the whole reason the enforcement flip is "+
			"deferred rather than taken: %s", msg)
	}
	if !strings.Contains(msg, "does not speak to the client") {
		t.Fatalf("the client clause must say the vendor rule does not reach this case: %s", msg)
	}
}

// TestAdvisoryNamesAnIdleInterfaceAsSafeToNarrow6519 — the operationally most
// useful of the three, and the only one actionable at zero risk today.
func TestAdvisoryNamesAnIdleInterfaceAsSafeToNarrow6519(t *testing.T) {
	msg := roleZone(t, baseRoleCfg("ge-0/0/9.0"))
	if !strings.Contains(msg, "ge-0/0/9.0 (no DHCP configured)") {
		t.Fatalf("an interface running neither a server/relay nor the client must be labelled "+
			"as such: %s", msg)
	}
	if !strings.Contains(msg, "removing it narrows nothing in use") {
		t.Fatalf("the idle clause must tell the operator this one is safe to remove today: %s", msg)
	}
	if strings.Contains(msg, "ADDRESS") {
		t.Fatalf("an idle interface must NOT draw the client clause: %s", msg)
	}
}

// TestAdvisoryRemedyAccountsForReplaceSemantics6519 pins the interaction with
// #6515. Following the stage-1 remedy verbatim moves the token to the interface
// — which, under replace semantics, DROPS every other service the zone admitted
// there. The operator learned that only from the sibling #6515 warning on a
// LATER commit, after the narrowing had already been authored.
func TestAdvisoryRemedyAccountsForReplaceSemantics6519(t *testing.T) {
	msg := roleZone(t, baseRoleCfg("ge-0/0/9.0"))
	if !strings.Contains(msg, "REPLACES") || !strings.Contains(msg, "#6515") {
		t.Fatalf("the remedy must warn that a per-interface stanza replaces the zone stanza, "+
			"or following it silently drops the zone's other tokens on that interface: %s", msg)
	}

	// And the narrowing it warns about is real, through the production resolver.
	before := baseRoleCfg("ge-0/0/9.0")
	beforeSvc, _, _ := before.Security.Zones["trust"].InterfaceHostInboundEffective("ge-0/0/9.0")
	after := baseRoleCfg("ge-0/0/9.0")
	after.Security.Zones["trust"].HostInboundTraffic = &HostInboundTraffic{SystemServices: []string{"ping"}}
	after.Security.Zones["trust"].InterfaceHostInbound = map[string]*HostInboundTraffic{
		"ge-0/0/9.0": {SystemServices: []string{"dhcp"}},
	}
	afterSvc, _, _ := after.Security.Zones["trust"].InterfaceHostInboundEffective("ge-0/0/9.0")
	if !hostInboundSetAdmitsService(beforeSvc, "ping") {
		t.Fatalf("precondition: the zone must admit ping before the remedy, got %v", beforeSvc)
	}
	if hostInboundSetAdmitsService(afterSvc, "ping") {
		t.Fatalf("precondition failed: following the remedy was expected to drop ping under "+
			"#6515 replace semantics, but it survived (%v) — if replace semantics changed, "+
			"this advisory's caveat needs revisiting, not deleting", afterSvc)
	}
}

// TestSameInterfaceDoesNotCollapseSiblingUnits6519 pins the matcher boundary. A
// bare physical ref and a unit under it are the same interface (#3720), but two
// DIFFERENT units are not — basing both sides on the physical would let a
// sibling unit's DHCP role leak onto an interface that has none.
func TestSameInterfaceDoesNotCollapseSiblingUnits6519(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"reth1", "reth1", true},
		{"reth1", "reth1.0", true},
		{"reth1.0", "reth1", true},
		{"reth1.0", "reth1.0", true},
		{"reth1.0", "reth1.50", false},
		{"reth1.0", "reth2.0", false},
		{"reth1", "reth2", false},
	} {
		// Nil config pins the legacy first-dot comparison, byte-identical.
		if got := hostInboundSameInterface(nil, tc.a, tc.b); got != tc.want {
			t.Errorf("hostInboundSameInterface(nil,%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
		}
	}
	// Declared-aware path (#9821): same dot-free answers through the split,
	// plus canonical-alias positives and both-declared independence that the
	// first-dot comparison cannot express.
	dottedCfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"reth1": {Name: "reth1", Units: map[int]*InterfaceUnit{0: {Number: 0}, 50: {Number: 50}}},
		"reth2": {Name: "reth2", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"p":     {Name: "p"},
		"p.0":   {Name: "p.0", Units: map[int]*InterfaceUnit{1: {Number: 1}}},
		"p.0.2": {Name: "p.0.2"},
	}}}
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"reth1", "reth1.0", true},
		{"reth1.0", "reth1.50", false},
		{"reth1.0", "reth2.0", false},
		{"p.0", "p.0.1", true},
		{"p.0.01", "p.0.1", true},
		{"p.0.1", "p.0.2", false},
		{"p.0", "p.0.2", false},
		{"p.0", "p", false},
		{"p.0.1", "p.2", false},
	} {
		if got := hostInboundSameInterface(dottedCfg, tc.a, tc.b); got != tc.want {
			t.Errorf("hostInboundSameInterface(cfg,%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
		}
		// Symmetric: argument order must not matter.
		if got := hostInboundSameInterface(dottedCfg, tc.b, tc.a); got != tc.want {
			t.Errorf("hostInboundSameInterface(cfg,%q,%q)=%v want %v", tc.b, tc.a, got, tc.want)
		}
	}

	// End to end: a server group on reth1.50 must NOT make reth1.0 read as a
	// server. Getting this wrong labels an idle interface "DHCP server" and
	// tells the operator migrating it is vendor-backed when it is not.
	cfg := baseRoleCfg("reth1.0")
	cfg.System.DHCPServer.DHCPLocalServer = &DHCPLocalServerConfig{
		Groups: map[string]*DHCPServerGroup{
			"other": {Name: "other", Interfaces: []string{"reth1.50"}},
		},
	}
	if msg := roleZone(t, cfg); !strings.Contains(msg, "reth1.0 (no DHCP configured)") {
		t.Fatalf("a server group on a SIBLING unit must not classify this unit as a server: %s", msg)
	}
}

// TestDHCPClientRoleIsV4Only6519 — the tokens this advisory covers open
// udp/67-68, and `dhcpv6` is deliberately outside the vendor sentence. A v6-only
// client must not be reported as the v4 client role.
func TestDHCPClientRoleIsV4Only6519(t *testing.T) {
	cfg := baseRoleCfg("ge-0/0/4.0")
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/4": {Name: "ge-0/0/4", Units: map[int]*InterfaceUnit{0: {Number: 0, DHCPv6: true}}},
	}
	if msg := roleZone(t, cfg); !strings.Contains(msg, "ge-0/0/4.0 (no DHCP configured)") {
		t.Fatalf("a DHCPv6-only client is not the v4 client role the dhcp/bootp tokens gate: %s", msg)
	}
}
