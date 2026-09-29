package config

import (
	"strings"
	"testing"
)

// #6519: Junos accepts `dhcp` / `bootp` host-inbound ONLY per interface ("All
// services (except DHCP and BOOTP) can be configured either per zone or per
// interface. A DHCP server is configured only per interface because the incoming
// interface must be known by the server to be able to send out DHCP replies.").
// xpf accepts them at the zone level and lets them authorize every member
// interface. This advisory names that deviation; enforcement is unchanged.

// dhcpScopeCfg6519 builds a one-zone config with two member interfaces, an
// optional interface-level override on the first, and the given zone-level
// system-services.
func dhcpScopeCfg6519(zoneSvc []string, ifaceSvc []string, firstRef string) *Config {
	cfg := &Config{}
	zone := &ZoneConfig{
		Name:               "trust",
		Interfaces:         []string{firstRef, "ge-0/0/1.0"},
		HostInboundTraffic: &HostInboundTraffic{SystemServices: zoneSvc},
	}
	if ifaceSvc != nil {
		zone.InterfaceHostInbound = map[string]*HostInboundTraffic{
			firstRef: {SystemServices: ifaceSvc},
		}
	}
	cfg.Security.Zones = map[string]*ZoneConfig{"trust": zone}
	return cfg
}

// TestZoneLevelDHCPAdvisory_6519 covers what the advisory must say and, as
// importantly, when it must stay quiet.
func TestZoneLevelDHCPAdvisory_6519(t *testing.T) {
	t.Run("names the token and the interfaces it authorizes", func(t *testing.T) {
		got := validateHostInboundZoneLevelDHCPWarnings(
			dhcpScopeCfg6519([]string{"ssh", "dhcp"}, nil, "ge-0/0/0.0"))
		if len(got) != 1 {
			t.Fatalf("want exactly one advisory, got %d: %v", len(got), got)
		}
		for _, want := range []string{`"trust"`, "dhcp", "ge-0/0/0.0", "ge-0/0/1.0", "per interface"} {
			if !strings.Contains(got[0], want) {
				t.Errorf("advisory must mention %q so the operator can act on it, got: %s", want, got[0])
			}
		}
		if strings.Contains(got[0], "ssh") {
			t.Errorf("ssh is configurable per zone in Junos and must not be named, got: %s", got[0])
		}
	})

	t.Run("fires for bootp as well as dhcp", func(t *testing.T) {
		got := validateHostInboundZoneLevelDHCPWarnings(
			dhcpScopeCfg6519([]string{"bootp"}, nil, "ge-0/0/0.0"))
		if len(got) != 1 || !strings.Contains(got[0], "bootp") {
			t.Fatalf("bootp is the other per-interface-only service; want one advisory naming it, got: %v", got)
		}
	})

	t.Run("fires for a zone-level `all`, which silently includes dhcp", func(t *testing.T) {
		// `all` expands to the named-service union, which contains dhcp and
		// bootp, so a zone-level `all` authorizes them on every member exactly
		// as a named token would. An advisory that reported only the named case
		// would leave this as a silent deviation.
		got := validateHostInboundZoneLevelDHCPWarnings(
			dhcpScopeCfg6519([]string{"all"}, nil, "ge-0/0/0.0"))
		if len(got) != 1 {
			t.Fatalf("want one advisory for the `all` case, got %d: %v", len(got), got)
		}
		if !strings.Contains(got[0], "via `all`") {
			t.Errorf("the advisory must say the token came from `all` — the edit that fixes it "+
				"is different from the named-token case; got: %s", got[0])
		}
	})

	t.Run("silent when no zone-level stanza admits dhcp or bootp", func(t *testing.T) {
		if got := validateHostInboundZoneLevelDHCPWarnings(
			dhcpScopeCfg6519([]string{"ssh", "ping"}, nil, "ge-0/0/0.0")); len(got) != 0 {
			t.Fatalf("want no advisory for a zone that never admits dhcp/bootp, got: %v", got)
		}
	})

	t.Run("silent when every member is a lifeline", func(t *testing.T) {
		cfg := dhcpScopeCfg6519([]string{"dhcp"}, nil, "fxp0.0")
		cfg.Chassis.Cluster = &ClusterConfig{ControlInterface: "em0"}
		cfg.Security.Zones["trust"].Interfaces = []string{"fxp0.0", "em0.0"}
		if got := validateHostInboundZoneLevelDHCPWarnings(cfg); len(got) != 0 {
			t.Fatalf("lifelines are excluded from host-inbound deny scoping, so no zone token "+
				"decides anything on them and an advisory would be a false alarm; got: %v", got)
		}
	})

	t.Run("does not name an interface that authorized dhcp itself", func(t *testing.T) {
		// The interface's OWN stanza admits dhcp, which is the Junos-correct
		// way to author it. Only the sibling relying on the zone-level token
		// should be named. This predicate — effective admits it, the
		// interface's own stanza does not — is also what keeps the advisory
		// correct after #6515 makes the interface level REPLACE the zone level.
		got := validateHostInboundZoneLevelDHCPWarnings(
			dhcpScopeCfg6519([]string{"dhcp"}, []string{"dhcp"}, "ge-0/0/0.0"))
		if len(got) != 1 {
			t.Fatalf("want one advisory (the sibling still relies on the zone token), got %d: %v", len(got), got)
		}
		if strings.Contains(got[0], "ge-0/0/0.0") {
			t.Errorf("ge-0/0/0.0 admits dhcp through its OWN interface stanza — the Junos-correct "+
				"authoring — and must not be named, got: %s", got[0])
		}
		if !strings.Contains(got[0], "ge-0/0/1.0") {
			t.Errorf("ge-0/0/1.0 has no stanza and is authorized only by the zone token; it must "+
				"be named, got: %s", got[0])
		}
	})
}

// TestInterfaceHostInboundOverrideAgreesWithEffective_6519 binds the new
// interface-level accessor to the resolver it was split out of. They must agree
// on stanza PRESENCE, and on a declared ref every interface-level token the
// accessor reports must also appear in the effective set — the property that
// holds whether the two levels union (today) or the interface level replaces the
// zone level (#6515), so this test does not have to be rewritten when that
// lands.
//
// Without this binding the advisory could silently reason about a different
// interface-level set than the resolver does, and its "authorized only by the
// zone token" claim would name the wrong interfaces.
func TestInterfaceHostInboundOverrideAgreesWithEffective_6519(t *testing.T) {
	z := &ZoneConfig{
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
		InterfaceHostInbound: map[string]*HostInboundTraffic{
			"ge-0/0/9":   {SystemServices: []string{"ping"}},
			"ge-0/0/9.0": {SystemServices: []string{"https"}},
			"ge-0/0/8.0": {}, // present-but-empty: declared, admits nothing
		},
	}
	for _, ref := range []string{"ge-0/0/9.0", "ge-0/0/8.0", "ge-0/0/7.0"} {
		effSvc, _, overridden := z.InterfaceHostInboundEffective(ref)
		ownSvc, _, declared := z.InterfaceHostInboundOverride(ref)
		if declared != overridden {
			t.Fatalf("%s: InterfaceHostInboundOverride declared=%v but "+
				"InterfaceHostInboundEffective overridden=%v — the two must agree on stanza "+
				"PRESENCE or the #6519 advisory names the wrong interfaces", ref, declared, overridden)
		}
		if !declared {
			continue
		}
		for _, tok := range ownSvc {
			if !hostInboundSetAdmitsService(effSvc, tok) {
				t.Errorf("%s: interface-level token %q is absent from the effective set %v — an "+
					"interface-level token must always reach the effective set", ref, tok, effSvc)
			}
		}
	}
	// The physical-parent inheritance is part of the accessor's contract: a bare
	// `ge-0/0/9` override applies to `ge-0/0/9.0`, so both tokens are reported.
	ownSvc, _, _ := z.InterfaceHostInboundOverride("ge-0/0/9.0")
	if strings.Join(ownSvc, ",") != "ping,https" {
		t.Fatalf("interface-level tokens for ge-0/0/9.0 = %v, want [ping https] (physical parent "+
			"UNION unit, #3720)", ownSvc)
	}
}
