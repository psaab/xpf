package config

import (
	"strings"
	"testing"
)

// #16018 A7-03: VRRP group / RETH-derived VRRP on a zone interface whose
// effective host-inbound protocols omit `vrrp` must WARN naming the
// AF_PACKET bypass (never hard-reject); admitting `vrrp`/`all` silences it.

func vrrpBypassWarningsContain(w []string, subs ...string) bool {
	for _, x := range w {
		ok := true
		for _, s := range subs {
			if !strings.Contains(x, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestVRRPBypassWarning16018(t *testing.T) {
	mkZone := func(iface string, protos []string) *ZoneConfig {
		z := &ZoneConfig{Interfaces: []string{iface}}
		if protos != nil {
			z.HostInboundTraffic = &HostInboundTraffic{Protocols: protos}
		}
		return z
	}
	withGroup := func(cfg *Config) *Config {
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
				0: {VRRPGroups: map[string]*VRRPGroup{"10.0.0.1_grp1": {ID: 1}}},
			}},
		}
		return cfg
	}

	t.Run("group-deny-warns-afpacket", func(t *testing.T) {
		cfg := withGroup(&Config{})
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", nil)}
		w := validateHostInboundVRRPBypassWarnings(cfg)
		if !vrrpBypassWarningsContain(w, `ge-0/0/0.0`, `"trust"`, "AF_PACKET", "bypass") {
			t.Fatalf("want AF_PACKET bypass warning, got %v", w)
		}
	})
	t.Run("group-admitted-silent", func(t *testing.T) {
		cfg := withGroup(&Config{})
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", []string{"vrrp"})}
		if w := validateHostInboundVRRPBypassWarnings(cfg); len(w) != 0 {
			t.Fatalf("admitted vrrp must be silent, got %v", w)
		}
	})
	t.Run("group-all-silent", func(t *testing.T) {
		cfg := withGroup(&Config{})
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", []string{"all"})}
		if w := validateHostInboundVRRPBypassWarnings(cfg); len(w) != 0 {
			t.Fatalf("protocols all must be silent, got %v", w)
		}
	})
	t.Run("no-group-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("ge-0/0/0.0", nil)}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {}}},
		}
		if w := validateHostInboundVRRPBypassWarnings(cfg); len(w) != 0 {
			t.Fatalf("no VRRP must be silent, got %v", w)
		}
	})
	t.Run("reth-derived-warns", func(t *testing.T) {
		cfg := &Config{}
		// PrivateRGElection=false + no NoRethVRRP => RETH VRRP active.
		cfg.Chassis.Cluster = &ClusterConfig{PrivateRGElection: false}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("reth0.0", nil)}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*InterfaceUnit{
				0: {Addresses: []string{"10.0.0.1/24"}},
			}},
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0", Units: map[int]*InterfaceUnit{0: {}}},
		}
		w := validateHostInboundVRRPBypassWarnings(cfg)
		if !vrrpBypassWarningsContain(w, "AF_PACKET") {
			t.Fatalf("RETH-derived VRRP must warn, got %v", w)
		}
	})
	t.Run("reth-suppressed-silent", func(t *testing.T) {
		cfg := &Config{}
		cfg.Chassis.Cluster = &ClusterConfig{PrivateRGElection: true}
		cfg.Security.Zones = map[string]*ZoneConfig{"trust": mkZone("reth0.0", nil)}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*InterfaceUnit{
				0: {Addresses: []string{"10.0.0.1/24"}},
			}},
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0", Units: map[int]*InterfaceUnit{0: {}}},
		}
		if w := validateHostInboundVRRPBypassWarnings(cfg); len(w) != 0 {
			t.Fatalf("suppressed RETH VRRP must be silent, got %v", w)
		}
	})
}

// End-to-end: strict compile succeeds (WARN-only) and carries the warning.
func TestVRRPBypassCompileWarnOnly16018(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 virtual-address 10.0.0.254/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile must not reject VRRP bypass config: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "AF_PACKET") && strings.Contains(w, "VRRP") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want AF_PACKET VRRP warning in cfg.Warnings, got %v", cfg.Warnings)
	}
}
