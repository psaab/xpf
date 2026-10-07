package config

import (
	"strings"
	"testing"
)

// FAIL-ON-REVERT: removing the #11060 gate or its uniform-gate dispatch lets
// both instances claim the same interface and makes their kernel/dataplane
// membership disagree. The strict error must name the interface and both RIs.
func TestRIDualClaimRejectedAndToleratedWithWarning11060(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/7 unit 0 family inet address 192.0.2.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface ge-0/0/7.0",
		"set routing-instances red instance-type virtual-router",
		"set routing-instances red interface ge-0/0/7.0",
	}

	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("strict commit accepted ge-0/0/7.0 claimed by routing-instances blue and red")
	} else {
		for _, want := range []string{"ge-0/0/7.0", "blue", "red", "#11060"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("dual-claim error %q does not name %q", err, want)
			}
		}
	}

	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("tolerant load must keep booting a legacy dual-claim config: %v", err)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "routing-instance interface membership QUARANTINED") &&
			strings.Contains(warning, "blue") && strings.Contains(warning, "red") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a quarantine warning naming both instances, got %v", cfg.Warnings)
	}
	if len(cfg.QuarantinedRIMemberDeviceConflicts) != 1 ||
		cfg.QuarantinedRIMemberDeviceConflicts[0].LinuxName != "ge-0-0-7" {
		t.Fatalf("tolerant conflict evidence = %+v, want the unbound ge-0-0-7 device", cfg.QuarantinedRIMemberDeviceConflicts)
	}
	for _, ri := range cfg.RoutingInstances {
		if len(ri.Interfaces) != 0 {
			t.Fatalf("ambiguous member remained in %s after tolerant load: %v", ri.Name, ri.Interfaces)
		}
	}
}

// A bare member claims its configured units, so it conflicts with another
// instance that lists one of those units explicitly.
func TestRIBareAndUnitClaimRejectedAcrossInstances11060(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/7 unit 0 family inet address 192.0.2.1/24",
		"set routing-instances blue interface ge-0/0/7",
		"set routing-instances red interface ge-0/0/7.0",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil ||
		!strings.Contains(err.Error(), "blue") || !strings.Contains(err.Error(), "red") {
		t.Fatalf("bare/unit dual claim must be rejected naming both RIs, got %v", err)
	}
}

// Two distinct logical units are independent routing keys and remain valid
// when split between instances (the ordinary VLAN-subinterface case).
func TestRIDualClaimDistinctUnitsRemainValid11060(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/7": {Name: "ge-0/0/7", Units: map[int]*InterfaceUnit{
				0: {Number: 0, VlanID: 100},
				1: {Number: 1, VlanID: 200},
			}}},
		},
		RoutingInstances: []*RoutingInstanceConfig{
			{Name: "blue", InstanceType: "vrf", Interfaces: []string{"ge-0/0/7.0"}},
			{Name: "red", InstanceType: "vrf", Interfaces: []string{"ge-0/0/7.1"}},
		},
	}
	if err := validateRIDualClaimStrict11060(cfg); err != nil {
		t.Fatalf("distinct units in different instances are a valid split: %v", err)
	}
	blue := RoutingInstanceMemberDeviceKeys(cfg, cfg.TunnelNameMap(), "ge-0/0/7.0")
	red := RoutingInstanceMemberDeviceKeys(cfg, cfg.TunnelNameMap(), "ge-0/0/7.1")
	if len(blue) != 1 || blue[0].LinuxName != "ge-0-0-7.100" ||
		len(red) != 1 || red[0].LinuxName != "ge-0-0-7.200" {
		t.Fatalf("distinct VLAN units did not resolve to distinct Linux devices: blue=%+v red=%+v", blue, red)
	}
}

// TestRethRoutingInstanceMemberUsesLocalPhysical12059 pins the Linux netdev
// identity used by the daemon bind, reassert, and stale-member desired set.
// RETH bonds are absent; each configured RETH unit is carried by the local
// physical member, whose slot is selected by the compiled node ID.
func TestRethRoutingInstanceMemberUsesLocalPhysical12059(t *testing.T) {
	for _, tc := range []struct {
		node int
		base string
	}{
		{node: 0, base: "ge-0-0-2"},
		{node: 1, base: "ge-7-0-2"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			cfg := &Config{}
			cfg.Chassis.Cluster = &ClusterConfig{NodeID: tc.node}
			cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
				"ge-7/0/2": {Name: "ge-7/0/2", RedundantParent: "reth0"},
				"reth0": {
					Name: "reth0",
					Units: map[int]*InterfaceUnit{
						50: {Number: 50, VlanID: 50},
						80: {Number: 80, VlanID: 180},
					},
				},
			}
			ri := &RoutingInstanceConfig{
				Name: "blue", InstanceType: "vrf", Interfaces: []string{"reth0"},
			}
			keys := RoutingInstanceMemberDeviceKeysForInstance(cfg, cfg.TunnelNameMap(), ri)
			want := map[string]string{
				"reth0":    tc.base,
				"reth0.50": tc.base + ".50",
				"reth0.80": tc.base + ".180",
			}
			if len(keys) != len(want) {
				t.Fatalf("RETH member keys = %+v, want %d logical keys", keys, len(want))
			}
			for _, key := range keys {
				if want[key.InterfaceKey] != key.LinuxName {
					t.Errorf("member %q LinuxName = %q, want %q",
						key.InterfaceKey, key.LinuxName, want[key.InterfaceKey])
				}
				delete(want, key.InterfaceKey)
			}
			if len(want) != 0 {
				t.Errorf("missing member keys: %v", want)
			}

			explicit := RoutingInstanceMemberDeviceKeys(cfg, cfg.TunnelNameMap(), "reth0.80")
			if len(explicit) != 1 || explicit[0].LinuxName != tc.base+".180" {
				t.Fatalf("explicit RETH unit key = %+v, want %s.180", explicit, tc.base)
			}

			// Exact declared dotted names outrank parsing as a RETH unit.
			cfg.Interfaces.Interfaces["reth0.50"] = &InterfaceConfig{Name: "reth0.50"}
			dotted := RoutingInstanceMemberDeviceKeys(cfg, cfg.TunnelNameMap(), "reth0.50")
			if len(dotted) != 1 || dotted[0].LinuxName != "reth0.50" {
				t.Fatalf("declared dotted device = %+v, want exact identity reth0.50", dotted)
			}
		})
	}
}

func TestRIDualClaimResolvesLinuxAliasesIndependentOfInstanceOrder11060(t *testing.T) {
	for _, tc := range []struct {
		name string
		ris  []*RoutingInstanceConfig
	}{
		{
			name: "blue-before-red",
			ris: []*RoutingInstanceConfig{
				{Name: "blue", Interfaces: []string{"ge-0/0/7.0"}},
				{Name: "red", Interfaces: []string{"ge-0-0-7.00"}},
			},
		},
		{
			name: "red-before-blue",
			ris: []*RoutingInstanceConfig{
				{Name: "red", Interfaces: []string{"ge-0-0-7.00"}},
				{Name: "blue", Interfaces: []string{"ge-0/0/7.0"}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
					"ge-0/0/7": {Name: "ge-0/0/7", Units: map[int]*InterfaceUnit{
						0: {Number: 0, VlanID: 100},
					}},
				}},
				RoutingInstances: tc.ris,
			}
			err := validateRIDualClaimStrict11060(cfg)
			if err == nil {
				t.Fatal("cross-spelled unit refs to the same VLAN device were accepted")
			}
			for _, want := range []string{"ge-0-0-7.100", "ge-0/0/7.0", "ge-0-0-7.00", "blue", "red"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("device conflict error %q does not identify %q", err, want)
				}
			}
		})
	}
}

func TestRIDualClaimNamesEveryOwnerAndRejectsSharedTunnelDevice11060(t *testing.T) {
	t.Run("three owners", func(t *testing.T) {
		cfg := &Config{
			Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/7": {Name: "ge-0/0/7", Units: map[int]*InterfaceUnit{
					0: {Number: 0, VlanID: 100},
				}},
			}},
			RoutingInstances: []*RoutingInstanceConfig{
				{Name: "blue", Interfaces: []string{"ge-0/0/7.0"}},
				{Name: "red", Interfaces: []string{"ge-0-0-7.0"}},
				{Name: "green", Interfaces: []string{"ge-0-0-7.00"}},
			},
		}
		err := validateRIDualClaimStrict11060(cfg)
		if err == nil {
			t.Fatal("three RIs claiming one Linux device were accepted")
		}
		for _, want := range []string{"blue", "red", "green"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("three-owner error %q omits %q", err, want)
			}
		}
	})

	t.Run("shared interface tunnel", func(t *testing.T) {
		cfg := &Config{
			Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
				"wg0": {
					Name:   "wg0",
					Tunnel: &TunnelConfig{Mode: "wireguard"},
					Units: map[int]*InterfaceUnit{
						0: {Number: 0},
						1: {Number: 1},
					},
				},
			}},
			RoutingInstances: []*RoutingInstanceConfig{
				{Name: "blue", Interfaces: []string{"wg0.0"}},
				{Name: "red", Interfaces: []string{"wg0.1"}},
			},
		}
		if got := cfg.TunnelNameMap(); got["wg0.0"] != "wg0" || got["wg0.1"] != "wg0" {
			t.Fatalf("fixture does not model shared tunnel identity: %v", got)
		}
		err := validateRIDualClaimStrict11060(cfg)
		if err == nil || !strings.Contains(err.Error(), "wg0") ||
			!strings.Contains(err.Error(), "blue") || !strings.Contains(err.Error(), "red") {
			t.Fatalf("shared tunnel-device conflict was not rejected with both owners: %v", err)
		}
	})
}

func TestRIDualClaimTolerantBareMemberKeepsOnlyUnambiguousUnits11060(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/7 unit 10 vlan-id 100",
		"set interfaces ge-0/0/7 unit 20 vlan-id 200",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface ge-0/0/7",
		"set routing-instances red instance-type virtual-router",
		"set routing-instances red interface ge-0-0-7.10",
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if len(cfg.QuarantinedRIMemberDeviceConflicts) != 1 ||
		cfg.QuarantinedRIMemberDeviceConflicts[0].LinuxName != "ge-0-0-7.100" {
		t.Fatalf("quarantined device metadata = %+v", cfg.QuarantinedRIMemberDeviceConflicts)
	}
	instances := make(map[string]*RoutingInstanceConfig)
	for _, ri := range cfg.RoutingInstances {
		instances[ri.Name] = ri
	}
	if got := instances["blue"].Interfaces; len(got) != 1 || got[0] != "ge-0/0/7.20" {
		t.Fatalf("safe fanout unit was not retained explicitly: %v", got)
	}
	if got := cfg.QuarantinedRIMemberPrimaryClaims; len(got) != 1 ||
		got[0].Instance != "blue" || got[0].InterfaceKey != "ge-0/0/7" ||
		got[0].LinuxName != "ge-0-0-7" {
		t.Fatalf("uncontested bare primary was not retained as a base-only claim: %+v", got)
	}
	keys := RoutingInstanceMemberDeviceKeysForInstance(cfg, cfg.TunnelNameMap(), instances["blue"])
	kept := make(map[string]string, len(keys))
	for _, key := range keys {
		kept[key.InterfaceKey] = key.LinuxName
	}
	if len(kept) != 2 || kept["ge-0/0/7"] != "ge-0-0-7" ||
		kept["ge-0/0/7.20"] != "ge-0-0-7.200" {
		t.Fatalf("sanitized ownership keys = %v, want primary base and safe tagged sibling", kept)
	}
	if got := instances["red"].Interfaces; len(got) != 0 {
		t.Fatalf("ambiguous explicit member remained in red: %v", got)
	}
	for _, ri := range cfg.RoutingInstances {
		for _, member := range ri.Interfaces {
			for _, key := range RoutingInstanceMemberDeviceKeys(cfg, cfg.TunnelNameMap(), member) {
				if key.LinuxName == "ge-0-0-7.100" {
					t.Fatalf("quarantined device was still assigned to %s via %q", ri.Name, member)
				}
			}
		}
	}
}

func TestRIDualClaimSameInstanceRepeatIsHarmless11060(t *testing.T) {
	cfg := &Config{RoutingInstances: []*RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", Interfaces: []string{"ge-0/0/7.0", "ge-0/0/7.0"},
	}}}
	if err := validateRIDualClaimStrict11060(cfg); err != nil {
		t.Fatalf("repeated member within one instance must not conflict: %v", err)
	}
}
