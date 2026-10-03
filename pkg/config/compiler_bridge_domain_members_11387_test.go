package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBridgeDomainMembersParseExplicitInterfaceUnits11387(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "hierarchical", body: `bridge-domains { bd0 { vlan-id-list 100; interface ge-0/0/0.0; } }`},
		{name: "hierarchical-list", body: `bridge-domains { bd0 { vlan-id-list 100; interface [ ge-0/0/0.0 ge-0/0/1.0 ]; } }`},
		{name: "compact", body: `bridge-domains { bd0 interface ge-0/0/0.0; }`},
		{name: "compact-list", body: `bridge-domains { bd0 interface [ ge-0/0/0.0 ge-0/0/1.0 ]; }`},
		{name: "set-list", body: `set bridge-domains bd0 vlan-id-list 100
set bridge-domains bd0 interface [ ge-0/0/0.0 ge-0/0/1.0 ]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *Config
			var err error
			if strings.HasPrefix(tc.body, "set ") {
				commands := strings.Split(tc.body, "\n")
				tree := &ConfigTree{}
				for _, command := range commands {
					path, parseErr := ParseSetCommand(command)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					if setErr := tree.SetPath(path); setErr != nil {
						t.Fatal(setErr)
					}
				}
				// Compile the section directly so this parser cell is independent
				// of the separate interface-resolution gate below.
				node := tree.FindChild("bridge-domains")
				var bds []*BridgeDomainConfig
				err = compileBridgeDomains(node, &bds, false, &[]string{})
				cfg = &Config{BridgeDomains: bds}
			} else {
				parsed, parseErr := NewParser(tc.body).Parse()
				if len(parseErr) != 0 {
					t.Fatal(parseErr)
				}
				node := parsed.FindChild("bridge-domains")
				var bds []*BridgeDomainConfig
				err = compileBridgeDomains(node, &bds, false, &[]string{})
				cfg = &Config{BridgeDomains: bds}
			}
			if err != nil {
				t.Fatalf("compile members: %v", err)
			}
			if len(cfg.BridgeDomains) != 1 {
				t.Fatalf("bridge domains = %d, want 1", len(cfg.BridgeDomains))
			}
			members := cfg.BridgeDomains[0].Members
			if len(members) == 0 || members[0] != "ge-0/0/0.0" {
				t.Fatalf("Members = %v, want explicit VLAN interface members", members)
			}
			if len(members) == 2 && members[1] != "ge-0/0/1.0" {
				t.Fatalf("Members = %v, want both bracket-list values", members)
			}
		})
	}
}

func TestBridgeDomainMembershipRequiresUniqueVIDAndExplicitZonedMember11387(t *testing.T) {
	base := func() *Config {
		return &Config{
			Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {VlanTagging: true, Units: map[int]*InterfaceUnit{
					0: {Number: 0, VlanID: 100, Addresses: []string{"192.0.2.1/24"}},
				}},
			}},
			BridgeDomains: []*BridgeDomainConfig{{Name: "bd0", VlanIDs: []int{100}, Members: []string{"ge-0/0/0.0"}}},
			Security: SecurityConfig{Zones: map[string]*ZoneConfig{
				"trust": {Interfaces: []string{"ge-0/0/0.0"}},
			}},
		}
	}

	t.Run("explicit member accepted", func(t *testing.T) {
		if err := validateBridgeDomainMembership11387(base()); err != nil {
			t.Fatalf("explicit zoned member rejected: %v", err)
		}
	})
	t.Run("zoned inet without member rejected", func(t *testing.T) {
		cfg := base()
		cfg.BridgeDomains[0].Members = nil
		err := validateBridgeDomainMembership11387(cfg)
		if err == nil || !strings.Contains(err.Error(), "no explicit bridge-domain interface member statement") {
			t.Fatalf("missing-member error = %v", err)
		}
	})
	t.Run("duplicate VID across domains rejected", func(t *testing.T) {
		cfg := base()
		cfg.BridgeDomains = append(cfg.BridgeDomains, &BridgeDomainConfig{Name: "bd1", VlanIDs: []int{100}})
		err := validateBridgeDomainMembership11387(cfg)
		if err == nil || !strings.Contains(err.Error(), "may belong to only one bridge domain") {
			t.Fatalf("duplicate VID error = %v", err)
		}
	})
}

func TestBridgeDomainExplicitMemberCompilesWithZonedInetUnit11387(t *testing.T) {
	const input = `interfaces {
  ge-0/0/0 {
    vlan-tagging;
    unit 0 {
      vlan-id 100;
      family inet { address 192.0.2.1/24; }
    }
  }
}
security {
  zones { security-zone trust { interfaces ge-0/0/0.0; } }
}
bridge-domains {
  bd0 { vlan-id-list 100; interface ge-0/0/0.0; }
}`
	tree, parseErrs := NewParser(input).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse: %v", parseErrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("explicit VLAN interface member must compile: %v", err)
	}
	if len(cfg.BridgeDomains) != 1 || len(cfg.BridgeDomains[0].Members) != 1 ||
		cfg.BridgeDomains[0].Members[0] != "ge-0/0/0.0" {
		t.Fatalf("compiled bridge-domain members = %+v", cfg.BridgeDomains)
	}
	missingMemberInput := strings.Replace(input, "interface ge-0/0/0.0; ", "", 1)
	missingTree, parseErrs := NewParser(missingMemberInput).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse missing-member case: %v", parseErrs)
	}
	_, err = CompileConfig(missingTree)
	if err == nil || !strings.Contains(err.Error(), "no explicit bridge-domain interface member statement") {
		t.Fatalf("strict compile without a zoned inet member error = %v", err)
	}
	lenient, err := CompileConfigLenient(missingTree)
	if err != nil {
		t.Fatalf("tolerant load with missing member must remain bootable: %v", err)
	}
	foundWarning := false
	for _, warning := range lenient.Warnings {
		if strings.Contains(warning, "bridge-domain membership (downgraded to warning on tolerant path)") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("tolerant missing-member warning absent: %v", lenient.Warnings)
	}
}

func TestBridgeDomainMembersAreNotOnSnapshotJSONWire11387(t *testing.T) {
	encoded, err := json.Marshal(Config{BridgeDomains: []*BridgeDomainConfig{{
		Name: "bd0", VlanIDs: []int{100}, Members: []string{"ge-0/0/0.0"},
	}}})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if strings.Contains(string(encoded), "Members") || strings.Contains(string(encoded), "ge-0/0/0.0") {
		t.Fatalf("compiler-only bridge members leaked onto config snapshot wire: %s", encoded)
	}
	familyWire, err := json.Marshal(InterfaceUnit{FamilyInet: true})
	if err != nil {
		t.Fatalf("marshal interface unit: %v", err)
	}
	if strings.Contains(string(familyWire), "FamilyInet") {
		t.Fatalf("compiler-only inet-family evidence leaked onto JSON wire: %s", familyWire)
	}
}

// The member suffix is a logical unit number, not a VID: ge-0/0/0.0 names
// unit 0, whose vlan-id supplies the VID. A fixture where the suffix equals
// the VID cannot tell the two readings apart; unit 0 / VLAN 100 does.
func TestBridgeDomainMemberSuffixIsLogicalUnitNotVID11387(t *testing.T) {
	base := func() *Config {
		return &Config{
			Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {VlanTagging: true, Units: map[int]*InterfaceUnit{
					0: {Number: 0, VlanID: 100, Addresses: []string{"192.0.2.1/24"}},
				}},
			}},
			BridgeDomains: []*BridgeDomainConfig{{Name: "bd0", VlanIDs: []int{100}, Members: []string{"ge-0/0/0.0"}}},
			Security: SecurityConfig{Zones: map[string]*ZoneConfig{
				"trust": {Interfaces: []string{"ge-0/0/0.0"}},
			}},
		}
	}

	t.Run("unit 0 with VLAN 100 accepted via ge-0/0/0.0", func(t *testing.T) {
		if err := validateBridgeDomainMembership11387(base()); err != nil {
			t.Fatalf("unit-number member rejected: %v", err)
		}
	})
	t.Run("VID-as-suffix rejected when no such unit exists", func(t *testing.T) {
		cfg := base()
		cfg.BridgeDomains[0].Members = []string{"ge-0/0/0.100"}
		err := validateBridgeDomainMembership11387(cfg)
		if err == nil || !strings.Contains(err.Error(), "does not reference a configured unit") {
			t.Fatalf("unit-100 member error = %v, want unconfigured-unit rejection", err)
		}
	})
	t.Run("unit whose VID is outside vlan-id-list rejected", func(t *testing.T) {
		cfg := base()
		cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].VlanID = 200
		err := validateBridgeDomainMembership11387(cfg)
		if err == nil || !strings.Contains(err.Error(), "not in vlan-id-list") {
			t.Fatalf("wrong-VID unit error = %v, want vlan-id-list rejection", err)
		}
	})
	t.Run("untagged unit rejected as member", func(t *testing.T) {
		cfg := base()
		cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].VlanID = 0
		err := validateBridgeDomainMembership11387(cfg)
		if err == nil || !strings.Contains(err.Error(), "no VLAN ID") {
			t.Fatalf("untagged member error = %v, want tagged-unit rejection", err)
		}
	})
}

// Authored `family inet` without an address or DHCP is still an inet unit:
// a filter-only unit must not escape the missing-member gate. IPv6-only and
// family-less units stay exempt.
func TestBridgeDomainMissingMemberCatchesAuthoredInetWithoutAddress11387(t *testing.T) {
	base := func(mutate func(*InterfaceUnit)) *Config {
		unit := &InterfaceUnit{Number: 0, VlanID: 100, FamilyInet: true}
		mutate(unit)
		return &Config{
			Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/0": {VlanTagging: true, Units: map[int]*InterfaceUnit{0: unit}},
			}},
			BridgeDomains: []*BridgeDomainConfig{{Name: "bd0", VlanIDs: []int{100}}},
			Security: SecurityConfig{Zones: map[string]*ZoneConfig{
				"trust": {Interfaces: []string{"ge-0/0/0.0"}},
			}},
		}
	}
	for _, tc := range []struct {
		name    string
		mutate  func(*InterfaceUnit)
		wantErr bool
	}{
		{name: "filter input only", mutate: func(u *InterfaceUnit) { u.FilterInputV4 = "f1" }, wantErr: true},
		{name: "filter output only", mutate: func(u *InterfaceUnit) { u.FilterOutputV4 = "f1" }, wantErr: true},
		{name: "unnumbered inet", mutate: func(u *InterfaceUnit) { u.UnnumberedInet = "ge-0/0/1.0" }, wantErr: true},
		{name: "targeted broadcast", mutate: func(u *InterfaceUnit) { u.TargetedBroadcast = true }, wantErr: true},
		{name: "dynamic-dns inet", mutate: func(u *InterfaceUnit) {
			u.DynamicDNSInet = &InterfaceDynamicDNSConfig{Provider: "p", Hostname: "h.example."}
		}, wantErr: true},
		{name: "dhcp", mutate: func(u *InterfaceUnit) { u.DHCP = true }, wantErr: true},
		{name: "ipv4 address", mutate: func(u *InterfaceUnit) { u.Addresses = []string{"192.0.2.1/24"} }, wantErr: true},
		{name: "empty authored inet family", mutate: func(u *InterfaceUnit) {}, wantErr: true},
		{name: "ipv6 address only stays exempt", mutate: func(u *InterfaceUnit) {
			u.FamilyInet = false
			u.Addresses = []string{"2001:db8::1/64"}
		}, wantErr: false},
		{name: "no family stays exempt", mutate: func(u *InterfaceUnit) { u.FamilyInet = false }, wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBridgeDomainMembership11387(base(tc.mutate))
			if tc.wantErr && (err == nil || !strings.Contains(err.Error(), "no explicit bridge-domain interface member statement")) {
				t.Fatalf("authored-inet escape: error = %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("non-inet unit wrongly gated: %v", err)
			}
		})
	}
}

// End-to-end form of the no-address escape: `family inet { filter {...} }`
// with no address must still demand an explicit member statement.
func TestBridgeDomainNoAddressInetFilterUnitRequiresMember11387(t *testing.T) {
	const input = `firewall {
  family inet {
    filter f1 { term t1 { from { protocol tcp; } then { accept; } } }
  }
}
interfaces {
  ge-0/0/0 {
    vlan-tagging;
    unit 0 {
      vlan-id 100;
      family inet { filter { input f1; } }
    }
  }
}
security {
  zones { security-zone trust { interfaces ge-0/0/0.0; } }
}
bridge-domains {
  bd0 { vlan-id-list 100; }
}`
	tree, parseErrs := NewParser(input).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse: %v", parseErrs)
	}
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "no explicit bridge-domain interface member statement") {
		t.Fatalf("filter-only inet without member error = %v", err)
	}
	withMember := strings.Replace(input, "bd0 { vlan-id-list 100; }", "bd0 { vlan-id-list 100; interface ge-0/0/0.0; }", 1)
	memberTree, parseErrs := NewParser(withMember).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse member case: %v", parseErrs)
	}
	if _, err := CompileConfig(memberTree); err != nil {
		t.Fatalf("filter-only inet with explicit member rejected: %v", err)
	}
}
