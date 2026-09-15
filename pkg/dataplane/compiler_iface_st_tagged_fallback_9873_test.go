package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9873: the lexical st<N> fallback in resolveInterfaceRef resolved a
// configured TAGGED unit as a physical netdev (vlan 0), so the reference never
// reached planPhysDesired's tagged branch: the parent's interface-level mtu
// was never planned, while the unit MTU was written to a dotted name with no
// VLAN. The unbound arm now falls through to ordinary resolution when the
// configured unit carries a vlan-id. The bound arm above it is untouched
// (#6691 order), and every other unbound shape keeps the verbatim ref — the
// unconfigured-base case the arm exists for, and the configured-but-untagged
// case #6729 and TestResolveInterfaceRefXFRMUnit pin.

// stTaggedConfig9873 is the issue's exact configuration: a vlan-tagging st10
// with an interface-level mtu and a tagged unit carrying its own mtu.
func stTaggedConfig9873() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"st10.5"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st10": {
			Name:        "st10",
			VlanTagging: true,
			MTU:         1400,
			Units: map[int]*config.InterfaceUnit{
				5: {Number: 5, VlanID: 100, Addresses: []string{"172.16.5.8/24"}, MTU: 1300},
			},
		},
	}
	return cfg
}

func TestUnboundTaggedStUnitHonoursItsVlanID_9873(t *testing.T) {
	cfg := stTaggedConfig9873()
	// PREMISE: nothing binds this ref — this case is about the UNBOUND arm,
	// which #6691 does not cover.
	if !config.IsSecureTunnelIfName("st10") {
		t.Fatal("premise broken: st10 must classify as a secure-tunnel base, else the lexical arm never competes for this ref")
	}
	if dev, ok := cfg.SecureTunnelUnitNetdev("st10.5"); ok {
		t.Fatalf("premise broken: st10.5 is owned by a VPN (device %q); this case is about the UNBOUND arm", dev)
	}
	phys, cfgName, unit, vlan := resolveInterfaceRef("st10.5", cfg)
	if phys != "st10" || cfgName != "st10" || unit != 5 || vlan != 100 {
		t.Fatalf("resolveInterfaceRef(st10.5) = (%q, %q, u%d, v%d), want (st10, st10, u5, v100): "+
			"a configured vlan-id makes the unit a VLAN child of st10, not a physical netdev",
			phys, cfgName, unit, vlan)
	}
	plan := planPhysDesired(cfg)
	pd := plan["st10"]
	if pd == nil {
		t.Fatal("no plan for st10: the interface-level mtu of a vlan-tagging st interface never reaches the parent")
	}
	if pd.mtu != 1400 {
		t.Errorf("parent mtu = %d, want the interface-level 1400; the unit's own mtu (1300) belongs to its VLAN sub-interface", pd.mtu)
	}
	if len(pd.addrs) != 0 {
		t.Errorf("parent addresses = %v, want none: a tagged unit's addresses belong to its sub-interface", pd.addrs)
	}
	if pd, ok := plan["st10.5"]; ok {
		t.Errorf("plan[st10.5] = %+v, want no entry: the unit MTU must not be written to a name with no VLAN", *pd)
	}
}

// TestBoundStUnitStillResolvesToTheAuthoredDevice_9873 pins the #6691 arm
// order at the resolveInterfaceRef level: a unit that IS secure-tunnel-owned
// resolves to the authored xfrmi device even when its stanza also carries a
// vlan-id. The #9873 fall-through only runs after the bound arm misses.
func TestBoundStUnitStillResolvesToTheAuthoredDevice_9873(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"st5.3"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st5": {
			Name:        "st5",
			VlanTagging: true,
			MTU:         1400,
			Units: map[int]*config.InterfaceUnit{
				3: {Number: 3, VlanID: 80, Addresses: []string{"10.9.9.1/24"}},
			},
		},
	}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"v": {Name: "v", BindInterface: "st5.3"},
	}
	// PREMISE: both arms really do claim this ref, and they disagree. Without
	// the disagreement the ordering assertion orders nothing.
	dev, owned := cfg.SecureTunnelUnitNetdev("st5.3")
	if !owned || dev != "st5.3" {
		t.Fatalf("premise broken: SecureTunnelUnitNetdev(st5.3) = (%q, %v), want (st5.3, true)", dev, owned)
	}
	phys, _, unit, vlan := resolveInterfaceRef("st5.3", cfg)
	if phys != "st5.3" || unit != 3 || vlan != 0 {
		t.Errorf("resolveInterfaceRef(st5.3) = (%q, u%d, v%d), want (st5.3, u3, v0): "+
			"bind-interface outranks vlan-id — the #9873 fall-through must not move the bound arm",
			phys, unit, vlan)
	}
}
