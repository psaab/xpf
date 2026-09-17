package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileSetTree9927(t *testing.T, cmds ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func fabricOwnerConfig9927(t *testing.T, memberFirst, tagged bool) *config.Config {
	t.Helper()
	fabricZone, memberZone := "aaa", "zzz"
	if memberFirst {
		fabricZone, memberZone = memberZone, fabricZone
	}
	cmds := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-9927",
		"set interfaces fab0 mtu 9000",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
		"set interfaces ge-0/0/0 mtu 1500",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet mtu 1500",
	}
	fabricRef, memberRef := "fab0.0", "ge-0/0/0.0"
	if tagged {
		cmds = append(cmds,
			"set interfaces fab0 vlan-tagging",
			"set interfaces fab0 unit 10 vlan-id 10",
			"set interfaces ge-0/0/0 vlan-tagging",
			"set interfaces ge-0/0/0 unit 20 vlan-id 20",
		)
		fabricRef, memberRef = "fab0.10", "ge-0/0/0.20"
	} else {
		cmds = append(cmds, "set interfaces fab0 unit 0")
	}
	cmds = append(cmds,
		"set security zones security-zone "+fabricZone+" interfaces "+fabricRef,
		"set security zones security-zone "+memberZone+" interfaces "+memberRef,
	)
	cfg, err := config.CompileConfigForNode(compileSetTree9927(t, cmds...), 0)
	if err != nil {
		t.Fatalf("CompileConfigForNode: %v", err)
	}
	return cfg
}

func fabricOwnerBondConfig9927(t *testing.T, name, ref string, tagged bool) *config.Config {
	t.Helper()
	cmds := []string{
		"set interfaces " + name + " mtu 1400",
		"set interfaces " + name + " fabric-options member-interfaces ge-0/0/0",
	}
	if tagged {
		cmds = append(cmds,
			"set interfaces "+name+" vlan-tagging",
			"set interfaces "+name+" unit 10 vlan-id 10",
		)
	} else {
		cmds = append(cmds, "set interfaces "+name+" unit 0")
	}
	cmds = append(cmds, "set security zones security-zone trust interfaces "+ref)
	cfg, err := config.CompileConfig(compileSetTree9927(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func nonFabricMTUConfig9927() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"ordinary": {Name: "ordinary", Interfaces: []string{"ge-0/0/1.0", "ge-0/0/1.5"}},
		}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name: "ge-0/0/1", MTU: 1400,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, MTU: 1500, Addresses: []string{"192.0.2.1/24"}},
					5: {Number: 5, MTU: 1600, Addresses: []string{"192.0.2.2/24"}},
				},
			},
		}},
	}
}

func ownerlessSlashBondConfig9927(t *testing.T) *config.Config {
	t.Helper()
	tree := compileSetTree9927(t,
		"set interfaces fab/0 mtu 1400",
		"set interfaces fab/0 vlan-tagging",
		"set interfaces fab/0 fabric-options member-interfaces ge-0/0/0",
		"set interfaces fab/0 unit 10 vlan-id 10",
		"set security zones security-zone trust interfaces fab/0.10",
	)
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// TestFabricOwnedNetdevSuppressesEveryReference_9927 is expected to fail on
// origin/master: the direct member reference contributes its 1500 MTU after
// fab0's 9000-MTU reference has resolved to the same netdev. Both sorted zone
// orders and both tagged/untagged reference shapes must converge on the
// fabric setup's owner, not the member stanza.
func TestFabricOwnedNetdevSuppressesEveryReference_9927(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tagged bool
	}{
		{name: "untagged", tagged: false},
		{name: "tagged", tagged: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, memberFirst := range []bool{false, true} {
				order := "fabric-first"
				if memberFirst {
					order = "member-first"
				}
				t.Run(order, func(t *testing.T) {
					cfg := fabricOwnerConfig9927(t, memberFirst, tc.tagged)
					fabricRef := "fab0.0"
					memberRef := "ge-0/0/0.0"
					wantVLAN := 0
					if tc.tagged {
						fabricRef = "fab0.10"
						memberRef = "ge-0/0/0.20"
						wantVLAN = 10
					}
					physFabric, _, _, vlanFabric := resolveInterfaceRef(fabricRef, cfg)
					physMember, _, _, vlanMember := resolveInterfaceRef(memberRef, cfg)
					if physFabric != "ge-0-0-0" || physMember != physFabric ||
						vlanFabric != wantVLAN || (tc.tagged && vlanMember != 20) ||
						(!tc.tagged && vlanMember != 0) {
						t.Fatalf("premise: refs resolve to (%q,vlan %d) and (%q,vlan %d), want one ge-0-0-0 netdev with expected VLANs", physFabric, vlanFabric, physMember, vlanMember)
					}
					fab0 := cfg.Interfaces.Interfaces["fab0"]
					if fab0 == nil || fab0.MTU != 9000 || fab0.LocalFabricMember != "ge-0/0/0" {
						t.Fatalf("premise: compiled fabric owner = %+v, want mtu 9000 and local member ge-0/0/0", fab0)
					}
					pd := planPhysDesired(cfg)[physFabric]
					if pd != nil && pd.mtu != 0 {
						t.Fatalf("planned mtu %d on fabric-owned netdev %s, want no dataplane MTU write; fabric setup owns 9000", pd.mtu, physFabric)
					}
					if !tc.tagged && pd == nil {
						t.Fatalf("untagged references must still create a desired-state row for %s", physFabric)
					}
				})
			}
		})
	}
}

// TestFabricBondOwnerSuppressesBondReference_9927 pins the bond half of the
// ownership pre-pass. A canonical bond name is the netdev routing/bond.go
// creates, so both tagged and untagged references must not plan its MTU.
func TestFabricBondOwnerSuppressesBondReference_9927(t *testing.T) {
	for _, tc := range []struct {
		name, ref string
		tagged    bool
		wantVLAN  int
	}{
		{name: "tagged", ref: "fab0.10", tagged: true, wantVLAN: 10},
		{name: "untagged", ref: "fab0.0", wantVLAN: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fabricOwnerBondConfig9927(t, "fab0", tc.ref, tc.tagged)
			phys, cfgName, _, vlan := resolveInterfaceRef(tc.ref, cfg)
			if phys != "fab0" || cfgName != "fab0" || vlan != tc.wantVLAN {
				t.Fatalf("premise: resolveInterfaceRef(%q) = (%q,%q,vlan %d), want (fab0,fab0,vlan %d)", tc.ref, phys, cfgName, vlan, tc.wantVLAN)
			}
			if pd := planPhysDesired(cfg)[phys]; pd != nil && pd.mtu != 0 {
				t.Fatalf("planned mtu %d on fabric bond %s, want bond owner to write interface MTU", pd.mtu, phys)
			}
		})
	}
}

// TestOwnerlessSlashBondStillPlansMTU_9927 is the negative ownership control:
// bond.go passes the authored slash-bearing name to netlink, while the planner
// resolves it to fab-0. Since that bond cannot be created, fab-0 has no fabric
// owner and the old tagged-parent behavior remains required.
func TestOwnerlessSlashBondStillPlansMTU_9927(t *testing.T) {
	cfg := ownerlessSlashBondConfig9927(t)
	phys, cfgName, _, vlan := resolveInterfaceRef("fab/0.10", cfg)
	if phys != "fab-0" || cfgName != "fab/0" || vlan != 10 {
		t.Fatalf("premise: resolveInterfaceRef(fab/0.10) = (%q,%q,vlan %d), want (fab-0,fab/0,vlan 10)", phys, cfgName, vlan)
	}
	pd := planPhysDesired(cfg)[phys]
	if pd == nil || pd.mtu != 1400 {
		t.Fatalf("plan[%s] = %+v, want interface MTU 1400: bond.go cannot create authored slash name %q", phys, pd, cfgName)
	}
}

// TestNonFabricMTUPlanningRemainsUnchanged_9927 is the control for the
// resolved-netdev gate: an ordinary interface still chooses the lowest
// referenced untagged unit MTU over the interface MTU.
func TestNonFabricMTUPlanningRemainsUnchanged_9927(t *testing.T) {
	plan := planPhysDesired(nonFabricMTUConfig9927())
	pd := plan["ge-0-0-1"]
	if pd == nil {
		t.Fatal("no plan for ordinary interface ge-0-0-1")
	}
	if pd.mtu != 1500 {
		t.Fatalf("ordinary interface plan mtu = %d, want lowest referenced unit MTU 1500", pd.mtu)
	}
	if len(pd.addrs) != 2 || pd.addrs[0] != "192.0.2.1/24" || pd.addrs[1] != "192.0.2.2/24" {
		t.Fatalf("ordinary interface addresses = %v, want stable union in reference order", pd.addrs)
	}
}
