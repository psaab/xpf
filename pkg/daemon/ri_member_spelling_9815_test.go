package daemon

import (
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// #9815 LEAD-F66: a routing-instance unit member whose base spelling differs
// from its `interfaces` stanza key (dash vs slash) misses the stanza lookup,
// so the unit's vlan-id is unknown and the VRF bind targets the wrong netdev:
// `base.<unit number>` (nonexistent when vlan-id differs) or, for a tagged
// unit 0, the parent netdev. The real 802.1Q child is never enslaved.
//
// spellingCfg9815 is a vlan-tagging port with unit 0 on vlan 10 and unit 1 on
// vlan 50, keyed under EITHER spelling — the matrix below crosses stanza
// spelling with member spelling.
func spellingCfg9815(stanza string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		stanza: {
			Name:        stanza,
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, VlanID: 10},
				1: {Number: 1, VlanID: 50},
			},
		},
	}
	return cfg
}

// #9815 LEAD-F66: the acceptance matrix from the issue. Slash/dash stanza x
// slash/dash member, with unit 1 on vlan 50 and a tagged unit 0: every row
// must bind the VLAN device, and the singular/plural resolvers must agree
// (the step-0a bind loop drives the plural, the tunnel scan the singular).
func TestRIMemberBindsVLANDeviceInEitherSpelling9815(t *testing.T) {
	units := []struct {
		num  string
		vlan int
	}{{"0", 10}, {"1", 50}}
	for _, stanza := range []string{"ge-0/0/0", "ge-0-0-0"} {
		for _, memberBase := range []string{"ge-0/0/0", "ge-0-0-0"} {
			for _, u := range units {
				member := memberBase + "." + u.num
				want := "ge-0-0-0." + string(rune('0'+u.vlan/10)) + string(rune('0'+u.vlan%10))
				if u.vlan == 50 {
					want = "ge-0-0-0.50"
				} else {
					want = "ge-0-0-0.10"
				}
				t.Run(stanza+"/"+member, func(t *testing.T) {
					cfg := spellingCfg9815(stanza)
					tunMap := cfg.TunnelNameMap()
					got := riMemberLinuxNames(cfg, tunMap, member)
					if len(got) != 1 || got[0] != want {
						t.Fatalf("#9815: stanza %q member %q binds %v, want [%s]",
							stanza, member, got, want)
					}
					if sing := riMemberLinuxName(cfg, tunMap, member); sing != want {
						t.Fatalf("#9815: stanza %q member %q singular binds %q, want %q",
							stanza, member, sing, want)
					}
				})
			}
		}
	}
	// Cross-spelled unit tunnel refs must preserve both tunnel forms: a
	// per-unit tunnel uses its authored device, while an interface-level
	// tunnel shares the stanza's base device. Test both spelling directions
	// and compare singular/plural member resolution.
	for _, tunnel := range []struct {
		name    string
		perUnit bool
		want    string
	}{
		{"per-unit", true, "ri-unit-tun"},
		{"interface-level", false, "ge-0-0-0"},
	} {
		for _, stanza := range []string{"ge-0/0/0", "ge-0-0-0"} {
			for _, memberBase := range []string{"ge-0/0/0", "ge-0-0-0"} {
				member := memberBase + ".1"
				t.Run("tunnel/"+tunnel.name+"/"+stanza+"/"+member, func(t *testing.T) {
					cfg := spellingCfg9815(stanza)
					ifc := cfg.Interfaces.Interfaces[stanza]
					if tunnel.perUnit {
						ifc.Units[1].Tunnel = &config.TunnelConfig{Name: tunnel.want}
					} else {
						ifc.Tunnel = &config.TunnelConfig{
							Name:        tunnel.want,
							Source:      "10.0.0.1",
							Destination: "10.0.0.2",
						}
					}
					tunMap := cfg.TunnelNameMap()
					if got := riMemberLinuxName(cfg, tunMap, member); got != tunnel.want {
						t.Fatalf("#9815: %s tunnel stanza %q member %q singular binds %q, want %q",
							tunnel.name, stanza, member, got, tunnel.want)
					}
					got := riMemberLinuxNames(cfg, tunMap, member)
					if len(got) != 1 || got[0] != tunnel.want {
						t.Fatalf("#9815: %s tunnel stanza %q member %q plural binds %v, want [%s]",
							tunnel.name, stanza, member, got, tunnel.want)
					}
				})
			}
		}
	}
}

// #9815 LEAD-F66: the acceptance cell against the kernel. Dash-spelled unit
// members against a slash-spelled stanza, driven through the real bind pass
// with the real routing.Manager and real netlink. Skips without CAP_NET_ADMIN
// — run it under `unshare -rn`.
//
// It asserts the VLAN children's master is the VRF, AND that the parent stays
// out (unit refs must not fan up to the base, #9063): the tagged-unit-0 defect
// binds the parent netdev, which exists, so the bind succeeds silently.
func TestDashMemberEnslavesVLANChildInKernel9815(t *testing.T) {
	enterPrivateNetns9813(t)

	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue"}, Table: 100}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Skipf("cannot create a VRF device in this netns (is the vrf module loaded?): %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("vrf up: %v", err)
	}
	parent := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-0"}}
	if err := netlink.LinkAdd(parent); err != nil {
		t.Skipf("cannot create a dummy parent in this netns: %v", err)
	}
	if err := netlink.LinkSetUp(parent); err != nil {
		t.Fatalf("parent up: %v", err)
	}
	live, err := netlink.LinkByName("ge-0-0-0")
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	for _, vlanID := range []int{10, 50} {
		name := "ge-0-0-0.10"
		if vlanID == 50 {
			name = "ge-0-0-0.50"
		}
		child := &netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        name,
				ParentIndex: live.Attrs().Index,
			},
			VlanId: vlanID,
		}
		if err := netlink.LinkAdd(child); err != nil {
			t.Skipf("cannot create an 802.1Q child in this netns: %v", err)
		}
		if err := netlink.LinkSetUp(child); err != nil {
			t.Fatalf("child %s up: %v", child.Name, err)
		}
	}

	rt, err := routing.New()
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	d := &Daemon{routing: rt, linkByNameFn: netlink.LinkByName}

	cfg := spellingCfg9815("ge-0/0/0")
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", TableID: 100,
		Interfaces: []string{"ge-0-0-0.0", "ge-0-0-0.1"},
	}}
	d.bindRoutingInstanceMembers(cfg)

	vrfLink, err := netlink.LinkByName("vrf-blue")
	if err != nil {
		t.Fatalf("vrf-blue: %v", err)
	}
	for _, name := range []string{"ge-0-0-0.10", "ge-0-0-0.50"} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("%s absent: %v", name, err)
		}
		if l.Attrs().MasterIndex != vrfLink.Attrs().Index {
			t.Fatalf("#9815: %s has master index %d, want vrf-blue (%d). A dash-spelled "+
				"member against a slash-spelled stanza must enslave the VLAN child, or "+
				"kernel-path traffic on it fails open to main",
				name, l.Attrs().MasterIndex, vrfLink.Attrs().Index)
		}
	}
	if l, err := netlink.LinkByName("ge-0-0-0"); err == nil {
		if l.Attrs().MasterIndex == vrfLink.Attrs().Index {
			t.Fatalf("#9815: the parent ge-0-0-0 is enslaved by unit members — unit refs " +
				"must not fan up to the base (#9063); the tagged-unit-0 defect binds the parent")
		}
	}
}

// #9815 fix-ordering invariant: a device this pass enslaves into a VRF must NOT
// also appear in the default-instance next-table ingress set — the ordering
// hazard the issue names explicitly. Green on base only vacuously (both sides
// miss the spelling split); it must stay green once the bind side is fixed,
// which is exactly when the scoping side has to move with it.
func TestBoundDevicesAreNotDefaultIngressInEitherSpelling9815(t *testing.T) {
	for _, stanza := range []string{"ge-0/0/0", "ge-0-0-0"} {
		for _, member := range []string{
			"ge-0/0/0", "ge-0-0-0",
			"ge-0/0/0.0", "ge-0-0-0.0",
			"ge-0/0/0.1", "ge-0-0-0.1",
		} {
			t.Run(stanza+"/"+member, func(t *testing.T) {
				cfg := spellingCfg9815(stanza)
				cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
					Name: "blue", InstanceType: "vrf", TableID: 100,
					Interfaces: []string{member},
				}}
				bound := make(map[string]struct{})
				for _, n := range riMemberLinuxNames(cfg, cfg.TunnelNameMap(), member) {
					bound[n] = struct{}{}
				}
				for _, iif := range routing.DefaultInstanceIngressIfaces(cfg) {
					if _, clash := bound[iif]; clash {
						t.Fatalf("#9815: %s is bound into a VRF by this pass AND listed "+
							"as default-instance next-table ingress; a unit cannot be in both",
							iif)
					}
				}
			})
		}
	}
}
