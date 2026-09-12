package daemon

import (
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// #9754: a routing-instance member written BARE (`interface ge-0/0/0`) means
// every configured unit of that interface, and the userspace route binder and
// the DHCP route map both read it that way. The kernel VRF bind did not: it
// enslaved only the parent netdev, so the 802.1Q children for the tagged units
// stayed masterless and kernel-path traffic on them routed in the DEFAULT
// instance — failing OPEN to main, on a config strict accepts with no warning.
//
// FRR/zebra takes interface VRF membership from the kernel master, so those
// units' connected prefixes also landed in the default VRF and VRF-bound
// sockets never saw them.
//
// bareMemberCfg9754 is a vlan-tagging port with unit 0 on vlan 10 and unit 1 on
// vlan 50, claimed by a bare member — the shape the issue pins.
func bareMemberCfg9754() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name:        "ge-0/0/0",
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, VlanID: 10},
				1: {Number: 1, VlanID: 50},
			},
		},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", TableID: 100,
		Interfaces: []string{"ge-0/0/0"},
	}}
	return cfg
}

// The acceptance cell from the issue, against the kernel: a parent, two 802.1Q
// children and a VRF, driven through the real bind pass with the real
// routing.Manager and real netlink. Skips without CAP_NET_ADMIN — run it under
// `unshare -rn`.
//
// It asserts EVERY child's master, not just that some bind happened. A pass
// that enslaved the parent alone is exactly the defect, and it would satisfy
// any assertion phrased as "the member is in the VRF".
func TestBareRIMemberEnslavesItsVLANChildren9754(t *testing.T) {
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
	// The children are named by VLAN ID, as logicalUnitDeviceKey builds them
	// and as compiler_iface.go creates them.
	for _, vlanID := range []int{10, 50} {
		child := &netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        vlanDevName9754(vlanID),
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

	d.bindRoutingInstanceMembers(bareMemberCfg9754())

	vrfLink, err := netlink.LinkByName("vrf-blue")
	if err != nil {
		t.Fatalf("vrf-blue: %v", err)
	}
	for _, name := range []string{"ge-0-0-0", "ge-0-0-0.10", "ge-0-0-0.50"} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("%s absent: %v", name, err)
		}
		if l.Attrs().MasterIndex != vrfLink.Attrs().Index {
			t.Fatalf("#9754: %s has master index %d, want vrf-blue (%d). A bare member means EVERY "+
				"configured unit, and a tagged child left outside the VRF routes kernel-path traffic "+
				"in the DEFAULT instance — failing open to main, with FRR reading the same kernel "+
				"master for VRF membership",
				name, l.Attrs().MasterIndex, vrfLink.Attrs().Index)
		}
	}
}

func vlanDevName9754(vlanID int) string {
	switch vlanID {
	case 10:
		return "ge-0-0-0.10"
	case 50:
		return "ge-0-0-0.50"
	}
	return ""
}

// #9754: the resolution itself, without a kernel. The netns cell above proves
// the binds land; this pins WHICH devices each spelling claims, including the
// two readings that must NOT change.
func TestRIMemberLinuxNamesPerSpelling9754(t *testing.T) {
	for _, tc := range []struct {
		name   string
		member string
		want   []string
	}{
		{
			// The defect: a bare member means every configured unit.
			name:   "bare member claims the base and every unit",
			member: "ge-0/0/0",
			want:   []string{"ge-0-0-0", "ge-0-0-0.10", "ge-0-0-0.50"},
		},
		{
			// Must NOT fan UP to the base (#9063): the base row carries unit 0's
			// addresses, so binding it from a unit-1 reference would move unit
			// 0's prefix into unit 1's instance.
			name:   "unit reference claims exactly that unit",
			member: "ge-0/0/0.1",
			want:   []string{"ge-0-0-0.50"},
		},
		{
			name:   "unit 0 reference claims the vlan child it names",
			member: "ge-0/0/0.0",
			want:   []string{"ge-0-0-0.10"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := bareMemberCfg9754()
			got := riMemberLinuxNames(cfg, cfg.TunnelNameMap(), tc.member)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("position %d: got %v want %v", i, got, tc.want)
				}
			}
		})
	}
}

// #9754: a unit with NO vlan-id has no 802.1Q child of its own -- it IS the base
// netdev -- so the fan-down must not name the same device twice. Without the
// dedup the bind loop drives BindInterfaceToVRF twice on one link; harmless
// today because the call is idempotent, which is exactly why nothing else would
// notice the duplicate.
func TestBareMemberDoesNotNameTheBaseTwice9754(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0}, // no vlan-id: collapses onto the base device
		}},
	}
	got := riMemberLinuxNames(cfg, cfg.TunnelNameMap(), "ge-0/0/1")
	if len(got) != 1 || got[0] != "ge-0-0-1" {
		t.Fatalf("an untagged unit 0 is the base device; got %v want [ge-0-0-1]", got)
	}
}

// #9754 fix-ordering invariant, which the issue asks for explicitly: a device
// this pass enslaves into a VRF must NOT also appear in the default-instance
// next-table ingress set. A unit in a VRF that still receives default-instance
// `iif` rules is the inconsistency the fix could have introduced.
//
// Measured per spelling rather than asserted in general, because the two sets
// are built from DIFFERENT readings and only agree by construction:
//
//	ge-0/0/0    (stanza spelling)  binds base + both children; default set empty
//	ge-0-0-0    (linux spelling)   binds the base only;        default set holds both children
//	ge-0/0/0.1  (unit reference)   binds that child;           default set holds the other
//
// The middle row is a PRE-EXISTING split this change does not alter and does not
// repair: the base lands in the VRF while the tagged units keep default-instance
// rules. Making the linux spelling fan down too is the "resolve members
// independently of spelling" path the issue warns needs DefaultInstanceIngressIfaces
// changed in the same breath, and that reaches the next-table rules. Recorded in
// docs/log/9754.md rather than folded in here.
func TestBoundDevicesAreNotAlsoDefaultInstanceIngress9754(t *testing.T) {
	for _, member := range []string{"ge-0/0/0", "ge-0-0-0", "ge-0/0/0.1"} {
		t.Run(member, func(t *testing.T) {
			cfg := bareMemberCfg9754()
			cfg.RoutingInstances[0].Interfaces = []string{member}
			bound := make(map[string]struct{})
			for _, n := range riMemberLinuxNames(cfg, cfg.TunnelNameMap(), member) {
				bound[n] = struct{}{}
			}
			for _, iif := range routing.DefaultInstanceIngressIfaces(cfg) {
				if _, clash := bound[iif]; clash {
					t.Fatalf("%s is bound into a VRF by this pass AND listed as default-instance "+
						"next-table ingress; a unit cannot be in both", iif)
				}
			}
		})
	}
}

// #9754: the two spellings the SHIPPED configs actually use must resolve
// exactly as they did before this change. This is the evidence behind the
// judgement that no cluster smoke is owed: the change touches no cluster, VRRP,
// session-sync or failover code, AND the cluster config's own member resolves
// to the same single device it always did.
//
//	docs/ha-cluster-userspace.conf   interface gr-0/0/0.0   a tunnel unit ref
//	test/incus/xpf-test.conf         interface ge-0/0/2     bare, one untagged unit
//
// A tunnel member resolves to ONE device in either spelling: TunnelNameMap is
// keyed on unit refs, and a bare tunnel member's fan-down lands on the same
// device through that map and is deduped. Only a bare member on a port with
// TAGGED units resolves differently than before, and no config in the tree has
// one.
func TestShippedMemberSpellingsResolveUnchanged9754(t *testing.T) {
	t.Run("cluster config: tunnel unit ref", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"gr-0/0/0": {
				Name:   "gr-0/0/0",
				Tunnel: &config.TunnelConfig{Source: "10.0.0.1", Destination: "10.0.0.2"},
				Units:  map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
		}
		for _, member := range []string{"gr-0/0/0.0", "gr-0/0/0"} {
			got := riMemberLinuxNames(cfg, cfg.TunnelNameMap(), member)
			if len(got) != 1 || got[0] != "gr-0-0-0" {
				t.Fatalf("a tunnel member resolves to one device; %s gave %v", member, got)
			}
		}
	})

	t.Run("test VM config: bare member, one untagged unit", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.30.10/24"}},
			}},
		}
		got := riMemberLinuxNames(cfg, cfg.TunnelNameMap(), "ge-0/0/2")
		if len(got) != 1 || got[0] != "ge-0-0-2" {
			t.Fatalf("an untagged unit 0 collapses onto the base; got %v want [ge-0-0-2]", got)
		}
	})
}
