package daemon

import (
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// #10174: the daemon's Linux-name matching layer must apply the #8829
// precedent to a BARE cross-spelled routing-instance member. A unit member
// already uses LookupInterfaceByLinuxName (#10151), but a bare member is
// deliberately outside that helper's normal placement rule: without a
// daemon-owned whole-member alias, only the parent is returned and VLAN
// children remain in the default VRF.
func TestRIBareCrossSpelledMemberFansDown10174(t *testing.T) {
	want := []string{"ge-0-0-0", "ge-0-0-0.10", "ge-0-0-0.50"}
	for _, tc := range []struct {
		stanza string
		member string
	}{
		{"ge-0/0/0", "ge-0-0-0"},
		{"ge-0-0-0", "ge-0/0/0"},
	} {
		t.Run(tc.stanza+"/"+tc.member, func(t *testing.T) {
			cfg := spellingCfg9815(tc.stanza)
			got := riMemberLinuxNames(cfg, cfg.TunnelNameMap(), tc.member)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("#10174: stanza %q bare member %q binds %v, want %v",
					tc.stanza, tc.member, got, want)
			}
			if got := riMemberLinuxName(cfg, cfg.TunnelNameMap(), tc.member); got != want[0] {
				t.Fatalf("#10174: stanza %q bare member %q singular binds %q, want %q",
					tc.stanza, tc.member, got, want[0])
			}
		})
	}
}

// #10174: both spelling directions must drive the real kernel bind pass. A
// bare member claims the parent plus every configured unit; the VLAN children
// are the observable acceptance surface and the parent assertion preserves
// the whole-port semantics from #9754. The unit-reference no-fan-up rule from
// #9063/#9815 is covered by the existing unit matrix.
//
// Run under `unshare -rn`; the cell skips when CAP_NET_ADMIN or the VRF/VLAN
// kernel support is unavailable.
func TestBareCrossSpelledMemberEnslavesVLANChildrenInKernel10174(t *testing.T) {
	for _, tc := range []struct {
		stanza string
		member string
	}{
		{"ge-0/0/0", "ge-0-0-0"},
		{"ge-0-0-0", "ge-0/0/0"},
	} {
		t.Run(tc.stanza+"/"+tc.member, func(t *testing.T) {
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
				child := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{
					Name: name, ParentIndex: live.Attrs().Index,
				}, VlanId: vlanID}
				if err := netlink.LinkAdd(child); err != nil {
					t.Skipf("cannot create an 802.1Q child in this netns: %v", err)
				}
				if err := netlink.LinkSetUp(child); err != nil {
					t.Fatalf("%s up: %v", name, err)
				}
			}
			rt, err := routing.New()
			if err != nil {
				t.Fatalf("routing.New: %v", err)
			}
			t.Cleanup(func() { _ = rt.Close() })
			d := &Daemon{routing: rt, linkByNameFn: netlink.LinkByName}
			cfg := spellingCfg9815(tc.stanza)
			cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
				Name: "blue", InstanceType: "vrf", TableID: 100,
				Interfaces: []string{tc.member},
			}}
			d.bindRoutingInstanceMembers(cfg)
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
					t.Fatalf("#10174: stanza %q bare member %q left %s with master index %d, want vrf-blue (%d)",
						tc.stanza, tc.member, name, l.Attrs().MasterIndex, vrfLink.Attrs().Index)
				}
			}
		})
	}
}
