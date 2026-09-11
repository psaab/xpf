package vrrp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9721, the binding half. For a VRRP-backed RETH with vlan-tagging,
// CollectRethInstances binds an addressed unit that has no vlan-id to the
// member's VLAN PARENT device, and a tagged unit to its sub-interface.
//
// The render half is pkg/dataplane's reth_vlan_untagged_unit_9721_test.go. It
// asserts the 169.254 advert source on exactly these device names: `ge-0-0-2`
// for unit 0 and `ge-0-0-2.80` for unit 80. pkg/dataplane cannot import this
// package (pkg/vrrp -> pkg/cluster -> pkg/dataplane), so the pairing is held
// from both sides on the NAME. If the collector moves an instance to another
// device, this cell goes red; if the render moves the source, that one does.
func TestRethUntaggedUnitInstanceBindsToTheVLANParent_9721(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-9721",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 2",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 0 family inet address 172.16.50.8/24",
		"set interfaces reth0 unit 80 vlan-id 80",
		"set interfaces reth0 unit 80 family inet address 172.16.80.8/24",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile of the legacy-mode RETH fixture: %v", err)
	}

	boundTo := map[string]string{} // VIP -> instance interface
	for _, inst := range CollectRethInstances(cfg, nil) {
		for _, vip := range inst.VirtualAddresses {
			boundTo[vip] = inst.Interface
		}
	}
	for vip, want := range map[string]string{
		"172.16.50.8/24": "ge-0-0-2",    // unit 0, no vlan-id: the VLAN parent
		"172.16.80.8/24": "ge-0-0-2.80", // unit 80: its own sub-interface
	} {
		if got := boundTo[vip]; got != want {
			t.Errorf("RETH VRRP instance for %s is bound to %q, want %q: that is the device "+
				"pkg/dataplane gives the 169.254 advert source (instances=%v)", vip, got, want, boundTo)
		}
	}
}
