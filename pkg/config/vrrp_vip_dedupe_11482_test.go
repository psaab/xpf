package config

import "testing"

func TestVRRPVIPCountDeduplicatesCanonicalIdentities(t *testing.T) {
	vips := make([]string, 0, MaxVRRPVirtualAddressesIPv6+1)
	for _, vip := range vipCountV6(MaxVRRPVirtualAddressesIPv6) {
		vips = append(vips, vip+"/64")
	}
	vips = append(vips, "2001:0DB8:0:0:0:0:0:2/64")

	if err := vrrpVIPCountErr("test VRRP group", vips); err != nil {
		t.Fatalf("cap-sized canonical VIP set plus a spelling alias must fit: %v", err)
	}
}

func TestCompileVRRPGroupDeduplicatesCanonicalVIPs(t *testing.T) {
	const base = "set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64 " +
		"vrrp-group 1 virtual-address "
	lines := make([]string, 0, MaxVRRPVirtualAddressesIPv6+1)
	for _, vip := range vipCountV6(MaxVRRPVirtualAddressesIPv6) {
		lines = append(lines, base+vip+"/64")
	}
	lines = append(lines, base+"2001:0DB8:0:0:0:0:0:2/64")
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig() rejected cap-sized canonical VIP set: %v", err)
	}
	got, found := compiledGroupVIPCount(cfg)
	if !found {
		t.Fatal("fixture produced no VRRP group")
	}
	if got != MaxVRRPVirtualAddressesIPv6 {
		t.Fatalf("compiled VRRP group has %d VIPs, want %d canonical identities",
			got, MaxVRRPVirtualAddressesIPv6)
	}
}

func TestVRRPVIPCountStillRejectsUniqueOverCapacity(t *testing.T) {
	vips := vipCountV6(MaxVRRPVirtualAddressesIPv6 + 1)
	for i := range vips {
		vips[i] += "/64"
	}
	if err := vrrpVIPCountErr("test VRRP group", vips); err == nil {
		t.Fatal("distinct over-capacity IPv6 VIPs unexpectedly fit")
	}
}

func TestUntaggedRETHCapacityDeduplicatesAcrossUnits(t *testing.T) {
	vips := vipCountV6(MaxVRRPVirtualAddressesIPv6)
	for i := range vips {
		vips[i] += "/64"
	}
	alias := "2001:0DB8:0:0:0:0:0:2/64"
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"reth0": {
			RedundancyGroup: 1,
			Units: map[int]*InterfaceUnit{
				0: {Addresses: vips},
				1: {Addresses: []string{alias}},
			},
		},
	}}}
	if err := validateVRRPVIPCountStrict(cfg); err != nil {
		t.Fatalf("untagged RETH cap-sized canonical set plus alias must fit: %v", err)
	}
}
