package config

import (
	"strings"
	"testing"
)

// Sub-96 mapped VIP (::ffff:10.0.0.1/95) through the commit-gate family
// (#17150 round 2). There is no v4 prefix equivalent for a sub-96 mapped
// prefix, so ParseVRRPVIP returns the v4 host identity (10.0.0.1/32).
// The commit gates must therefore classify it exactly as they classify
// the plain v4 host: inet family, contained by a v4 unit subnet, and
// colliding with a plain 10.0.0.1 claim in another group. A kept-mapped
// parse would make the counter inet6 while these gates (which branch on
// vrrpVIPHostIP(...).To4()) already said inet — the split this pins.
//
// FAIL-ON-REVERT: restoring the kept-mapped sub-96 branch in
// unmapVRRPMappedPrefix makes the cross-group collision disappear (the
// /95 claim keys inet6/::ffff:10.0.0.1 while the plain claim keys
// inet/10.0.0.1) and the CompileConfig below commits — RED.

func TestMappedSub96CommitGateFamily17150(t *testing.T) {
	const vip95 = "::ffff:10.0.0.1/95"

	// (a1) Host helper + family derivation: the gate-facing helpers see
	// the v4 host, in the inet family.
	if ip := vrrpVIPHostIP(vip95); ip == nil || ip.To4() == nil || ip.String() != "10.0.0.1" {
		t.Fatalf("vrrpVIPHostIP(%q) = %v, want IPv4 host 10.0.0.1", vip95, ip)
	}
	if fam := vrrpFamilyOfAddrs([]string{vip95}); fam != "inet" {
		t.Errorf("vrrpFamilyOfAddrs(%q) = %q, want inet", vip95, fam)
	}
	if n4, n6 := countVRRPVIPFamilies([]string{vip95}); n4 != 1 || n6 != 0 {
		t.Errorf("countVRRPVIPFamilies(%q) = (%d,%d), want (1,0) — counter and gates must agree inet", vip95, n4, n6)
	}
	if err := vrrpVIPEmptyErr("test", []string{vip95}); err != nil {
		t.Errorf("vrrpVIPEmptyErr(%q) = %v, want nil (advertisable v4 host)", vip95, err)
	}

	// (a2) Subnet gate family: a /95 VIP under a v4-only unit must be
	// checked against the v4 subnets and PASS (10.0.0.1 is inside
	// 10.0.0.2/24's subnet). Direct validator call so the family branch
	// is exercised without schema family routing masking it.
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*InterfaceUnit{
			0: {
				Addresses: []string{"10.0.0.2/24"},
				VRRPGroups: map[string]*VRRPGroup{
					"10.0.0.2/24_grp1": {ID: 1, VirtualAddresses: []string{vip95}},
				},
			},
		}},
	}}}
	warns, err := validateVRRPVirtualAddressSubnet(cfg, false)
	if err != nil {
		t.Fatalf("validateVRRPVirtualAddressSubnet(/95 in v4 subnet) = %v, want nil (inet containment)", err)
	}
	if len(warns) != 0 {
		t.Errorf("validateVRRPVirtualAddressSubnet(/95) warnings = %v, want none", warns)
	}
	// Control: the same /95 VIP under a v6-only unit must REJECT as
	// cross-family inet — proving the gate took the inet branch, not a
	// silent skip (a nil ip would have continued without error).
	cfg6 := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*InterfaceUnit{
			0: {
				Addresses: []string{"2001:db8::2/64"},
				VRRPGroups: map[string]*VRRPGroup{
					"2001:db8::2/64_grp1": {ID: 1, VirtualAddresses: []string{vip95}},
				},
			},
		}},
	}}}
	if _, err := validateVRRPVirtualAddressSubnet(cfg6, false); err == nil || !strings.Contains(err.Error(), "family inet subnet") {
		t.Errorf("validateVRRPVirtualAddressSubnet(/95 under v6-only unit) = %v, want family inet subnet reject", err)
	}

	// (a3) Cross-group claim: /95 in group 1 and plain 10.0.0.1/24 in
	// group 2 on the same interface are ONE v4 host claimed by two
	// elections — strict commit must reject. Authored under family
	// inet6 because the schema's inet validator rejects a mapped CIDR
	// (To4() != nil); the lenient/runtime spelling reaches the gates
	// exactly as here.
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::2/64 vrrp-group 1 virtual-address " + vip95,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 vrrp-group 2 virtual-address 10.0.0.1/24",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted /95 + plain 10.0.0.1/24 claimed by two groups; want cross-group reject (same v4 host)")
	} else if !strings.Contains(err.Error(), "10.0.0.1") {
		t.Errorf("cross-group reject must name the v4 host; got: %v", err)
	}
}
