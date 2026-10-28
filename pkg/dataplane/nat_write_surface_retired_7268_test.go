package dataplane

import (
	"reflect"
	"strings"
	"testing"
)

// TestRetiredNATWriteSurfaceStaysOff is the precondition guard for #7268.
//
// The deletion rests on a specific argument, and it is NOT "nothing calls
// these". It is that the maps they wrote -- snat_rules, snat_rules_v6,
// static_nat_v4, static_nat_v6, nptv6_rules, nat_pool_*, snat_egress_ips and
// nat64_* -- are not declared by the AF_XDP shim (userspace-xdp/src/lib.rs), so
// on the deployed dataplane there is nowhere for the write to land even if a
// caller returned. #6420 removed the record construction that used to call
// them; a future change could reintroduce one, and it would have to re-add a
// method here to do it.
//
// So this asserts the METHOD SET, by reflection over the interface rather than
// by scanning source. A source scan can be satisfied by a comment that happens
// to contain the name; a reflection assertion cannot.
//
// #17229: dnat_table/dnat_table_v6 joined this list — the shim no longer
// declares them and no reader remains, so their writers are retired too.
// #7804 Q2, answered here rather than left open in the issue.
//
// The issue asks, of the three stale sweepers that DO have production callers
// (DeleteStaleZonePairPolicies -> compiler.go, ZeroStaleScreenConfigs ->
// compiler_iface.go, ZeroStaleFilterConfigs -> compiler_filter.go), whether
// writing to a map no loaded program reads is work worth doing on the commit
// path at all.
//
// Measured: zone_pair_policies, screen_configs and filter_configs are each
// declared ZERO times in userspace-xdp/src/lib.rs, so those writes are inert
// for the same reason the retired ones were. But the cost is already nil, and
// that is the part the issue could not see: every one of them opens with
// lookupMapLocked, which reads m.maps -- populated only by
// publishShimRegistryLocked from the shim's own collection. On the deployed
// userspace dataplane the name is absent, `present` is false, and the function
// returns before constructing a key. The commit-path cost is one
// mutex-guarded map miss, not a write.
//
// So the answer is: not worth removing for cost, and removing them is NOT the
// same change as this one. These have live callers, so retiring them edits the
// COMPILE PATH rather than deleting an unreferenced declaration -- a different
// blast radius and its own review. Deliberately out of scope here.

func TestRetiredNATWriteSurfaceStaysOff(t *testing.T) {
	retired := []string{
		"SetSNATRule", "SetSNATRuleV6", "ClearSNATRules", "ClearSNATRulesV6",
		"SetStaticNATEntryV4", "SetStaticNATEntryV6", "ClearStaticNATEntries",
		"SetNPTv6Rule", "DeleteStaleNPTv6",
		"SetNATPoolConfig", "SetNATPoolIPV4", "SetNATPoolIPV6",
		"ClearNATPoolConfigs", "ClearNATPoolIPs",
		"SetSNATEgressIP", "ClearSNATEgressIPs",
		"SetNAT64Config", "SetNAT64Count", "ClearNAT64Configs",
		"ClearDNATStatic", "ClearDNATStaticV6",
		"DeleteStaleSNATRules", "DeleteStaleSNATRulesV6",
		"SetDNATEntry", "SetDNATEntryV6", "DeleteDNATEntry", "DeleteDNATEntryV6",
		"DeleteStaleDNATStatic", "DeleteStaleDNATStaticV6",
		// #7804: the same argument, measured again for the two stale sweepers
		// #7268 left behind. nat64_configs, nat64_prefix_map, nat_pool_configs
		// and nat_pool_ips_v4/v6 are each declared 0 times in
		// userspace-xdp/src/lib.rs -- so these wrote to maps that do not exist on the deployed
		// dataplane, and they had no production caller to write from either.
		"DeleteStaleNAT64", "ZeroStaleNATPoolConfigs",
	}

	dpType := reflect.TypeOf((*DataPlane)(nil)).Elem()

	// ANTI-VACUITY FLOOR. If the reflection ever stopped reaching the real
	// interface -- a rename, a build tag, a moved type -- every membership
	// check below would pass against an empty method set and this test would
	// certify the retirement while measuring nothing.
	if dpType.NumMethod() < 40 {
		t.Fatalf("DataPlane reflects %d methods; the scan is not reaching the real "+
			"interface, so a clean result here would certify nothing", dpType.NumMethod())
	}

	for _, name := range retired {
		if _, ok := dpType.MethodByName(name); ok {
			t.Errorf("DataPlane declares %s again. The maps this wrote are not declared "+
				"by the AF_XDP shim, so re-adding the method means re-adding a write with "+
				"nowhere to land -- if a NAT record constructor came back, it needs a live "+
				"map, not this surface (#7268)", name)
		}
	}

	// POSITIVE CONTROL: a live writer must still be declared, so the loop
	// above cannot pass because names are misspelled or the interface empty.
	for _, name := range []string{"SetSessionV4", "DeleteSession"} {
		if _, ok := dpType.MethodByName(name); !ok {
			t.Errorf("DataPlane no longer declares live writer %s (#7268 control)", name)
		}
	}
}

// TestRetiredNATWriteSurfaceGoneFromManager mirrors the check on the concrete
// eBPF writer. The interface and the implementation are separate surfaces: a
// method removed from the interface but left on *Manager is still reachable by
// anyone holding the concrete type, which is exactly how the retired writers
// would come back into use.
func TestRetiredNATWriteSurfaceGoneFromManager(t *testing.T) {
	mType := reflect.TypeOf(&Manager{})
	if mType.NumMethod() < 100 {
		t.Fatalf("*Manager reflects %d methods; the scan is not reaching the real type",
			mType.NumMethod())
	}
	for i := 0; i < mType.NumMethod(); i++ {
		name := mType.Method(i).Name
		switch {
		case strings.HasPrefix(name, "SetSNATRule"),
			strings.HasPrefix(name, "SetStaticNATEntry"),
			strings.HasPrefix(name, "SetNPTv6"),
			strings.HasPrefix(name, "SetNATPool"),
			strings.HasPrefix(name, "SetSNATEgress"),
			strings.HasPrefix(name, "SetNAT64"),
			strings.HasPrefix(name, "DeleteStaleSNATRules"),
			strings.HasPrefix(name, "DeleteStaleNPTv6"):
			t.Errorf("*Manager declares %s again — the retired eBPF NAT writer is back "+
				"on the concrete type even if the interface no longer names it (#7268)", name)
		}
	}
}
