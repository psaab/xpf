package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// sync_nat_scope_fold_16826_test.go — #16826 sender leg: the #15176
// NAT-scope fold must name the logical VLAN unit, not its parent.
//
// Pre-fix stampNatScopeFold folded the logical child's ifindex with
// vlan 0, so `ge-0-0-2.80` truncated to `reth0` and the peer revalidated
// against the parent's interface/RI scope. The wired natScopeFoldFn folds
// the (parent, VLAN) pair instead. FAIL-ON-REVERT: reverting
// stampNatScopeFold to the unconditional vlan-0 fold makes the stamped
// value the parent fold and the first cell goes RED.

func TestStampNatScopeFoldUsesLogicalUnit_16826(t *testing.T) {
	ss := NewSessionSync(":0", ":0", nil)
	ss.SetZoneOwnership(ZoneRGMap{}, nil, func(ifindex uint32, vlan uint16) uint32 {
		if ifindex == 10 && vlan == 80 {
			return config.StableIfaceID("reth0.80")
		}
		if ifindex == 10 {
			return config.StableIfaceID("reth0")
		}
		return 0
	})
	ss.SetNatScopeFoldFn(func(ifindex int32) uint32 {
		if ifindex == 22 {
			return config.StableIfaceID("reth0.80")
		}
		return 0
	})
	if got := ss.StampNatScopeFoldForTesting(22); got != config.StableIfaceID("reth0.80") {
		t.Fatalf("scope fold = %d, want fold(reth0.80)=%d (parent fold %d revokes on the peer)",
			got, config.StableIfaceID("reth0.80"), config.StableIfaceID("reth0"))
	}
	if got := ss.StampNatScopeFoldForTesting(0); got != 0 {
		t.Fatalf("scope fold(0) = %d, want the 0 unknown sentinel", got)
	}
	if got := ss.StampNatScopeFoldForTesting(-3); got != 0 {
		t.Fatalf("scope fold(-3) = %d, want the 0 unknown sentinel", got)
	}
}

// Control: without the #16826 folder wired, the legacy vlan-0 fold is
// kept byte-identically (non-RETH-VLAN configs and unwired nodes).
func TestStampNatScopeFoldLegacyWithoutPairFolder_16826(t *testing.T) {
	ss := NewSessionSync(":0", ":0", nil)
	ss.SetZoneOwnership(ZoneRGMap{}, nil, func(ifindex uint32, vlan uint16) uint32 {
		if vlan != 0 {
			t.Errorf("legacy fold called with vlan %d, want 0", vlan)
		}
		if ifindex == 22 {
			return config.StableIfaceID("reth0")
		}
		return 0
	})
	if got := ss.StampNatScopeFoldForTesting(22); got != config.StableIfaceID("reth0") {
		t.Fatalf("legacy scope fold = %d, want fold(reth0)=%d", got, config.StableIfaceID("reth0"))
	}
}

// The stamped fold lands in stampInstallGenV4/V6 exactly as before.
func TestStampInstallGenCarriesNatScopePairFold_16826(t *testing.T) {
	ss := NewSessionSync(":0", ":0", nil)
	ss.SetZoneOwnership(ZoneRGMap{}, nil, func(uint32, uint16) uint32 { return 0 })
	ss.SetNatScopeFoldFn(func(ifindex int32) uint32 {
		if ifindex == 22 {
			return config.StableIfaceID("reth0.80")
		}
		return 0
	})
	val := &dataplane.SessionValue{NatScopeIfindex: 22}
	ss.stampInstallGenV4(dataplane.SessionKey{}, val)
	if val.NatScopeFold != config.StableIfaceID("reth0.80") {
		t.Fatalf("v4 NatScopeFold = %d, want fold(reth0.80)=%d", val.NatScopeFold, config.StableIfaceID("reth0.80"))
	}
	val6 := &dataplane.SessionValueV6{NatScopeIfindex: 22}
	ss.stampInstallGenV6(dataplane.SessionKeyV6{}, val6)
	if val6.NatScopeFold != config.StableIfaceID("reth0.80") {
		t.Fatalf("v6 NatScopeFold = %d, want fold(reth0.80)=%d", val6.NatScopeFold, config.StableIfaceID("reth0.80"))
	}
}
