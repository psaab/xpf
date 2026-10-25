package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// manager_nat_scope_logical_16826_test.go — #16826 receiver leg: on
// import, the NAT-scope fold -> (parent, VLAN) must land on this node's
// LOGICAL unit ifindex, so the helper revalidates `from interface
// reth0.80` instead of the parent.
//
// FAIL-ON-REVERT: reverting fillSessionSyncValue to `NatScopeIfindex =
// parent ifindex` makes the tagged cell read 20 (the parent) and goes RED.

func natScopeManager16826() *Manager {
	m := &Manager{
		bpfShim: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
			{Name: "ge-7/0/2", Ifindex: 20},
			{Name: "reth0.80", Ifindex: 22, ParentIfindex: 20, VLANID: 80},
			{Name: "reth0.50", Ifindex: 21, ParentIfindex: 20, VLANID: 50},
		}},
	}
	m.SetIngressFoldResolver(func(fold uint32) (uint32, uint16, bool) {
		switch fold {
		case 0xF01D0080:
			return 20, 80, true
		case 0xF01D0050:
			return 20, 50, true
		case 0xF01D0000:
			return 20, 0, true
		}
		return 0, 0, false
	})
	return m
}

func TestNatScopeFoldResolvesToLogicalUnit_16826(t *testing.T) {
	m := natScopeManager16826()
	val := &dataplane.SessionValue{NatScopeFold: 0xF01D0080}
	req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, val)
	if req.NatScopeIfindex != 22 {
		t.Fatalf("NatScopeIfindex = %d, want 22 (ge-7-0-2.80 logical unit), not the parent 20", req.NatScopeIfindex)
	}
	val50 := &dataplane.SessionValue{NatScopeFold: 0xF01D0050}
	if req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, val50); req.NatScopeIfindex != 21 {
		t.Fatalf("vlan50 NatScopeIfindex = %d, want 21", req.NatScopeIfindex)
	}
}

func TestNatScopeFoldResolvesToLogicalUnitV6_16826(t *testing.T) {
	m := natScopeManager16826()
	val := &dataplane.SessionValueV6{NatScopeFold: 0xF01D0080}
	req := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{Protocol: 6}, val)
	if req.NatScopeIfindex != 22 {
		t.Fatalf("v6 NatScopeIfindex = %d, want 22, not the parent 20", req.NatScopeIfindex)
	}
}

// Controls: an untagged fold lands on the parent itself; an unknown pair
// and a zero fold leave the scope unset (the #15176 no-scope keep), never
// naming the parent for a tagged scope.
func TestNatScopeFoldControls_16826(t *testing.T) {
	m := natScopeManager16826()
	untagged := &dataplane.SessionValue{NatScopeFold: 0xF01D0000}
	if req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, untagged); req.NatScopeIfindex != 20 {
		t.Fatalf("untagged NatScopeIfindex = %d, want the parent 20 itself", req.NatScopeIfindex)
	}
	unknown := &dataplane.SessionValue{NatScopeFold: 0xDEAD}
	if req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, unknown); req.NatScopeIfindex != 0 {
		t.Fatalf("unknown-fold NatScopeIfindex = %d, want 0 (no scope recorded)", req.NatScopeIfindex)
	}
	zero := &dataplane.SessionValue{}
	if req := m.buildSessionSyncRequestV4("upsert", dataplane.SessionKey{Protocol: 6}, zero); req.NatScopeIfindex != 0 {
		t.Fatalf("zero-fold NatScopeIfindex = %d, want 0", req.NatScopeIfindex)
	}
}
