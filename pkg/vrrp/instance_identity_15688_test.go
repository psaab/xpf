package vrrp

import (
	"testing"
)

// #15688: a duplicate identity or RETH election-domain overlap must skip only
// the offending instance, not abort UpdateInstances for the whole node.

func TestUpdateInstancesDuplicateIdentitySkipsOnlyDuplicate15688(t *testing.T) {
	m := vrrpFamilyManager()
	defer stopManagerForTest(m)

	good := &Instance{Interface: "ge-0-0-0", Family: "inet", GroupID: 5, VirtualAddresses: []string{"10.0.0.1/24"}}
	dup := &Instance{Interface: "ge-0-0-0", Family: "inet", GroupID: 5, VirtualAddresses: []string{"10.0.0.2/24"}}
	other := &Instance{Interface: "ge-0-0-1", Family: "inet", GroupID: 5, VirtualAddresses: []string{"10.0.1.1/24"}}

	if err := m.UpdateInstances([]*Instance{good, dup, other}); err != nil {
		t.Fatalf("duplicate identity must not abort the whole batch: %v", err)
	}
	m.mu.RLock()
	_, haveGood := m.instances[instanceKey{iface: "ge-0-0-0", groupID: 5, family: "inet"}]
	_, haveOther := m.instances[instanceKey{iface: "ge-0-0-1", groupID: 5, family: "inet"}]
	n := len(m.instances)
	_, unbuilt := m.unbuiltDesired[instanceKey{iface: "ge-0-0-0", groupID: 5, family: "inet"}]
	m.mu.RUnlock()
	if !haveGood || !haveOther || n != 2 {
		t.Fatalf("expected first duplicate claimant and unrelated instance seated, got n=%d good=%v other=%v", n, haveGood, haveOther)
	}
	if !unbuilt {
		t.Fatal("rejected duplicate key must be recorded in unbuiltDesired")
	}
}

func TestUpdateInstancesRethOverlapSkipsOnlyOverlap15688(t *testing.T) {
	generic := &Instance{Interface: "ge-0-0-0", Family: "inet", GroupID: 101, VirtualAddresses: []string{"10.0.0.1/24"}}
	reth := &Instance{Interface: "ge-0-0-0", GroupID: 101, VirtualAddresses: []string{"10.0.0.254/24"}}
	other := &Instance{Interface: "ge-0-0-1", Family: "inet", GroupID: 5, VirtualAddresses: []string{"10.0.1.1/24"}}
	for _, desired := range [][]*Instance{{generic, reth, other}, {reth, generic, other}} {
		m := vrrpFamilyManager()
		if err := m.UpdateInstances(desired); err != nil {
			t.Fatalf("RETH overlap must not abort the whole batch (order %v): %v", desired[0].Family, err)
		}
		m.mu.RLock()
		n := len(m.instances)
		_, haveOther := m.instances[instanceKey{iface: "ge-0-0-1", groupID: 5, family: "inet"}]
		m.mu.RUnlock()
		stopManagerForTest(m)
		if n != 2 || !haveOther {
			t.Fatalf("expected overlapping pair reduced to one plus unrelated instance, got n=%d other=%v", n, haveOther)
		}
	}
}
