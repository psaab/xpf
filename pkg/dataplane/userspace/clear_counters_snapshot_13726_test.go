package userspace

import "testing"

// #13726: Manager.Status() and Manager.CachedStatus() return m.lastStatus by
// value, but ProcessStatus's counter slices are shared with the manager. The
// no-helper branches of clearHelperPolicyCountersLocked /
// clearHelperNATCountersLocked used to zero Packets/Bytes in place, mutating
// every previously handed-out snapshot (and racing readers of it). The zone /
// flood twins already replace their slice (m.lastStatus.ZoneTrafficCounters =
// nil). The policy / NAT clears must likewise install a fresh slice so earlier
// snapshots keep their pre-clear values while the live cache reads zero.
func TestClearHelperCountersDoNotMutateHandedOutStatus13726(t *testing.T) {
	m := New()
	m.proc = nil // no live helper: exercise the direct-cache clear branches
	m.lastStatus = ProcessStatus{
		PID: 4242,
		PolicyRuleCounters: []PolicyRuleCounterStatus{
			{RuleID: "lan->wan/allow-web", Packets: 7, Bytes: 700},
		},
		NATRuleCounters: []NATRuleCounterStatus{
			{CounterID: 1, Packets: 9, Bytes: 900},
		},
	}

	// Status() and CachedStatus() expose ProcessStatus by value, so its slices
	// share backing storage with the manager cache.
	snap := m.lastStatus

	m.mu.Lock()
	polErr := m.clearHelperPolicyCountersLocked()
	natErr := m.clearHelperNATCountersLocked()
	m.mu.Unlock()
	if polErr != nil {
		t.Fatalf("clearHelperPolicyCountersLocked: %v", polErr)
	}
	if natErr != nil {
		t.Fatalf("clearHelperNATCountersLocked: %v", natErr)
	}

	// The previously handed-out snapshot must be untouched by the clear.
	if got := snap.PolicyRuleCounters[0]; got.Packets != 7 || got.Bytes != 700 {
		t.Fatalf("handed-out policy snapshot mutated by clear = %+v, want packets=7 bytes=700", got)
	}
	if got := snap.NATRuleCounters[0]; got.Packets != 9 || got.Bytes != 900 {
		t.Fatalf("handed-out NAT snapshot mutated by clear = %+v, want packets=9 bytes=900", got)
	}

	// The live cache must read zeroed counters with identities preserved.
	if got := m.lastStatus.PolicyRuleCounters[0]; got.RuleID != "lan->wan/allow-web" || got.Packets != 0 || got.Bytes != 0 {
		t.Fatalf("cached policy counter after clear = %+v, want rule preserved, zero packets/bytes", got)
	}
	if got := m.lastStatus.NATRuleCounters[0]; got.CounterID != 1 || got.Packets != 0 || got.Bytes != 0 {
		t.Fatalf("cached NAT counter after clear = %+v, want id preserved, zero packets/bytes", got)
	}
}
