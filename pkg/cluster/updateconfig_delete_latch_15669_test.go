package cluster

import (
	"testing"
	"time"
)

// #15669: deleting heartbeat-interval, heartbeat-threshold,
// control-interface, or a redundancy group's gratuitous-arp-count must
// revert the running manager to the defaults / empty value on the next
// UpdateConfig. Before the fix each of those knobs was only written when
// the new config carried a positive / non-empty value, so a deletion
// latched the previously committed value forever: the heartbeat kept the
// old cadence, the node stayed in cluster (readiness-gated) mode after
// its control interface was removed, and the old GARP burst count kept
// applying to a group that no longer authored one.
//
// Fail-on-revert: drop any one of the else/delete arms in UpdateConfig and
// the matching assertion below goes RED (the latched value survives the
// unset apply). The changed-nonzero control at the end pins the other
// direction: a live heartbeat whose committed timing was just reverted
// to defaults must register as diverged so ApplyCommittedHeartbeatTiming
// (#7164) restarts it — deleting the stanza must reach the wire too.
func TestUpdateConfigUnsetRevertsHeartbeatControlGARP15669(t *testing.T) {
	m := NewManager(0, 1)

	set := makeConfig(garpRG(1, 7))
	set.HeartbeatInterval = 250
	set.HeartbeatThreshold = 9
	set.ControlInterface = "em0"
	m.UpdateConfig(set)
	drainEvents(m, 4)

	if m.hbInterval != 250*time.Millisecond {
		t.Fatalf("after set: hbInterval = %v, want 250ms", m.hbInterval)
	}
	if m.hbThreshold != 9 {
		t.Fatalf("after set: hbThreshold = %d, want 9", m.hbThreshold)
	}
	if m.controlInterface != "em0" {
		t.Fatalf("after set: controlInterface = %q, want %q", m.controlInterface, "em0")
	}
	if got, ok := m.garpCounts[1]; !ok || got != 7 {
		t.Fatalf("after set: garpCounts[1] = (%d, present=%v), want (7, true)", got, ok)
	}

	// --- Delete every knob: same RG, no gratuitous-arp-count, and the
	// cluster stanza carries no heartbeat/control values. ---
	unset := makeConfig(garpRG(1, 0))
	m.UpdateConfig(unset)
	drainEvents(m, 4)

	if m.hbInterval != DefaultHeartbeatInterval {
		t.Errorf("after unset: hbInterval = %v, want default %v (deleted heartbeat-interval latched)",
			m.hbInterval, DefaultHeartbeatInterval)
	}
	if m.hbThreshold != DefaultHeartbeatThreshold {
		t.Errorf("after unset: hbThreshold = %d, want default %d (deleted heartbeat-threshold latched)",
			m.hbThreshold, DefaultHeartbeatThreshold)
	}
	if m.controlInterface != "" {
		t.Errorf("after unset: controlInterface = %q, want %q (deleted control-interface latched)",
			m.controlInterface, "")
	}
	if got, ok := m.garpCounts[1]; ok {
		t.Errorf("after unset: garpCounts[1] = %d, want absent so the default burst applies "+
			"(deleted gratuitous-arp-count latched)", got)
	}

	// --- Control: a changed nonzero timing still registers as diverged
	// from a running heartbeat, and so does the reverted-to-default
	// timing after a deletion. Both directions must reach the wire via
	// ApplyCommittedHeartbeatTiming. ---
	changed := makeConfig(garpRG(1, 0))
	changed.HeartbeatInterval = 300
	changed.HeartbeatThreshold = 3
	m.UpdateConfig(changed)
	drainEvents(m, 4)
	installReceiverWithTiming(m, DefaultHeartbeatInterval, DefaultHeartbeatThreshold)
	if !m.heartbeatTimingDivergedLocked() {
		t.Error("changed nonzero timing (300ms/3) vs live (default) must diverge so the heartbeat restarts")
	}

	m.UpdateConfig(unset)
	drainEvents(m, 4)
	// The fake receiver still runs the defaults; the deletion reverted
	// the committed values to those same defaults, so now they agree.
	if m.heartbeatTimingDivergedLocked() {
		t.Error("after deletion revert, committed defaults vs live defaults must not diverge")
	}
	// Point the live receiver at the pre-deletion timing: the reverted
	installReceiverWithTiming(m, 300*time.Millisecond, 3)
	if !m.heartbeatTimingDivergedLocked() {
		t.Error("deleted timing reverted to defaults vs live 300ms/3 must diverge so the restart reaches the wire")
	}

	// Re-setting after a deletion must still take effect (the revert is
	// a default, not a latch in the other direction).

	m.UpdateConfig(set)
	drainEvents(m, 4)
	if m.hbInterval != 250*time.Millisecond || m.hbThreshold != 9 || m.controlInterface != "em0" {
		t.Errorf("after re-set: hbInterval=%v hbThreshold=%d controlInterface=%q, want 250ms/9/em0",
			m.hbInterval, m.hbThreshold, m.controlInterface)
	}
	if got, ok := m.garpCounts[1]; !ok || got != 7 {
		t.Errorf("after re-set: garpCounts[1] = (%d, present=%v), want (7, true)", got, ok)
	}
}
