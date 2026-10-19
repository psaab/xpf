package cluster

import (
	"testing"
	"time"
)

// #15181: LocalDrainedSince is the drain-start evidence self-recovery
// uses to require that the kernel-roll lease it acts on postdates the
// current drain.

func TestLocalDrainedSinceEarliestDrainedRG15181(t *testing.T) {
	m := NewManager(0, 1)
	early := time.Unix(1_700_000_000, 0)
	late := early.Add(time.Hour)
	m.groups[0] = &RedundancyGroupState{GroupID: 0, State: StateSecondary, Weight: 0, ManualFailover: true, ManualFailoverAt: late}
	m.groups[1] = &RedundancyGroupState{GroupID: 1, State: StateSecondary, Weight: 0, ManualFailover: true, ManualFailoverAt: early}
	if got := m.LocalDrainedSince(); !got.Equal(early) {
		t.Fatalf("LocalDrainedSince = %v, want earliest %v", got, early)
	}
}

func TestLocalDrainedSinceZeroWhenNotFullyDrained15181(t *testing.T) {
	m := NewManager(0, 1)
	at := time.Unix(1_700_000_000, 0)
	m.groups[0] = &RedundancyGroupState{GroupID: 0, State: StateSecondary, Weight: 0, ManualFailover: true, ManualFailoverAt: at}
	m.groups[1] = &RedundancyGroupState{GroupID: 1, State: StatePrimary, Weight: 255}
	if got := m.LocalDrainedSince(); !got.IsZero() {
		t.Fatalf("LocalDrainedSince = %v, want zero when not fully drained", got)
	}
}

func TestLocalDrainedSinceZeroWhenStartUnknown15181(t *testing.T) {
	m := NewManager(0, 1)
	m.groups[0] = &RedundancyGroupState{GroupID: 0, State: StateSecondary, Weight: 0, ManualFailover: true}
	if got := m.LocalDrainedSince(); !got.IsZero() {
		t.Fatalf("LocalDrainedSince = %v, want zero when ManualFailoverAt is unset", got)
	}
	if got := NewManager(0, 1).LocalDrainedSince(); !got.IsZero() {
		t.Fatalf("LocalDrainedSince = %v, want zero with no RGs", got)
	}
}
