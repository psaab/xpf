package vrrp

import (
	"net"
	"testing"
	"time"
)

// #14406: ForceRGMaster must refuse during sync-hold. forcePreemptOnce
// bypasses the Preempt=false the hold installed, so forcing while held
// preempts before bulk session sync. After release the force proceeds.
// RED on revert: drop the InSyncHold guard in ForceRGMaster.
func TestForceRGMasterRefusedDuringSyncHold14406(t *testing.T) {
	m := NewManager()
	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   false,
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)
	vi.setState(StateBackup)
	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}
	m.mu.Unlock()

	m.SetSyncHold(time.Hour)
	defer m.ReleaseSyncHold()
	m.ForceRGMaster(1) // RG 1 -> VRID 101

	vi.mu.RLock()
	forced := vi.forcePreemptOnce
	vi.mu.RUnlock()
	if forced {
		t.Fatal("ForceRGMaster during sync-hold must not set forcePreemptOnce (#14406)")
	}
	select {
	case <-vi.preemptNowCh:
		t.Fatal("ForceRGMaster during sync-hold must not signal preemptNow (#14406)")
	default:
	}

	m.ReleaseSyncHold()
	m.ForceRGMaster(1)
	vi.mu.RLock()
	forced = vi.forcePreemptOnce
	vi.mu.RUnlock()
	if !forced {
		t.Fatal("ForceRGMaster after ReleaseSyncHold must set forcePreemptOnce")
	}
	select {
	case <-vi.preemptNowCh:
	default:
		t.Fatal("ForceRGMaster after ReleaseSyncHold must signal preemptNow")
	}
}
