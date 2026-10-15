package cluster

import (
	"strings"
	"testing"
)

func TestSyncStatsSnapshotIncludesSuppressionAndAuthEvictionCounts13230(t *testing.T) {
	ss := &SessionSync{}
	ss.stats.PreKeyAuthEvictions.Add(2)
	ss.stats.DeletesSuppressedPeerIncapable.Add(3)
	ss.stats.DeletesSuppressedPurgeRetirement.Add(4)

	got := ss.Stats()
	if got.PreKeyAuthEvictions != 2 {
		t.Errorf("PreKeyAuthEvictions = %d, want 2", got.PreKeyAuthEvictions)
	}
	if got.DeletesSuppressedPeerIncapable != 3 {
		t.Errorf("DeletesSuppressedPeerIncapable = %d, want 3", got.DeletesSuppressedPeerIncapable)
	}
	if got.DeletesSuppressedPurgeRetirement != 4 {
		t.Errorf("DeletesSuppressedPurgeRetirement = %d, want 4", got.DeletesSuppressedPurgeRetirement)
	}
}

func TestForeignSourceHeartbeatDropsVisibleInStatistics13230(t *testing.T) {
	m := NewManager(0, 1)
	receiver := &heartbeatReceiver{}
	receiver.foreignSrc.Add(2)
	m.mu.Lock()
	m.hbReceiver = receiver
	m.mu.Unlock()

	for name, output := range map[string]string{
		"statistics":    m.FormatStatistics(),
		"control plane": m.FormatControlPlaneStatistics(),
	} {
		if !strings.Contains(output, "Foreign-source heartbeats dropped: 2") {
			t.Errorf("%s output does not expose foreign-source drops:\n%s", name, output)
		}
	}
}
