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
	ss.stats.DeletesSuppressedScopedPolicy.Add(5)
	ss.stats.InstallsSuppressedNoPeerInstallTable.Add(6)

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
	if got.DeletesSuppressedScopedPolicy != 5 {
		t.Errorf("DeletesSuppressedScopedPolicy = %d, want 5", got.DeletesSuppressedScopedPolicy)
	}
	if got.InstallsSuppressedNoPeerInstallTable != 6 {
		t.Errorf("InstallsSuppressedNoPeerInstallTable = %d, want 6", got.InstallsSuppressedNoPeerInstallTable)
	}
}

func TestSyncSuppressionCountersVisibleInStatistics13230(t *testing.T) {
	ss := &SessionSync{}
	ss.stats.PreKeyAuthEvictions.Add(2)
	ss.stats.DeletesSuppressedPeerIncapable.Add(3)
	ss.stats.DeletesSuppressedPurgeRetirement.Add(4)
	ss.stats.DeletesSuppressedScopedPolicy.Add(5)
	ss.stats.InstallsSuppressedNoPeerInstallTable.Add(6)

	m := NewManager(0, 1)
	m.SetSyncStats(ss)
	information := m.FormatInformation()
	for _, want := range []string{
		"Pre-key authentication evictions: 2",
		"Deletes suppressed for incapable peer: 3",
		"Purge-retirement deletes suppressed: 4",
		"Scoped-policy deletes suppressed: 5",
		"Installs suppressed (peer lacks install-table support): 6",
	} {
		if !strings.Contains(information, want) {
			t.Errorf("FormatInformation does not expose %q:\n%s", want, information)
		}
	}

	statistics := m.FormatStatistics()
	for _, want := range []string{
		"Pre-key auth evictions",
		"Deletes suppressed (peer incapable)",
		"Deletes suppressed (purge retirement)",
		"Deletes suppressed (scoped policy)",
		"Installs suppressed (no peer install table)",
	} {
		if !strings.Contains(statistics, want) {
			t.Errorf("FormatStatistics does not expose %q:\n%s", want, statistics)
		}
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
