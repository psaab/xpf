package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestWorkerRepairImportOutcomesAreNotCountedAsInstalled11360(t *testing.T) {
	outcomes := []struct {
		name string
		err  error
	}{
		{name: "pending", err: dataplane.ErrSyncedImportRepairPending},
		{name: "overflow", err: dataplane.ErrSyncedImportRepairOverflow},
	}
	v4Key := dataplane.SessionKey{
		Protocol: 6,
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 2},
		SrcPort:  1234,
		DstPort:  80,
	}
	v6Key := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1234, DstPort: 80}
	v6Key.SrcIP[15] = 1
	v6Key.DstIP[15] = 2

	for _, outcome := range outcomes {
		outcome := outcome
		t.Run("v4/"+outcome.name, func(t *testing.T) {
			dp := &mockSweepDP{
				v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
				failSetV4:  map[dataplane.SessionKey]error{v4Key: outcome.err},
			}
			ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
			installedCallbacks := 0
			ss.OnForwardSessionInstalled = func() { installedCallbacks++ }
			if ss.installClusterSyncedV4(v4Key, dataplane.SessionValue{
				State: dataplane.SessStateEstablished,
			}) {
				t.Fatal("worker repair response reported the session as installed")
			}
			if got := ss.stats.SessionsInstalled.Load(); got != 0 {
				t.Fatalf("SessionsInstalled = %d, want 0", got)
			}
			if got := ss.stats.ImportsRefusedByHelper.Load(); got != 0 {
				t.Fatalf("ImportsRefusedByHelper = %d, want 0 for committed repair status", got)
			}
			if installedCallbacks != 0 {
				t.Fatalf("forward-install callback count = %d, want 0", installedCallbacks)
			}
		})
		t.Run("v6/"+outcome.name, func(t *testing.T) {
			dp := &mockSweepDP{
				v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
				failSetV6:  map[dataplane.SessionKeyV6]error{v6Key: outcome.err},
			}
			ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
			installedCallbacks := 0
			ss.OnForwardSessionInstalled = func() { installedCallbacks++ }
			if ss.installClusterSyncedV6(v6Key, dataplane.SessionValueV6{
				State: dataplane.SessStateEstablished,
			}) {
				t.Fatal("worker repair response reported the session as installed")
			}
			if got := ss.stats.SessionsInstalled.Load(); got != 0 {
				t.Fatalf("SessionsInstalled = %d, want 0", got)
			}
			if got := ss.stats.ImportsRefusedByHelper.Load(); got != 0 {
				t.Fatalf("ImportsRefusedByHelper = %d, want 0 for committed repair status", got)
			}
			if installedCallbacks != 0 {
				t.Fatalf("forward-install callback count = %d, want 0", installedCallbacks)
			}
		})
	}
}
