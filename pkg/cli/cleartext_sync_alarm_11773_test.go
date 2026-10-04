package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

type cleartextAlarmStats11773 struct{}

func (cleartextAlarmStats11773) Stats() cluster.SyncStatsSnapshot {
	return cluster.SyncStatsSnapshot{
		ConfigsSent: 8, ConfigsReceived: 10,
		ConfigsSentCleartext: 2, ConfigsReceivedCleartext: 3,
		CleartextSyncAlarmLatched: true, PeerBootIncarnation: "none",
	}
}
func (cleartextAlarmStats11773) IsConnected() bool { return true }
func (cleartextAlarmStats11773) PeerSessionSyncWireVersion() uint16 { return 0 }
func (cleartextAlarmStats11773) UnauthenticatedSessionConns() []string { return nil }

// TestClusterCLIReportsLatchedCleartextSync11773 exercises the console
// commands, rather than only the Manager's formatters. Those are also the
// formatters used by gRPC ShowText for cluster status and information.
func TestClusterCLIReportsLatchedCleartextSync11773(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	manager := cluster.NewManager(0, 1)
	manager.SetSyncStats(cleartextAlarmStats11773{})
	c := &CLI{cluster: manager, store: store}

	for _, tc := range []struct {
		name string
		run  func() error
		want []string
	}{
		{
			name: "status",
			run:  c.showChassisClusterStatus,
			want: []string{
				"Warning: config sync has sent or received cleartext payloads (#11773; alarm latched).",
				"Cleartext config payloads: sent 2, received 3.",
			},
		},
		{
			name: "information",
			run:  c.showChassisClusterInformation,
			want: []string{
				"WARNING: config sync cleartext fallback has been used (alarm latched; sent 2, received 3)",
			},
		},
		{
			name: "statistics",
			run:  c.showChassisClusterStatistics,
			want: []string{fmt.Sprintf("%-32s %-12d %d", "Config cleartext", 2, 3)},
		},
		{
			name: "data-plane statistics",
			run:  c.showChassisClusterDataPlaneStats,
			want: []string{fmt.Sprintf("%-32s %-12d %d", "Config cleartext", 2, 3)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var runErr error
			out := captureStdout(t, func() { runErr = tc.run() })
			if runErr != nil {
				t.Fatalf("show cluster %s: %v", tc.name, runErr)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("show cluster %s lacks %q:\n%s", tc.name, want, out)
				}
			}
		})
	}
}
