package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type cleartextSyncStats11773 struct{}

func (cleartextSyncStats11773) Stats() cluster.SyncStatsSnapshot {
	return cluster.SyncStatsSnapshot{
		ConfigsSent: 8, ConfigsReceived: 10,
		ConfigsSentCleartext: 2, ConfigsReceivedCleartext: 3,
		CleartextSyncAlarmLatched: true, PeerBootIncarnation: "none",
	}
}
func (cleartextSyncStats11773) IsConnected() bool { return true }
func (cleartextSyncStats11773) PeerSessionSyncWireVersion() uint16 { return 0 }
func (cleartextSyncStats11773) UnauthenticatedSessionConns() []string { return nil }

// TestGRPCClusterShowReportsLatchedCleartextSync11773 exercises the remote
// ShowText routes that carry the same cluster alarm and counters as the console.
func TestGRPCClusterShowReportsLatchedCleartextSync11773(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	manager := cluster.NewManager(0, 1)
	manager.SetSyncStats(cleartextSyncStats11773{})
	server := &Server{store: store, cluster: manager}

	for _, tc := range []struct {
		topic string
		want  []string
	}{
		{
			topic: "chassis-cluster-status",
			want: []string{
				"Warning: config sync has sent or received cleartext payloads (#11773; alarm latched).",
				"Cleartext config payloads: sent 2, received 3.",
			},
		},
		{
			topic: "chassis-cluster-information",
			want: []string{
				"WARNING: config sync cleartext fallback has been used (alarm latched; sent 2, received 3)",
			},
		},
		{
			topic: "chassis-cluster-statistics",
			want:  []string{"Config cleartext"},
		},
	} {
		t.Run(tc.topic, func(t *testing.T) {
			response, err := server.ShowText(context.Background(), &pb.ShowTextRequest{Topic: tc.topic})
			if err != nil {
				t.Fatalf("ShowText(%s): %v", tc.topic, err)
			}
			for _, want := range tc.want {
				if !strings.Contains(response.GetOutput(), want) {
					t.Errorf("ShowText(%s) lacks %q:\n%s", tc.topic, want, response.GetOutput())
				}
			}
		})
	}
}
