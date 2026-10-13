package grpcapi

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// statusSessionsDP is a grpcRuntime whose SessionCount reports the live
// (forward-only) dataplane session totals. It embeds *dataplane.Manager for
// the methods GetStatus does not touch and overrides IsLoaded/SessionCount.
type statusSessionsDP struct {
	*dataplane.Manager
	v4 int
	v6 int
}

func (d *statusSessionsDP) IsLoaded() bool           { return true }
func (d *statusSessionsDP) SessionCount() (int, int) { return d.v4, d.v6 }

func (d *statusSessionsDP) SessionCountContext(context.Context) (int, int, error) {
	return d.v4, d.v6, nil
}

// TestGetStatusSessionCountFromUserspaceTable is the #3929 RED-on-revert guard
// for the gRPC GetStatus SessionCount. It must report the live dataplane
// session count (forward-only v4+v6 = 7), NOT gc.Stats().TotalEntries, which is
// permanently 0 on the userspace dataplane (the BPF GC sweep is skipped, #333).
// Reverting server_show_status.go to `resp.SessionCount = stats.TotalEntries`
// reports 0 and flips this assertion red.
func TestGetStatusSessionCountFromUserspaceTable(t *testing.T) {
	s := &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    &statusSessionsDP{Manager: dataplane.New(), v4: 5, v6: 2},
		// A GC that has never swept — models the userspace runtime, where
		// gc.Stats() is all-zero. The reverted code would read 0 from here.
		gc: conntrack.NewGC(nil, time.Minute),
	}

	resp, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.SessionCount != 7 {
		t.Fatalf("SessionCount = %d, want 7 (live userspace forward count v4=5 + v6=2)", resp.SessionCount)
	}
}

// TestGetStatusSessionCountNoDataplane guards the nil/unloaded dataplane path:
// no dp => SessionCount 0, no panic.
func TestGetStatusSessionCountNoDataplane(t *testing.T) {
	s := &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		gc:    conntrack.NewGC(nil, time.Minute),
	}
	resp, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.SessionCount != 0 {
		t.Fatalf("SessionCount = %d, want 0 with no dataplane", resp.SessionCount)
	}
}
