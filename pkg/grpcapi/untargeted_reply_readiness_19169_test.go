package grpcapi

import (
	"context"
	"runtime/debug"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #19169 (codex-e P2-1): the gRPC twin of the CLI cell. The untargeted
// failover's "already left this node" reply reads only the state, so it must
// not run the transfer-readiness callback before answering.
func TestUntargetedNoLongerPrimaryReplyRunsNoReadiness19169(t *testing.T) {
	s, mgr := untargetedServer18559(t, true, true, nil)
	s.fabricPeerAddrFn = func() []string {
		mgr.SetGroupStateForTesting(1, cluster.StateSecondary)
		mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
		return nil
	}
	var calls atomic.Int32
	mgr.SetTransferReadinessFunc(func(rg int) (bool, []string) {
		calls.Add(1)
		t.Errorf("the failover reply ran the transfer-readiness callback for RG%d:\n%s", rg, debug.Stack())
		return true, nil
	})
	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1"})
	if err != nil {
		t.Fatalf("the group already left this node; want OK, got %v", err)
	}
	if want := clusterfailover.UntargetedNoLongerPrimaryMessage(1, "secondary", 1); resp.GetMessage() != want {
		t.Fatalf("reply = %q, want %q", resp.GetMessage(), want)
	}
	if calls.Load() != 0 {
		t.Fatalf("the reply path ran readiness %d times", calls.Load())
	}
}

// #19169: gRPC status reports the cluster role from RG0's state alone.
func TestStatusClusterRoleRunsNoReadiness19169(t *testing.T) {
	_, mgr := untargetedServer18559(t, true, true, nil)
	// GetStatus reads the config store; the untargeted-failover fixture has
	// none, so this cell builds the server the #12609 status cells use, with
	// the cluster manager attached.
	s := &Server{store: newConfigStore(t, t.TempDir()+"/xpf.conf"), cluster: mgr}
	var calls atomic.Int32
	mgr.SetTransferReadinessFunc(func(int) (bool, []string) { calls.Add(1); return true, nil })
	resp, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.GetClusterRole() == "" {
		t.Fatal("setup: no cluster role reported, so this cell observed nothing")
	}
	if calls.Load() != 0 {
		t.Fatalf("the status call ran readiness %d times", calls.Load())
	}
}
