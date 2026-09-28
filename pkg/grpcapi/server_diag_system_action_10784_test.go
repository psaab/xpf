package grpcapi

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

func TestClearPersistentNATRevokesLocalAndForwardsToPeer10784(t *testing.T) {
	dp := dataplane.New()
	table := dp.GetPersistentNAT()
	table.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.0.10"),
		SrcPort:  40000,
		NatIP:    netip.MustParseAddr("192.0.2.10"),
		NatPort:  50000,
		PoolName: "pool-a",
	})

	peerCalls := 0
	s := &Server{
		dp:      dp,
		cluster: cluster.NewManager(0, 0),
		peerSystemActionFn: func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
			peerCalls++
			if req.Action != "clear-persistent-nat" {
				t.Errorf("peer action = %q, want clear-persistent-nat", req.Action)
			}
			md, ok := metadata.FromOutgoingContext(ctx)
			if !ok || len(md.Get("x-peer-forwarded")) == 0 {
				t.Error("peer clear was not marked as forwarded")
			}
			return &pb.SystemActionResponse{Message: "Cleared 3 persistent NAT bindings"}, nil
		},
	}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "clear-persistent-nat"})
	if err != nil {
		t.Fatalf("SystemAction clear-persistent-nat: %v", err)
	}
	if table.Len() != 0 {
		t.Fatalf("local SHOW mirror has %d bindings after clear, want 0", table.Len())
	}
	if peerCalls != 1 {
		t.Fatalf("peer clear calls = %d, want 1", peerCalls)
	}
	if !strings.Contains(resp.Message, "Cleared 1 persistent NAT bindings") ||
		!strings.Contains(resp.Message, "peer: Cleared 3 persistent NAT bindings") {
		t.Fatalf("clear response = %q, missing local/peer results", resp.Message)
	}

	// A request already forwarded by the peer executes locally without fanning
	// back out and creating a clear loop.
	forwarded := withPeerMarkers(context.Background(), peerMarkers{forwarded: true})
	if _, err := s.SystemAction(forwarded, &pb.SystemActionRequest{Action: "clear-persistent-nat"}); err != nil {
		t.Fatalf("forwarded clear-persistent-nat: %v", err)
	}
	if peerCalls != 1 {
		t.Fatalf("forwarded clear re-propagated to peer: calls=%d, want 1", peerCalls)
	}
}

func TestClearPersistentNATReportsPeerFailureAfterLocalClear10784(t *testing.T) {
	dp := dataplane.New()
	table := dp.GetPersistentNAT()
	table.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.0.11"),
		SrcPort:  40001,
		NatIP:    netip.MustParseAddr("192.0.2.11"),
		NatPort:  50001,
		PoolName: "pool-a",
	})
	s := &Server{
		dp:      dp,
		cluster: cluster.NewManager(0, 0),
		peerSystemActionFn: func(context.Context, *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
			return nil, context.DeadlineExceeded
		},
	}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "clear-persistent-nat"})
	if err != nil {
		t.Fatalf("local clear should still succeed when peer clear fails: %v", err)
	}
	if table.Len() != 0 {
		t.Fatalf("local SHOW mirror has %d bindings after clear, want 0", table.Len())
	}
	if !strings.Contains(resp.Message, "WARNING: peer persistent NAT clear failed") {
		t.Fatalf("clear response = %q, missing peer failure warning", resp.Message)
	}
}
