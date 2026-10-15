package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestGetNATPoolStatsDeduplicatesInterfaceRules13246(t *testing.T) {
	s := &Server{store: newNATStatsGRPCStore(t)}
	resp, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats: %v", err)
	}
	var rows int
	for _, p := range resp.GetPools() {
		if p.GetName() == "trust->untrust" {
			rows++
		}
	}
	if rows != 1 {
		t.Fatalf("trust->untrust interface rows = %d, want 1: %+v", rows, resp.GetPools())
	}
}
