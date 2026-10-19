package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15775: the gRPC ShowText topic behind remote
// `show chassis cluster fence-status` must render real peer-fencing
// output, not RG status.
func TestShowTextClusterFenceStatus15775(t *testing.T) {
	store := fallbackStore12605(t, "set chassis cluster peer-fencing disable-rg")
	s := &Server{store: store}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "chassis-cluster-fence-status"})
	if err != nil {
		t.Fatalf("ShowText fence-status: %v", err)
	}
	if !strings.Contains(resp.Output, "Peer fencing:") || !strings.Contains(resp.Output, "Action: disable-rg") {
		t.Errorf("fence-status output wrong:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "Redundancy group:") {
		t.Errorf("fence-status rendered RG status:\n%s", resp.Output)
	}
}
