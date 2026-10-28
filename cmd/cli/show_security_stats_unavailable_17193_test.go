package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// unavailableStatsFakeClient17193 returns a GetGlobalStatsResponse naming
// tc_egress_packets unavailable (the #17193 additive field), with healthy
// values elsewhere.
type unavailableStatsFakeClient17193 struct {
	pb.BpfrxServiceClient
}

func (f *unavailableStatsFakeClient17193) GetGlobalStats(
	_ context.Context, _ *pb.GetGlobalStatsRequest, _ ...grpc.CallOption,
) (*pb.GetGlobalStatsResponse, error) {
	return &pb.GetGlobalStatsResponse{
		RxPackets:           42,
		TcEgressPackets:     0,
		UnavailableCounters: []string{"tc_egress_packets"},
	}, nil
}

func (f *unavailableStatsFakeClient17193) ShowText(
	_ context.Context, _ *pb.ShowTextRequest, _ ...grpc.CallOption,
) (*pb.ShowTextResponse, error) {
	return &pb.ShowTextResponse{}, nil
}

// TestShowStatisticsRendersUnavailable17193: the remote CLI must render
// "unavailable" for a server-named unavailable counter, never the
// non-authoritative numeric 0.
//
// FAIL-ON-REVERT: dropping the unavailable branch in showStatistics prints
// "TC egress packets: 0" and the assertions go RED.
func TestShowStatisticsRendersUnavailable17193(t *testing.T) {
	c := &ctl{client: &unavailableStatsFakeClient17193{}}
	out := captureStdout13200(t, func() {
		if err := c.showStatistics(false); err != nil {
			t.Fatalf("showStatistics: %v", err)
		}
	})
	found := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "TC egress packets:") {
			found = true
			if !strings.Contains(line, "unavailable") {
				t.Errorf("TC egress must render unavailable, got %q\nfull:\n%s", line, out)
			}
		}
		if strings.Contains(line, "RX packets:") && !strings.Contains(line, "42") {
			t.Errorf("healthy RX packets must keep its value, got %q", line)
		}
	}
	if !found {
		t.Fatalf("missing TC egress line:\n%s", out)
	}
}
