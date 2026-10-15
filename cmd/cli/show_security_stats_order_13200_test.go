package main

import (
	"context"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// TestShowStatisticsSortsScreenDropDetails_13200 is the #13200 (D10-04)
// regression: `show security statistics detail` must render the
// ScreenDropDetails map in deterministic sorted order, not Go map order.
//
// FAIL-ON-REVERT: unsort the loop in showStatistics and output order becomes
// map-random; the repeated runs and exact-order assertions go RED.
func TestShowStatisticsSortsScreenDropDetails_13200(t *testing.T) {
	keys := []string{"udp-flood", "tcp-no-flag", "spoof", "land-attack", "winnuke", "icmp-flood", "teardrop"}
	sort.Strings(keys)
	want := keys
	c := &ctl{client: &showStatsFakeClient{}}
	// Multiple runs: map iteration order varies per run, so a single pass
	// could coincidentally be sorted on the broken code.
	for run := range 5 {
		out := captureStdout13200(t, func() {
			if err := c.showStatistics(true); err != nil {
				t.Fatalf("showStatistics: %v", err)
			}
		})
		var got []string
		for _, line := range strings.Split(out, "\n") {
			name, _, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok {
				continue
			}
			for _, w := range want {
				if name == w {
					got = append(got, name)
				}
			}
		}
		if len(got) != len(want) {
			t.Fatalf("run %d: screen drop rows = %v, want %v\noutput:\n%s", run, got, want, out)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("run %d: screen drop order = %v, want sorted %v\noutput:\n%s", run, got, want, out)
			}
		}
	}
}

type showStatsFakeClient struct {
	pb.BpfrxServiceClient
}

func (f *showStatsFakeClient) GetGlobalStats(
	_ context.Context, _ *pb.GetGlobalStatsRequest, _ ...grpc.CallOption,
) (*pb.GetGlobalStatsResponse, error) {
	return &pb.GetGlobalStatsResponse{
		ScreenDrops: 21,
		ScreenDropDetails: map[string]uint64{
			"udp-flood": 3, "tcp-no-flag": 4, "spoof": 2, "land-attack": 5,
			"winnuke": 1, "icmp-flood": 6, "teardrop": 7,
		},
	}, nil
}

func (f *showStatsFakeClient) ShowText(
	_ context.Context, _ *pb.ShowTextRequest, _ ...grpc.CallOption,
) (*pb.ShowTextResponse, error) {
	return &pb.ShowTextResponse{}, nil
}

func captureStdout13200(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = orig
	var out strings.Builder
	if _, err := io.Copy(&out, r); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	_ = r.Close()
	return out.String()
}
