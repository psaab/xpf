package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type natShowClient13199 struct {
	pb.BpfrxServiceClient
	destination *pb.GetNATDestinationResponse
	stats       *pb.GetNATRuleStatsResponse
	statsErr    error
}

func (c *natShowClient13199) GetNATDestination(context.Context, *pb.GetNATDestinationRequest, ...grpc.CallOption) (*pb.GetNATDestinationResponse, error) {
	return c.destination, nil
}

func (c *natShowClient13199) GetNATRuleStats(context.Context, *pb.GetNATRuleStatsRequest, ...grpc.CallOption) (*pb.GetNATRuleStatsResponse, error) {
	return c.stats, c.statsErr
}

func TestShowNATDestinationSummaryUsesPoolNamesAndSorts13199(t *testing.T) {
	client := &natShowClient13199{
		destination: &pb.GetNATDestinationResponse{Rules: []*pb.NATDestInfo{
			{Name: "z-rule", PoolName: "z-pool", TranslateIp: "198.51.100.2/32", TranslatePort: 8080},
			{Name: "a-rule", PoolName: "a-pool", TranslateIp: "198.51.100.1/32"},
			{Name: "off-rule", TranslateIp: ""},
		}},
		stats: &pb.GetNATRuleStatsResponse{Rules: []*pb.NATRuleStats{
			{Action: "pool z-pool", HitPackets: 42},
			{Action: "pool a-pool", HitPackets: 7},
		}},
	}
	c := &ctl{client: client}
	out := captureStdout(t, func() {
		if err := c.showNATDestinationSummary(); err != nil {
			t.Fatalf("showNATDestinationSummary: %v", err)
		}
	})
	if strings.Index(out, "a-pool") > strings.Index(out, "z-pool") {
		t.Fatalf("pool rows are not sorted by pool name:\n%s", out)
	}
	for _, want := range []string{"a-pool", "198.51.100.1/32", "7", "z-pool", "198.51.100.2/32", "42"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary omits %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "off-rule") || strings.Contains(out, "Pool name: \n") {
		t.Fatalf("poolless destination-NAT rule rendered as a pool:\n%s", out)
	}
	if !strings.Contains(out, "Total pools: 2") {
		t.Fatalf("poolless rule inflated pool count:\n%s", out)
	}
}

func TestShowNATDestinationPoolFiltersByName13199(t *testing.T) {
	client := &natShowClient13199{destination: &pb.GetNATDestinationResponse{Rules: []*pb.NATDestInfo{
		{Name: "web-rule", PoolName: "web-pool", TranslateIp: "192.0.2.10/32"},
		{Name: "mail-rule", PoolName: "mail-pool", TranslateIp: "192.0.2.20/32"},
		{Name: "off-rule", TranslateIp: ""},
	}}}
	c := &ctl{client: client}
	out := captureStdout(t, func() {
		if err := c.handleShowNAT([]string{"destination", "pool", "web-pool"}); err != nil {
			t.Fatalf("handleShowNAT pool filter: %v", err)
		}
	})
	if !strings.Contains(out, "Pool name: web-pool") || !strings.Contains(out, "web-rule") {
		t.Fatalf("filtered pool output missing matching pool/rule:\n%s", out)
	}
	if strings.Contains(out, "mail-pool") || strings.Contains(out, "mail-rule") {
		t.Fatalf("pool filter leaked unrelated pool/rule:\n%s", out)
	}
	if err := c.handleShowNAT([]string{"destination", "pool", "missing"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing pool error = %v, want not found", err)
	}
	allOut := captureStdout(t, func() {
		if err := c.showNATDestinationPool(""); err != nil {
			t.Fatalf("showNATDestinationPool: %v", err)
		}
	})
	if strings.Contains(allOut, "off-rule") || strings.Contains(allOut, "Pool name: \n") {
		t.Fatalf("poolless destination-NAT rule rendered as a pool:\n%s", allOut)
	}
}

func TestShowNATDestinationSummaryReturnsStatsErrors13199(t *testing.T) {
	client := &natShowClient13199{
		destination: &pb.GetNATDestinationResponse{Rules: []*pb.NATDestInfo{{PoolName: "web-pool", TranslateIp: "192.0.2.10"}}},
		statsErr:    errors.New("stats unavailable"),
	}
	c := &ctl{client: client}
	if err := c.showNATDestinationSummary(); err == nil || !strings.Contains(err.Error(), "stats unavailable") {
		t.Fatalf("showNATDestinationSummary error = %v, want propagated stats error", err)
	}
}

func TestNatPoolArgRejectsMalformedSelectors13199(t *testing.T) {
	if name, err := natPoolArg(nil); err != nil || name != "" {
		t.Fatalf("natPoolArg(nil) = %q, %v; want empty selector", name, err)
	}
	if name, err := natPoolArg([]string{"pool", "web"}); err != nil || name != "web" {
		t.Fatalf("natPoolArg(pool web) = %q, %v; want web", name, err)
	}
	for _, rest := range [][]string{{"pool"}, {"bogus"}, {"pool", "web", "extra"}, {"pool", ""}} {
		if name, err := natPoolArg(rest); err == nil || name != "" {
			t.Errorf("natPoolArg(%q) = %q, %v; want an error", rest, name, err)
		}
	}
}
