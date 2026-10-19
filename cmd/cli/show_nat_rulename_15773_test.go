package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15773 RED: remote rule-name filtering + NotInstalled/PortNoTranslation
// rendering + unreferenced DNAT pools.

type natRuleNameClient15773 struct {
	pb.BpfrxServiceClient
	rules       *pb.GetNATRuleStatsResponse
	destination *pb.GetNATDestinationResponse
	pools       *pb.GetNATPoolStatsResponse
	lastRuleReq *pb.GetNATRuleStatsRequest
}

func (c *natRuleNameClient15773) GetNATRuleStats(_ context.Context, req *pb.GetNATRuleStatsRequest, _ ...grpc.CallOption) (*pb.GetNATRuleStatsResponse, error) {
	c.lastRuleReq = req
	// Emulate the post-#15773 daemon: nat_type selects the family and
	// `rule` filters server-side. The client's own filter is exercised
	// by the output assertions regardless.
	family := c.rules.Rules
	if req.NatType == "destination" {
		family = []*pb.NATRuleStats{
			{RuleSet: "drs1", RuleName: "dr-disarmed", FromZone: "untrust", Action: "pool dp-empty", DestinationMatch: "203.0.113.1/32", NotInstalled: true, NotInstalledReason: "pool has no address"},
			{RuleSet: "drs1", RuleName: "dr-normal", FromZone: "untrust", Action: "pool dp-normal", DestinationMatch: "203.0.113.2/32"},
		}
	}
	out := &pb.GetNATRuleStatsResponse{}
	for _, r := range family {
		if req.Rule == "" || r.RuleName == req.Rule {
			out.Rules = append(out.Rules, r)
		}
	}
	return out, nil
}
func (c *natRuleNameClient15773) GetNATDestination(context.Context, *pb.GetNATDestinationRequest, ...grpc.CallOption) (*pb.GetNATDestinationResponse, error) {
	return c.destination, nil
}
func (c *natRuleNameClient15773) GetNATPoolStats(context.Context, *pb.GetNATPoolStatsRequest, ...grpc.CallOption) (*pb.GetNATPoolStatsResponse, error) {
	return c.pools, nil
}

func natRuleNameClientFixture15773() *natRuleNameClient15773 {
	return &natRuleNameClient15773{
		rules: &pb.GetNATRuleStatsResponse{Rules: []*pb.NATRuleStats{
			{RuleSet: "rs1", RuleName: "r-disarmed", FromZone: "trust", ToZone: "untrust", Action: "pool p-empty", SourceMatch: "10.0.0.0/8", DestinationMatch: "0.0.0.0/0", NotInstalled: true, NotInstalledReason: "references a source NAT pool with no usable addresses"},
			{RuleSet: "rs1", RuleName: "r-notrans", FromZone: "trust", ToZone: "untrust", Action: "pool p-notrans", SourceMatch: "10.1.0.0/16", DestinationMatch: "0.0.0.0/0", PortNoTranslation: true},
			{RuleSet: "rs1", RuleName: "r-normal", FromZone: "trust", ToZone: "untrust", Action: "pool p-normal", SourceMatch: "10.2.0.0/16", DestinationMatch: "0.0.0.0/0"},
		}},
		destination: &pb.GetNATDestinationResponse{Rules: []*pb.NATDestInfo{
			{Name: "dr-disarmed", DstAddr: "203.0.113.1/32", PoolName: "dp-empty", NotInstalled: true, NotInstalledReason: "pool has no address"},
			{Name: "dr-normal", DstAddr: "203.0.113.2/32", PoolName: "dp-normal", TranslateIp: "192.0.2.50", TranslatePort: 8080},
		}, Pools: []*pb.NATDestPoolInfo{
			{Name: "dp-empty"}, {Name: "dp-normal", Address: "192.0.2.50", Port: 8080}, {Name: "dp-lonely", Address: "192.0.2.60"},
		}},
	}
}

func TestRemoteNATRuleNameFilter15773(t *testing.T) {
	client := natRuleNameClientFixture15773()
	c := &ctl{client: client}

	var err error
	out := captureStdout(t, func() { err = c.handleShowNAT([]string{"source", "rule", "r-disarmed"}) })
	if err != nil {
		t.Fatalf("source rule r-disarmed: %v", err)
	}
	if client.lastRuleReq == nil || client.lastRuleReq.Rule != "r-disarmed" {
		t.Errorf("request must carry rule name, got %+v", client.lastRuleReq)
	}
	if !strings.Contains(out, "r-disarmed") || strings.Contains(out, "r-normal") || strings.Contains(out, "r-notrans") {
		t.Errorf("remote source rule <name> must show only named rule:\n%s", out)
	}
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Errorf("remote disarmed rule must carry NOT INSTALLED:\n%s", out)
	}

	out = captureStdout(t, func() { err = c.handleShowNAT([]string{"source", "rule", "r-notrans"}) })
	if err != nil {
		t.Fatalf("source rule r-notrans: %v", err)
	}
	if !strings.Contains(out, "no-translation") {
		t.Errorf("remote port no-translation state must be visible:\n%s", out)
	}
	if strings.Contains(out, "NOT INSTALLED") && strings.Contains(out, "r-notrans") {
		// only check combined below; placeholder
	}
	out = captureStdout(t, func() { err = c.handleShowNAT([]string{"destination", "rule", "dr-disarmed"}) })
	if err != nil {
		t.Fatalf("dest rule dr-disarmed: %v", err)
	}
	if client.lastRuleReq == nil || client.lastRuleReq.Rule != "dr-disarmed" || client.lastRuleReq.NatType != "destination" {
		t.Errorf("dest request must carry rule name+type, got %+v", client.lastRuleReq)
	}
	if !strings.Contains(out, "dr-disarmed") || strings.Contains(out, "dr-normal") {
		t.Errorf("remote dest rule <name> must show only named rule:\n%s", out)
	}
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Errorf("remote disarmed dest rule must carry NOT INSTALLED:\n%s", out)
	}

	if err := c.handleShowNAT([]string{"source", "rule", "nope"}); err == nil {
		t.Error("remote source rule unknown: want error")
	}
	if err := c.handleShowNAT([]string{"destination", "rule", "nope"}); err == nil {
		t.Error("remote dest rule unknown: want error")
	}
	// Bare rule lists all.
	out = captureStdout(t, func() { err = c.handleShowNAT([]string{"source", "rule"}) })
	if err != nil || !strings.Contains(out, "r-normal") || !strings.Contains(out, "r-disarmed") {
		t.Errorf("remote bare source rule must list all err=%v:\n%s", err, out)
	}
	// Unreferenced DNAT pool visible in summary and pool views.
	out = captureStdout(t, func() { err = c.handleShowNAT([]string{"destination", "summary"}) })
	if err != nil || !strings.Contains(out, "dp-lonely") || !strings.Contains(out, "Total pools: 3") {
		t.Errorf("remote dest summary must include unreferenced pool err=%v:\n%s", err, out)
	}
	out = captureStdout(t, func() { err = c.handleShowNAT([]string{"destination", "pool"}) })
	if err != nil || !strings.Contains(out, "dp-lonely") {
		t.Errorf("remote dest pool must include unreferenced pool err=%v:\n%s", err, out)
	}
	out = captureStdout(t, func() { err = c.handleShowNAT([]string{"destination", "pool", "dp-lonely"}) })
	if err != nil || !strings.Contains(out, "dp-lonely") {
		t.Errorf("remote dest pool <unreferenced> err=%v:\n%s", err, out)
	}
}
