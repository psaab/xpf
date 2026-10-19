package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15773: GetNATRuleStats honours the `rule` name filter in both families,
// and GetNATDestination carries every configured pool (referenced or not).

const natRuleFilterCfg15773 = "security {\nnat {\n" +
	"source {\npool p1 { address 192.0.2.10; }\npool pnt { address 192.0.2.20; port { no-translation; } }\n" +
	"rule-set rs {\nfrom zone trust;\nto zone untrust;\n" +
	"rule r-alpha { match { source-address 10.0.0.0/8; } then { source-nat { pool p1; } } }\n" +
	"rule r-notrans { match { source-address 10.1.0.0/16; } then { source-nat { pool pnt; } } }\n" +
	"}\n}\n" +
	"destination {\npool dp1 { address 10.0.0.5; }\npool dp-lonely { address 10.0.0.6; }\n" +
	"rule-set drs {\nfrom zone untrust;\n" +
	"rule dr-alpha { match { destination-address 203.0.113.1/32; } then { destination-nat { pool dp1; } } }\n" +
	"rule dr-beta { match { destination-address 203.0.113.2/32; } then { destination-nat { pool dp1; } } }\n" +
	"}\n}\n}\n}\n"

func TestGetNATRuleStatsRuleFilter15773(t *testing.T) {
	s := natStructuredServer(t, natRuleFilterCfg15773)

	resp, err := s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{Rule: "r-notrans"})
	if err != nil {
		t.Fatalf("GetNATRuleStats(rule): %v", err)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].RuleName != "r-notrans" {
		t.Fatalf("filtered source rules = %+v, want only r-notrans", resp.Rules)
	}
	if !resp.Rules[0].PortNoTranslation {
		t.Error("r-notrans must carry port_no_translation=true")
	}

	resp, err = s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{Rule: "r-alpha"})
	if err != nil {
		t.Fatalf("GetNATRuleStats(r-alpha): %v", err)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].PortNoTranslation {
		t.Fatalf("r-alpha = %+v, want one rule with port_no_translation=false", resp.Rules)
	}

	resp, err = s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{NatType: "destination", Rule: "dr-beta"})
	if err != nil {
		t.Fatalf("GetNATRuleStats(dest rule): %v", err)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].RuleName != "dr-beta" {
		t.Fatalf("filtered dest rules = %+v, want only dr-beta", resp.Rules)
	}

	// Unknown name yields empty (remote CLI turns that into an error).
	resp, err = s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{Rule: "nope"})
	if err != nil || len(resp.Rules) != 0 {
		t.Fatalf("unknown rule = %+v err=%v, want empty", resp.Rules, err)
	}
	// Unfiltered still lists all.
	resp, err = s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{})
	if err != nil || len(resp.Rules) != 2 {
		t.Fatalf("unfiltered source rules = %d err=%v, want 2", len(resp.Rules), err)
	}
}

func TestGetNATDestinationPoolsIncludeUnreferenced15773(t *testing.T) {
	s := natStructuredServer(t, natRuleFilterCfg15773)
	resp, err := s.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
	if err != nil {
		t.Fatalf("GetNATDestination: %v", err)
	}
	seen := map[string]bool{}
	for _, p := range resp.Pools {
		seen[p.Name] = true
	}
	if !seen["dp1"] || !seen["dp-lonely"] {
		t.Errorf("pools = %v, want dp1 and unreferenced dp-lonely", resp.Pools)
	}
}
