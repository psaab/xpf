package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestGetNATRuleStatsDestinationAction13246(t *testing.T) {
	for _, tc := range []struct {
		name, config, want string
	}{
		{"actionless", destCfg(false), "none"},
		{"explicit off", "security { nat { destination { rule-set drs { from zone untrust; rule dr1 { match { destination-address 203.0.113.10/32; } then { destination-nat { off; } } } } } } }", "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := natStructuredServer(t, tc.config)
			resp, err := s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{NatType: "destination"})
			if err != nil {
				t.Fatalf("GetNATRuleStats: %v", err)
			}
			if len(resp.GetRules()) != 1 {
				t.Fatalf("rules = %d, want 1: %+v", len(resp.GetRules()), resp.GetRules())
			}
			if got := resp.GetRules()[0].GetAction(); got != tc.want {
				t.Fatalf("destination rule action = %q, want %q", got, tc.want)
			}
		})
	}
}
