package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #12900: with the dataplane unloaded, counted rules must report
// HitCountersUnavailable instead of a published-looking zero.
func TestGetPoliciesUnloadedCountersUnavailable12900(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{store: store} // dp nil: not loaded
	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}
	var checked int
	for _, policy := range resp.GetPolicies() {
		for _, rule := range policy.GetRules() {
			if !rule.GetCount() {
				continue
			}
			checked++
			if !rule.GetHitCountersUnavailable() {
				t.Fatalf("rule %q: HitCountersUnavailable=false with unloaded dataplane (hits %d/%d)",
					rule.GetName(), rule.GetHitPackets(), rule.GetHitBytes())
			}
		}
	}
	if checked == 0 {
		t.Fatal("no counted rules in fixture; test would be vacuous")
	}
}
