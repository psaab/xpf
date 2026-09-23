package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestGRPCZoneDetailCallerPrefixContract10530(t *testing.T) {
	s := &Server{store: quarantinePolicyTextStore10530(t)}
	cfg := s.store.ActiveConfig()
	var out strings.Builder
	s.showZonesDetail(cfg, "z214", &out)
	if !strings.Contains(out.String(), config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("gRPC zones-detail quarantined policy block lacks caller qualifier:\n%s", out.String())
	}
	lines := strings.Split(out.String(), "\n")
	summaryAdjacent := false
	for i, line := range lines {
		if strings.Contains(line, "Policy summary") {
			if i == 0 || !strings.Contains(lines[i-1], config.ZoneQuarantinePoliciesQualifier) {
				t.Fatalf("gRPC caller qualifier is not immediately adjacent to SSOT summary:\n%s", out.String())
			}
			summaryAdjacent = true
			break
		}
	}
	if !summaryAdjacent {
		t.Fatalf("gRPC zones-detail omitted shared policy summary:\n%s", out.String())
	}
	var ordinary strings.Builder
	s.showZonesDetail(cfg, "trust", &ordinary)
	if strings.Contains(ordinary.String(), config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("ordinary gRPC zones-detail gained quarantine qualifier:\n%s", ordinary.String())
	}
}
