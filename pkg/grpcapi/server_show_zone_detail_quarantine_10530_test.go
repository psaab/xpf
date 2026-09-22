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
	if !strings.Contains(out.String(), "Policy summary") {
		t.Fatalf("gRPC zones-detail omitted shared policy summary:\n%s", out.String())
	}
	var ordinary strings.Builder
	s.showZonesDetail(cfg, "trust", &ordinary)
	if strings.Contains(ordinary.String(), config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("ordinary gRPC zones-detail gained quarantine qualifier:\n%s", ordinary.String())
	}
}
