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
	// #12896 narrowed the ordinary control: a healthy zone never gains the
	// BLOCK qualifier, but a row whose peer zone is quarantined is per-row
	// qualified by the SSOT (what apply would scrub), so "no qualifier
	// anywhere" is no longer the contract.
	var ordinary strings.Builder
	s.showZonesDetail(cfg, "trust", &ordinary)
	ordinaryLines := strings.Split(ordinary.String(), "\n")
	for i, line := range ordinaryLines {
		if strings.Contains(line, "Policy summary") {
			// The #10530 contract is about the dedicated block-qualifier LINE;
			// the references line above may legitimately carry per-reference
			// #12896 marks.
			if i == 0 || ordinaryLines[i-1] == "  "+config.ZoneQuarantinePoliciesQualifier {
				t.Fatalf("ordinary gRPC zones-detail gained the block qualifier:\n%s", ordinary.String())
			}
			break
		}
	}
	ordinaryRow := ""
	deadRow := ""
	for _, line := range ordinaryLines {
		if strings.Contains(line, "ordinary-rule") {
			ordinaryRow = line
		}
		if strings.Contains(line, "loser-rule") {
			deadRow = line
		}
	}
	if ordinaryRow == "" || deadRow == "" {
		t.Fatalf("ordinary gRPC zones-detail lost its policy rows:\n%s", ordinary.String())
	}
	if strings.Contains(ordinaryRow, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("live trust->trust row gained quarantine qualifier:\n%s", ordinaryRow)
	}
	if !strings.Contains(deadRow, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("peer-quarantined trust->z214 row lacks the #12896 scrub qualifier:\n%s", deadRow)
	}
}
