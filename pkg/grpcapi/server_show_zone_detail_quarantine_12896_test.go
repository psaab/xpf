package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12896: the gRPC zones-detail "Policies referencing this zone" line lists a
// set whose other endpoint is a StableZoneID-collision loser. Under a healthy
// viewed zone that set is dropped by the apply-time scrub, so the reference
// must carry ZoneQuarantinePoliciesQualifier instead of reading as a live
// peer; the live references on the same line stay unqualified. Under a
// quarantined viewed zone every listed reference is scrubbed by definition and
// the line-level qualifier already covers them (pinned by the #10489 tests).
func TestGRPCZoneDetailRefsQualifyQuarantinedPeer12896(t *testing.T) {
	s := &Server{store: quarantinePolicyTextStore10530(t)}
	cfg := s.store.ActiveConfig()
	var out strings.Builder
	s.showZonesDetail(cfg, "trust", &out)

	refsLine := ""
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "  Policies: ") {
			refsLine = line
			break
		}
	}
	if refsLine == "" {
		t.Fatalf("healthy zones-detail lost its Policies references line:\n%s", out.String())
	}
	// RED on master: the reference to the quarantined peer read as live.
	if !strings.Contains(refsLine, "from z214 (1 rules) "+config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("quarantined-peer reference lacks the #12896 scrub qualifier:\n%s", refsLine)
	}
	// Control: the live self-reference on the same line stays unqualified.
	if !strings.Contains(refsLine, "to trust (1 rules)") ||
		strings.Contains(refsLine, "to trust (1 rules) "+config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("live reference misrendered on the qualified line:\n%s", refsLine)
	}
}
