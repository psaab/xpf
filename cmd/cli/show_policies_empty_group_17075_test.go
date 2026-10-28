package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #17075 fold (Rev18317Glm): the remote detail view must keep the header
// (plus trailing blank line) for an applicable zone-pair group with zero
// rules, exactly as the pre-#17075 view and the config-backed grouped
// twins do. The filtered inventory loop previously skipped
// len(stanza.Rules)==0 stanzas yielded by ZonePairStanzasOrdered, whose
// contract is to yield empty stanzas so grouped renderers preserve that
// header. FAIL-ON-REVERT: restoring the skip drops the
// "From zone: trust, To zone: untrust" header below.
func TestShowPoliciesFilteredKeepsEmptyZonePairGroup17075(t *testing.T) {
	fake := &fakeBpfrxClient{
		getPoliciesResp: &pb.GetPoliciesResponse{Policies: []*pb.PolicyInfo{
			{FromZone: "*", ToZone: "*", Rules: []*pb.PolicyRule{
				{Name: "open-global", Action: "permit"},
			}},
			{FromZone: "trust", ToZone: "untrust"},
			{FromZone: "trust", ToZone: "dmz", Rules: []*pb.PolicyRule{
				{Name: "off-pair", Action: "deny"},
			}},
			{FromZone: "dmz", ToZone: "untrust", Rules: []*pb.PolicyRule{
				{Name: "also-off-pair", Action: "deny"},
			}},
		}},
		getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{
			{Name: "trust"}, {Name: "untrust"}, {Name: "dmz"},
		}},
	}
	c := &ctl{client: fake}
	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("trust", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})
	wantHeader := "From zone: trust, To zone: untrust\n\n"
	if !strings.Contains(out, wantHeader) {
		t.Fatalf("filtered remote detail dropped empty zone-pair group header %q:\n%q", wantHeader, out)
	}
	if strings.Contains(out, "off-pair") {
		t.Fatalf("filtered remote detail rendered an off-pair rule:\n%s", out)
	}
	if n := strings.Count(out, "Rule:"); n != 1 {
		t.Fatalf("filtered remote detail rule rows = %d, want only the applicable global:\n%s", n, out)
	}
	if !strings.Contains(out, "Rule: open-global") {
		t.Fatalf("filtered remote detail dropped applicable global after empty group:\n%s", out)
	}
	// The empty group is exact tier and must precede the global tier.
	if strings.Index(out, wantHeader) > strings.Index(out, "Rule: open-global") {
		t.Fatalf("empty zone-pair group header not in tier order before globals:\n%s", out)
	}
}
