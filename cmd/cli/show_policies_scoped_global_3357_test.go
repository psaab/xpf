package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3357: the remote CLI dropped scoped global policies (#3148) from the
// FILTERED policy view and rendered them as "*"/"*" in the brief view.
//
//   - showPoliciesFiltered compared the enclosing group zones (the global
//     group is "*"/"*") against the filter, so a `from-zone X to-zone Y`
//     filter dropped the whole global block — including a scoped global that
//     targets exactly that pair.
//   - showPoliciesBrief printed the group zones ("*") instead of the per-rule
//     MatchFromZone/MatchToZone the proto already carries, regressing the
//     local-CLI #3286 display.
//
// These tests are the fail-on-revert guard.

// scopedGlobalPoliciesResp models GetPolicies output: a zone-pair set
// (trust->untrust), a second zone-pair set (trust->dmz) used to prove the
// per-set filter still works, and the global group "*"/"*" carrying a scoped
// global for trust->untrust, a scoped global for the off-pair trust->dmz, and
// an unscoped (all-zones) global.
func scopedGlobalPoliciesResp() *pb.GetPoliciesResponse {
	return &pb.GetPoliciesResponse{
		Policies: []*pb.PolicyInfo{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Rules: []*pb.PolicyRule{
					{Name: "zp-allow", Action: "permit"},
				},
			},
			{
				FromZone: "trust",
				ToZone:   "dmz",
				Rules: []*pb.PolicyRule{
					{Name: "zp-dmz", Action: "deny"},
				},
			},
			{
				FromZone: "*",
				ToZone:   "*",
				Rules: []*pb.PolicyRule{
					{Name: "scoped-tu", Action: "deny", MatchFromZone: "trust", MatchToZone: "untrust"},
					{Name: "scoped-td", Action: "deny", MatchFromZone: "trust", MatchToZone: "dmz"},
					{Name: "open-global", Action: "permit"},
				},
			},
		},
	}
}

// TestShowPoliciesFilteredKeepsScopedGlobal: a `from-zone trust to-zone untrust`
// filter must include the scoped global that targets that pair AND the unscoped
// (all-zones) global, while excluding a scoped global bound to a different pair
// and the non-matching zone-pair set.
//
// FAIL-ON-REVERT: restoring the group-level `pi.FromZone != fromZone` filter
// drops the whole "*"/"*" global block, so the scoped-tu / open-global
// assertions go RED.
func TestShowPoliciesFilteredKeepsScopedGlobal(t *testing.T) {
	fake := &fakeBpfrxClient{
		getPoliciesResp: scopedGlobalPoliciesResp(),
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

	if !strings.Contains(out, "Rule: scoped-tu") {
		t.Fatalf("filtered view dropped scoped global trust->untrust (#3357 regression):\n%s", out)
	}
	// The scoped global must render under its effective scope, not "*"/"*".
	if !strings.Contains(out, "From zone: trust, To zone: untrust") {
		t.Fatalf("filtered view missing scoped-global scope header trust/untrust:\n%s", out)
	}
	if !strings.Contains(out, "Rule: open-global") {
		t.Fatalf("filtered view dropped unscoped (all-zones) global:\n%s", out)
	}
	if strings.Contains(out, "Rule: scoped-td") {
		t.Fatalf("filtered view leaked an off-pair scoped global (trust->dmz):\n%s", out)
	}
	if strings.Contains(out, "Rule: zp-dmz") {
		t.Fatalf("filtered view leaked a non-matching zone-pair set (trust->dmz):\n%s", out)
	}
	if !strings.Contains(out, "Rule: zp-allow") {
		t.Fatalf("filtered view dropped the matching zone-pair rule:\n%s", out)
	}
}

// TestShowPoliciesBriefRendersScopedGlobalScope: the brief tabular view must
// print a scoped global's per-rule zones, not the group "*"/"*".
//
// FAIL-ON-REVERT: restoring `pi.FromZone`/`pi.ToZone` in the brief columns
// prints "*"/"*" for scoped-tu, so the trust/untrust column assertion goes RED.
func TestShowPoliciesBriefRendersScopedGlobalScope(t *testing.T) {
	fake := &fakeBpfrxClient{getPoliciesResp: scopedGlobalPoliciesResp()}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showPoliciesBrief(); err != nil {
			t.Fatalf("showPoliciesBrief: %v", err)
		}
	})

	scoped := briefRowFor(t, out, "scoped-tu")
	fields := strings.Fields(scoped)
	if len(fields) < 2 || fields[0] != "trust" || fields[1] != "untrust" {
		t.Fatalf("scoped-tu brief row = %q, want trust/untrust columns (rendered as */* — #3357 regression)", scoped)
	}
	open := briefRowFor(t, out, "open-global")
	ofields := strings.Fields(open)
	if len(ofields) < 2 || ofields[0] != "*" || ofields[1] != "*" {
		t.Fatalf("open-global brief row = %q, want */* columns (unscoped global)", open)
	}
}

// briefRowFor returns the brief output line containing the named policy.
func briefRowFor(t *testing.T, out, name string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, name) {
			return line
		}
	}
	t.Fatalf("policy %q row not found in brief output:\n%s", name, out)
	return ""
}
