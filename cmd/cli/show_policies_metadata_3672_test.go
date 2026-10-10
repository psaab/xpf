package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3672: the remote `show security policies` (non-detail) renderRule printed
// only name / description / raw addresses / action / hits, silently dropping
// security-relevant metadata the gRPC PolicyRule already carries (#3336/#3623/
// #3624):
//
//   - M01: source_address_excluded / destination_address_excluded — an
//     exclusive ("all EXCEPT these") match read identical to an inclusive one,
//     inverting reachability meaning.
//   - M02: log / log_session_init / log_session_close — a logged permit was
//     indistinguishable from an unlogged one; init-only vs close-only hidden.
//   - M03: scheduler_name / inactive — a scheduled rule outside its window
//     printed "Action: permit" with no inactive annotation while the runtime
//     skipped/denied it.
//   - M04: count — a "then count" rule with zero hits printed nothing, so
//     counted-but-idle was indistinguishable from not-counted.
//
// These tests lock the default remote output and are the fail-on-revert guard.

func metadataPoliciesResp() *pb.GetPoliciesResponse {
	return &pb.GetPoliciesResponse{
		Policies: []*pb.PolicyInfo{
			{
				FromZone: "trust",
				ToZone:   "untrust",
				Rules: []*pb.PolicyRule{
					{
						Name:                       "block-except",
						Action:                     "deny",
						SrcAddresses:               []string{"trusted-net"},
						DstAddresses:               []string{"blocked-net"},
						Applications:               []string{"any"},
						SourceAddressExcluded:      true,
						DestinationAddressExcluded: true,
						Log:                        true,
						LogSessionInit:             true,
						LogSessionClose:            true,
						SchedulerName:              "workhours",
						Inactive:                   true,
						Count:                      true,
						// zero hits: HitPackets/HitBytes deliberately unset.
					},
				},
			},
		},
	}
}

// TestRenderRuleSurfacesAllMetadata drives showPoliciesFiltered over a rule with
// every metadata bit set and asserts the non-detail view renders each field.
//
// FAIL-ON-REVERT: restoring the old renderRule (name/desc/raw addr/action/hits)
// drops every one of these lines, so each assertion goes RED.
func TestRenderRuleSurfacesAllMetadata(t *testing.T) {
	fake := &fakeBpfrxClient{
		getPoliciesResp: metadataPoliciesResp(),
		getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{
			{Name: "trust"}, {Name: "untrust"},
		}},
	}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("trust", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})

	// M01: exclusion "(except)" marker on both src and dst.
	if !strings.Contains(out, "src=[trusted-net] (except)") {
		t.Errorf("source-address-excluded not annotated (except):\n%s", out)
	}
	if !strings.Contains(out, "dst=[blocked-net] (except)") {
		t.Errorf("destination-address-excluded not annotated (except):\n%s", out)
	}
	// M02: session log modes.
	if !strings.Contains(out, "Log: at-create, at-close") {
		t.Errorf("log session-init/close modes not rendered:\n%s", out)
	}
	// M03: scheduler name + inactive annotation.
	if !strings.Contains(out, "Scheduler: workhours (inactive)") {
		t.Errorf("scheduler/inactive state not rendered:\n%s", out)
	}
	// M04: counted-but-idle rule shows a zero hit count.
	if !strings.Contains(out, "Hit count: 0 packets, 0 bytes") {
		t.Errorf("counted rule with zero hits did not render count state:\n%s", out)
	}
}

// TestRenderRuleInactiveWithoutScheduler pins the standalone inactive
// annotation for a rule marked inactive without a scheduler name.
func TestRenderRuleInactiveWithoutScheduler(t *testing.T) {
	fake := &fakeBpfrxClient{
		getPoliciesResp: &pb.GetPoliciesResponse{
			Policies: []*pb.PolicyInfo{{
				FromZone: "trust",
				ToZone:   "untrust",
				Rules:    []*pb.PolicyRule{{Name: "r", Action: "permit", Inactive: true}},
			}},
		},
		getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{{Name: "trust"}, {Name: "untrust"}}},
	}
	c := &ctl{client: fake}
	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("trust", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})
	if !strings.Contains(out, "Inactive: true") {
		t.Errorf("inactive-without-scheduler not rendered:\n%s", out)
	}
}

// TestRenderRulePlainRuleUnchanged guards the common path: an ordinary rule with
// no metadata bits set renders no exclusion marker, no Log/Scheduler/Inactive
// line, and no zero hit-count line (byte-identical to the pre-#3672 output).
func TestRenderRulePlainRuleUnchanged(t *testing.T) {
	fake := &fakeBpfrxClient{
		getPoliciesResp: &pb.GetPoliciesResponse{
			Policies: []*pb.PolicyInfo{{
				FromZone: "trust",
				ToZone:   "untrust",
				Rules: []*pb.PolicyRule{{
					Name:         "allow-web",
					Action:       "permit",
					SrcAddresses: []string{"any"},
					DstAddresses: []string{"web"},
					Applications: []string{"junos-http"},
				}},
			}},
		},
		getZonesResp: &pb.GetZonesResponse{Zones: []*pb.ZoneInfo{{Name: "trust"}, {Name: "untrust"}}},
	}
	c := &ctl{client: fake}
	out := captureStdout(t, func() {
		if err := c.showPoliciesFiltered("trust", "untrust", false); err != nil {
			t.Fatalf("showPoliciesFiltered: %v", err)
		}
	})
	for _, unwanted := range []string{"(except)", "Log:", "Scheduler:", "Inactive:", "Hit count:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("plain rule rendered unexpected %q:\n%s", unwanted, out)
		}
	}
}
