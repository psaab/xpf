package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// TestShowMatchPoliciesHostOriginated16805 pins #16805 on the REMOTE CLI
// surface: a typed host_originated response must render the dedicated
// host-originated verdict, never the unknown-ingress-zone deny or a
// fabricated default line. The unzoned-ingress control is unchanged.
//
// FAIL-ON-REVERT: dropping the GetHostOriginated() branch makes the
// junos-host row fall through to the no-match/default render.
func TestShowMatchPoliciesHostOriginated16805(t *testing.T) {
	fake := &fakeBpfrxClient{matchPoliciesResp: &pb.MatchPoliciesResponse{
		Matched:        false,
		HostOriginated: true,
		Action:         policymatch.HostOriginatedActionString,
	}}
	c := &ctl{client: fake}
	out := captureStdout(t, func() {
		if err := c.showMatchPolicies([]string{"from-zone", "junos-host", "to-zone", "untrust", "protocol", "tcp", "destination-port", "53"}); err != nil {
			t.Fatalf("showMatchPolicies: %v", err)
		}
	})
	if !strings.Contains(out, "Host-originated (from-zone junos-host -> untrust): not evaluated by security policy") || !strings.Contains(out, policymatch.HostOriginatedShowLine) {
		t.Fatalf("host-originated must render its dedicated verdict (#16805):\n%s", out)
	}
	if strings.Contains(out, "Ingress zone unknown") || strings.Contains(out, "No matching policy found") {
		t.Fatalf("host-originated must not fabricate an unzoned/default verdict:\n%s", out)
	}

	// Control: unzoned ingress unchanged.
	fake2 := &fakeBpfrxClient{matchPoliciesResp: &pb.MatchPoliciesResponse{
		Matched:        false,
		UnzonedIngress: true,
		Action:         policymatch.UnzonedIngressActionString,
	}}
	c2 := &ctl{client: fake2}
	out2 := captureStdout(t, func() {
		if err := c2.showMatchPolicies([]string{"from-zone", "nosuch", "to-zone", "untrust"}); err != nil {
			t.Fatalf("showMatchPolicies: %v", err)
		}
	})
	if !strings.Contains(out2, "Ingress zone unknown") || strings.Contains(out2, "Host-originated") {
		t.Fatalf("unzoned-ingress control changed:\n%s", out2)
	}
}
