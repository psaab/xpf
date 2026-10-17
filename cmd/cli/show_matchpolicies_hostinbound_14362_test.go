package main

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// TestShowMatchPoliciesHostInboundVerdict14362 pins #14362 on the REMOTE CLI
// surface: the structured MatchPolicies RPC already carries the
// host-inbound-traffic admission (proto field 21, populated by the server on
// both host-bound returns), but showMatchPolicies never rendered it — a
// matched `to-zone junos-host` permit whose coarse host-inbound gate DENIES
// printed as an unqualified "Action: permit", and the unmatched branch printed
// only the generic HostInboundShowLine without the deny/token detail the
// local CLI prints (#3627 B1a / #5649).
//
// RED-on-revert: dropping the GetHostInbound() rendering in either branch
// makes the "host-inbound-traffic (zone trust): DENIED ..." assertion fail;
// dropping the unzoned/content-rejected/unsupported branches makes those
// verdicts fall through to a fabricated "(permit (default))" / default line.
func TestShowMatchPoliciesHostInboundVerdict14362(t *testing.T) {
	denied := "DENIED by host-inbound-traffic — no system-service/protocol admits this tuple, so the box drops it"

	t.Run("matched permit still names coarse deny", func(t *testing.T) {
		fake := &fakeBpfrxClient{matchPoliciesResp: &pb.MatchPoliciesResponse{
			Matched:    true,
			PolicyName: "allow-host",
			Action:     "permit",
			HostInbound: &pb.HostInboundAdmission{
				Status:      pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_DENIED,
				Description: denied,
			},
		}}
		c := &ctl{client: fake}
		out := captureStdout(t, func() {
			if err := c.showMatchPolicies([]string{"from-zone", "trust", "to-zone", "junos-host", "protocol", "tcp", "destination-port", "23"}); err != nil {
				t.Fatalf("showMatchPolicies: %v", err)
			}
		})
		if !strings.Contains(out, "Action: permit") {
			t.Fatalf("matched output missing policy action:\n%s", out)
		}
		if !strings.Contains(out, "host-inbound-traffic (zone trust): "+denied) {
			t.Fatalf("matched junos-host permit must name the coarse host-inbound deny (#14362):\n%s", out)
		}
	})

	t.Run("unmatched names coarse deny", func(t *testing.T) {
		fake := &fakeBpfrxClient{matchPoliciesResp: &pb.MatchPoliciesResponse{
			Matched:              false,
			HostInboundUnmatched: true,
			Action:               policymatch.HostInboundActionString,
			HostInbound: &pb.HostInboundAdmission{
				Status:      pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_DENIED,
				Description: denied,
			},
		}}
		c := &ctl{client: fake}
		out := captureStdout(t, func() {
			if err := c.showMatchPolicies([]string{"from-zone", "trust", "to-zone", "junos-host", "protocol", "tcp", "destination-port", "23"}); err != nil {
				t.Fatalf("showMatchPolicies: %v", err)
			}
		})
		if !strings.Contains(out, policymatch.HostInboundShowLine) {
			t.Fatalf("unmatched output missing SSOT HostInboundShowLine:\n%s", out)
		}
		if !strings.Contains(out, "host-inbound-traffic (zone trust): "+denied) {
			t.Fatalf("unmatched junos-host must name the coarse host-inbound deny (#14362):\n%s", out)
		}
	})

	t.Run("unzoned ingress is not a default verdict", func(t *testing.T) {
		fake := &fakeBpfrxClient{matchPoliciesResp: &pb.MatchPoliciesResponse{
			Matched:        false,
			UnzonedIngress: true,
			Action:         policymatch.UnzonedIngressActionString,
		}}
		c := &ctl{client: fake}
		out := captureStdout(t, func() {
			if err := c.showMatchPolicies([]string{"from-zone", "noz", "to-zone", "untrust"}); err != nil {
				t.Fatalf("showMatchPolicies: %v", err)
			}
		})
		if !strings.Contains(out, "Ingress zone unknown") || !strings.Contains(out, policymatch.UnzonedIngressShowLine) {
			t.Fatalf("unzoned ingress must render its dedicated verdict (#14362):\n%s", out)
		}
		if strings.Contains(out, "No matching policy found") {
			t.Fatalf("unzoned ingress must not fabricate a default verdict:\n%s", out)
		}
	})

	t.Run("unzoned egress is not a default verdict", func(t *testing.T) {
		fake := &fakeBpfrxClient{matchPoliciesResp: &pb.MatchPoliciesResponse{
			Matched:       false,
			UnzonedEgress: true,
			Action:        policymatch.UnzonedEgressActionString,
		}}
		c := &ctl{client: fake}
		out := captureStdout(t, func() {
			if err := c.showMatchPolicies([]string{"from-zone", "trust", "to-zone", "noz"}); err != nil {
				t.Fatalf("showMatchPolicies: %v", err)
			}
		})
		if !strings.Contains(out, "Egress zone unknown") || !strings.Contains(out, policymatch.UnzonedEgressShowLine) {
			t.Fatalf("unzoned egress must render its dedicated verdict (#14362):\n%s", out)
		}
	})

	t.Run("content rejected is not a verdict", func(t *testing.T) {
		fake := &fakeBpfrxClient{matchPoliciesResp: &pb.MatchPoliciesResponse{
			Matched:         false,
			ContentRejected: true,
			Action:          policymatch.ContentRejectedActionString,
		}}
		c := &ctl{client: fake}
		out := captureStdout(t, func() {
			if err := c.showMatchPolicies([]string{"from-zone", "trust", "to-zone", "untrust"}); err != nil {
				t.Fatalf("showMatchPolicies: %v", err)
			}
		})
		if !strings.Contains(out, policymatch.ContentRejectedShowLine) {
			t.Fatalf("content-rejected must render the fail-closed line (#14362):\n%s", out)
		}
		if strings.Contains(out, "No matching policy found") {
			t.Fatalf("content-rejected must not fabricate a default verdict:\n%s", out)
		}
	})

	t.Run("unsupported tuple family is not a default verdict", func(t *testing.T) {
		fake := &fakeBpfrxClient{matchPoliciesResp: &pb.MatchPoliciesResponse{
			Matched:                false,
			UnsupportedTupleFamily: true,
			Action:                 policymatch.UnsupportedTupleFamilyActionString,
		}}
		c := &ctl{client: fake}
		out := captureStdout(t, func() {
			if err := c.showMatchPolicies([]string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.0.1", "destination-ip", "2001:db8::1", "protocol", "tcp"}); err != nil {
				t.Fatalf("showMatchPolicies: %v", err)
			}
		})
		if !strings.Contains(out, policymatch.UnsupportedTupleFamilyActionString) {
			t.Fatalf("unsupported tuple must render its dedicated verdict (#14362):\n%s", out)
		}
	})
}
