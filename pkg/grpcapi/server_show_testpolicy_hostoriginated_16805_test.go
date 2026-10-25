package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// TestShowTestPolicyHostOriginated16805 pins #16805 on the gRPC ShowText
// `test-policy:` surface: a `from=junos-host` query must print the
// host-originated verdict, never "Ingress zone unknown". The `from=nosuch`
// and `to=junos-host` controls are unchanged.
//
// FAIL-ON-REVERT: removing the policymatch host-originated arm (or the
// HostOriginated case in showTestPolicy) makes the junos-host row render
// the unzoned-ingress deny.
func TestShowTestPolicyHostOriginated16805(t *testing.T) {
	s := &Server{store: hostInboundStore(t)}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic: "test-policy:from=junos-host,to=untrust,proto=tcp,port=53",
	})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	if !strings.Contains(resp.Output, "Host-originated (from-zone junos-host -> untrust): not evaluated by security policy") ||
		!strings.Contains(resp.Output, policymatch.HostOriginatedShowLine) {
		t.Fatalf("want host-originated verdict, got:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "Ingress zone unknown") {
		t.Fatalf("host-originated must not print an unzoned verdict:\n%s", resp.Output)
	}

	// Control: genuinely unknown from-zone unchanged.
	nosuch, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic: "test-policy:from=nosuch,to=untrust,proto=tcp,port=80",
	})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	if !strings.Contains(nosuch.Output, "Ingress zone unknown") || strings.Contains(nosuch.Output, "Host-originated") {
		t.Fatalf("from=nosuch control changed:\n%s", nosuch.Output)
	}

	// Control: host-bound to-zone unchanged.
	hi, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic: "test-policy:from=trust,to=junos-host,proto=tcp,port=22",
	})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	if !strings.Contains(hi.Output, "No matching to-zone junos-host policy") || strings.Contains(hi.Output, "Host-originated") {
		t.Fatalf("to=junos-host control changed:\n%s", hi.Output)
	}
}
