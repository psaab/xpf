package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// server_matchpolicies_ingress_iface_5579_test.go pins the #5579 gRPC
// ingress-interface selector. A mixed `trust` zone exposes ssh host-inbound on
// ge-0/0/0.0 only; the sibling ge-0/0/1.0 default-denies host SSH. Before #5579
// the gRPC match-policies host-inbound classifier folded every effective view in
// the zone with a first-admit OR, reporting a zone-wide TOKEN_ADMIT/ssh even for a
// packet entering ge-0/0/1.0 — a false admission. It now scopes to one interface's
// TRUE posture when ingress_interface is set, and reports AMBIGUOUS when the
// per-interface views disagree.

// mixedHostInboundGRPCStore builds the mixed-zone config via set commands.
func mixedHostInboundGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.10/24
set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.10/24
set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh
set security zones security-zone trust interfaces ge-0/0/1.0
set security policies default-policy deny-all`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestMatchPoliciesGRPCIngressInterfaceScopesHostInbound is the gRPC
// fail-on-revert for #5579.
//
// RED-on-revert: drop the ingress_interface plumbing (Query.IngressInterface or
// ClassifyHostInboundForInterface) and the ge-0/0/1.0 query folds to the zone-wide
// first-admit — TOKEN_ADMIT/ssh instead of DENIED. Drop the per-view ambiguity and
// the unqualified query returns TOKEN_ADMIT/ssh instead of AMBIGUOUS.
func TestMatchPoliciesGRPCIngressInterfaceScopesHostInbound(t *testing.T) {
	s := &Server{store: mixedHostInboundGRPCStore(t)}

	base := func() *pb.MatchPoliciesRequest {
		return &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "junos-host", Protocol: "tcp", DestinationPort: int32Ptr17081(22)}
	}

	// ge-0/0/0.0 (ssh override) — admits.
	admitReq := base()
	admitReq.IngressInterface = "ge-0/0/0.0"
	admit, err := s.MatchPolicies(context.Background(), admitReq)
	if err != nil {
		t.Fatalf("MatchPolicies(ge-0/0/0.0) error = %v", err)
	}
	if admit.HostInbound == nil ||
		admit.HostInbound.Status != pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_TOKEN_ADMIT ||
		admit.HostInbound.Token != "ssh" {
		t.Errorf("ge-0/0/0.0 host_inbound = %+v, want TOKEN_ADMIT/ssh", admit.HostInbound)
	}

	// ge-0/0/1.0 (no override) — TRUE posture is DENY, not the zone-wide ssh. Core fix.
	denyReq := base()
	denyReq.IngressInterface = "ge-0/0/1.0"
	deny, err := s.MatchPolicies(context.Background(), denyReq)
	if err != nil {
		t.Fatalf("MatchPolicies(ge-0/0/1.0) error = %v", err)
	}
	if deny.HostInbound == nil ||
		deny.HostInbound.Status != pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_DENIED {
		t.Errorf("ge-0/0/1.0 host_inbound = %+v, want DENIED (false-admission #5579)", deny.HostInbound)
	}

	// Unqualified — the per-interface views disagree, so report AMBIGUOUS.
	amb, err := s.MatchPolicies(context.Background(), base())
	if err != nil {
		t.Fatalf("MatchPolicies(unqualified) error = %v", err)
	}
	if amb.HostInbound == nil ||
		amb.HostInbound.Status != pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_AMBIGUOUS {
		t.Errorf("unqualified host_inbound = %+v, want AMBIGUOUS", amb.HostInbound)
	}
}

// TestMatchPoliciesGRPCIngressInterfaceRejectsBadRef pins the fail-closed
// validation: an unknown / zone-mismatched ingress_interface is InvalidArgument.
func TestMatchPoliciesGRPCIngressInterfaceRejectsBadRef(t *testing.T) {
	s := &Server{store: mixedHostInboundGRPCStore(t)}

	_, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "junos-host", Protocol: "tcp", DestinationPort: int32Ptr17081(22),
		IngressInterface: "ge-9/9/9.9",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("unknown ingress_interface error code = %v, want InvalidArgument", status.Code(err))
	}
}
