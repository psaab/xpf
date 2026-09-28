// #5810 / #5851: the gRPC loopback SystemAction handler and the fabric
// allowlist interceptor share ONE strict cluster-failover grammar
// (pkg/clusterfailover). A malformed failover action must be rejected with
// InvalidArgument BEFORE any cluster method or peer dial, and the loopback
// handler and the fabric gate must never disagree about which action strings
// are well-formed.
//
// RED on revert: restoring the loose loopback parsing — e.g. the
// `if nodeStr != ""` fall-through that treated `cluster-failover:1:node`
// (empty node suffix) as "no target" — makes that action reach
// ManualFailover(1). On an un-configured manager ManualFailover returns
// NotFound, so the InvalidArgument assertion below flips to NotFound and the
// reject table goes RED.

package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
	"github.com/psaab/xpf/pkg/clusterfailover/grammarvectors"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSystemActionFailoverRejects_5810 pins that every malformed failover
// action is rejected with InvalidArgument and never proxies to a peer.
func TestSystemActionFailoverRejects_5810(t *testing.T) {
	for _, action := range grammarvectors.ActionRejects {
		t.Run(action, func(t *testing.T) {
			s := &Server{cluster: cluster.NewManager(0, 1)}
			s.peerSystemActionFn = func(context.Context, *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
				t.Fatalf("rejected action %q was proxied to a peer", action)
				return nil, nil
			}
			_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: action})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("SystemAction(%q) code = %v (%v); want InvalidArgument — a malformed "+
					"failover form must fail before any cluster call", action, status.Code(err), err)
			}
		})
	}
}

// TestSystemActionFailoverAccepts_5810 pins that every well-formed failover
// action PASSES the grammar at the handler: it is never rejected as
// InvalidArgument (any error it returns is a cluster-state error, not a grammar
// rejection).
func TestSystemActionFailoverAccepts_5810(t *testing.T) {
	for _, tc := range grammarvectors.ActionAccepts {
		t.Run(tc.Name, func(t *testing.T) {
			s := &Server{cluster: cluster.NewManager(0, 1)}
			s.peerSystemActionFn = func(context.Context, *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
				return &pb.SystemActionResponse{Message: "proxied"}, nil
			}
			_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: tc.Action})
			if status.Code(err) == codes.InvalidArgument {
				t.Fatalf("SystemAction(%q) = InvalidArgument (%v); a well-formed failover action "+
					"must not be rejected by the grammar", tc.Action, err)
			}
		})
	}
}

// TestFailoverParseAgreement_5810 mechanically compares the shared parser, the
// loopback handler's routing, and the fabric gate so they cannot drift: for
// failover actions the fabric gate admits iff the shared parser accepts it AND
// it names a target node (Targeted). The fabric gate also admits the separately
// authorized exact persistent-NAT clear action. Every reject vector is denied.
func TestFailoverParseAgreement_5810(t *testing.T) {
	for _, tc := range grammarvectors.ActionAccepts {
		op, err := clusterfailover.ParseAction(tc.Action)
		if err != nil {
			t.Fatalf("ParseAction(%q) unexpected error: %v", tc.Action, err)
		}
		want := op.Targeted()
		got := isFabricSafeSystemAction(&pb.SystemActionRequest{Action: tc.Action})
		if got != want {
			t.Errorf("isFabricSafeSystemAction(%q) = %v, want %v (Targeted); "+
				"fabric gate disagrees with the shared parser", tc.Action, got, want)
		}
	}
	for _, action := range grammarvectors.ActionRejects {
		if _, err := clusterfailover.ParseAction(action); err == nil {
			t.Errorf("ParseAction(%q) accepted a reject vector", action)
		}
		if isFabricSafeSystemAction(&pb.SystemActionRequest{Action: action}) {
			t.Errorf("isFabricSafeSystemAction(%q) = true; a malformed failover action "+
				"must be denied at the fabric gate", action)
		}
	}
}
