// #3408: gRPC structured GetZones / GetPolicies must fail with codes.Internal
// when a per-zone / per-policy counter read fails, rather than returning
// clean-zero counter fields — the same contract as GetGlobalStats (#3345).
//
// FAIL-ON-REVERT: restoring the `err == nil` swallow (dropping the readErr
// capture + the codes.Internal return) makes both RPCs return a non-error
// zero-counter response and the want-Internal assertions go RED.
package grpcapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type policyZoneErrGRPCDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *policyZoneErrGRPCDP) IsLoaded() bool { return true }

func (d *policyZoneErrGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

func (d *policyZoneErrGRPCDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

func (d *policyZoneErrGRPCDP) ReadZoneCounters(uint32, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

func TestGetPoliciesFailsOnCounterReadError(t *testing.T) {
	// newSchedulerCounterGRPCStore enables policy-stats + has counted policies,
	// so a per-policy read is attempted.
	s := &Server{store: newSchedulerCounterGRPCStore(t), dp: &policyZoneErrGRPCDP{Manager: dataplane.New()}}

	_, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err == nil {
		t.Fatal("GetPolicies returned nil error on policy counter read failure; want codes.Internal")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetPolicies error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}

func TestGetZonesFailsOnCounterReadError(t *testing.T) {
	s := &Server{
		store: newSchedulerCounterGRPCStore(t),
		dp: &policyZoneErrGRPCDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1, "untrust": 2, "dmz": 3}},
		},
	}

	_, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err == nil {
		t.Fatal("GetZones returned nil error on zone counter read failure; want codes.Internal")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetZones error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}
