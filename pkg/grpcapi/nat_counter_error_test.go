// #5046: the gRPC NAT-stats RPCs must fail with codes.Internal when an
// authoritative telemetry read fails, rather than returning a clean
// zero-usage / zero-hit response — the same #3345/#3408 counter-error contract
// as GetZones / GetPolicies.
//
// FAIL-ON-REVERT: restoring the `if err == nil` swallow (dropping the
// codes.Internal return / the readCounter error propagation) makes both RPCs
// return a non-error zero-counter response and the want-Internal assertions go
// RED.
package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// natPortCtrErrGRPCDP is a loaded DP whose NAT port counter read FAILS. It has
// no Telemetry() method, so TelemetryOf wraps it and routes NATPortCounter
// through this override.
type natPortCtrErrGRPCDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *natPortCtrErrGRPCDP) IsLoaded() bool                          { return true }
func (d *natPortCtrErrGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.result.Clone() }

// #8606: the RPC's occupancy source moved from the legacy `nat_port_counters`
// map (a rand.Uint64() seed with no writer since #1476) to the helper's live
// status, so the failure this fixture injects is a STATUS read failure. The
// contract under test is unchanged -- a failed read must fail the RPC as
// unavailable rather than return a healthy zero-usage pool (#5046, #3345).
func (d *natPortCtrErrGRPCDP) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, errors.New("nat status bridge degraded")
}

// Telemetry routes reads through THIS mock (not the embedded Manager's promoted
// Telemetry(), which would wrap the raw Manager and bypass the override above).
func (d *natPortCtrErrGRPCDP) Telemetry() dataplane.Telemetry {
	return dataplane.NewDataPlaneTelemetry(d)
}

// natRuleCtrErrGRPCDP is a loaded DP whose NAT rule counter read FAILS.
type natRuleCtrErrGRPCDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *natRuleCtrErrGRPCDP) IsLoaded() bool                          { return true }
func (d *natRuleCtrErrGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.result.Clone() }
func (d *natRuleCtrErrGRPCDP) ReadNATRuleCounter(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("nat rule counter bridge degraded")
}

// Telemetry routes reads through THIS mock (not the embedded Manager's promoted
// Telemetry(), which would wrap the raw Manager and bypass the override above).
func (d *natRuleCtrErrGRPCDP) Telemetry() dataplane.Telemetry {
	return dataplane.NewDataPlaneTelemetry(d)
}

func newNATPoolStatsGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set security zones security-zone trust
set security zones security-zone untrust
set security nat source pool p1 address 203.0.113.10/32
set security nat source rule-set rs from zone trust
set security nat source rule-set rs to zone untrust
set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8
set security nat source rule-set rs rule r1 then source-nat pool p1`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestGetNATPoolStatsFailsOnRuntimeStatusReadError(t *testing.T) {
	s := &Server{
		store: newNATPoolStatsGRPCStore(t),
		dp: &natPortCtrErrGRPCDP{
			Manager: dataplane.New(),
			result:  &dataplane.ApplyResult{PoolIDs: map[string]uint8{"p1": 7}},
		},
	}

	_, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err == nil {
		t.Fatal("GetNATPoolStats returned nil error on runtime status read failure; want codes.Internal")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetNATPoolStats error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}

func TestGetNATRuleStatsFailsOnRuleCounterReadError(t *testing.T) {
	s := &Server{
		store: newNATStatsGRPCStore(t),
		dp: &natRuleCtrErrGRPCDP{
			Manager: dataplane.New(),
			result: &dataplane.ApplyResult{
				NATCounterIDs: map[string]uint32{
					dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r1"): 21,
					dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r2"): 22,
				},
			},
		},
	}

	_, err := s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{})
	if err == nil {
		t.Fatal("GetNATRuleStats returned nil error on rule counter read failure; want codes.Internal")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetNATRuleStats error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}
