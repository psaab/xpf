package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

// deferredMACReapplyTestDP is a minimal RuntimeDataPlane whose ApplyConfig can
// be made to fail, recording whether the daemon reacted by recording
// deferred-MAC worker-arm debt (#5134) instead of swallowing the error.
type deferredMACReapplyTestDP struct {
	applyErr    error
	applyCalls  int
	debtRecords int
}

func (d *deferredMACReapplyTestDP) Start(context.Context) error { return nil }
func (d *deferredMACReapplyTestDP) Close() error                { return nil }
func (d *deferredMACReapplyTestDP) Teardown() error             { return nil }

func (d *deferredMACReapplyTestDP) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	d.applyCalls++
	if d.applyErr != nil {
		return nil, d.applyErr
	}
	return &dataplane.ApplyResult{}, nil
}

func (d *deferredMACReapplyTestDP) LastApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{}
}
func (d *deferredMACReapplyTestDP) Link() dataplane.LinkController { return noopLinkController{} }
func (d *deferredMACReapplyTestDP) HA() dataplane.HAController {
	return dataplane.NewDataPlaneHAController(nil)
}
func (d *deferredMACReapplyTestDP) Sessions() dataplane.SessionStore {
	return dataplane.SessionStoreOf(nil)
}
func (d *deferredMACReapplyTestDP) Telemetry() dataplane.Telemetry              { return dataplane.TelemetryOf(nil) }
func (d *deferredMACReapplyTestDP) SessionDeltas() dpruntime.SessionDeltaSource { return nil }

// RecordDeferredWorkerArmDebt is the #5134 debt-recorder the daemon reaches via
// an optional type assertion on d.dp.
func (d *deferredMACReapplyTestDP) RecordDeferredWorkerArmDebt() { d.debtRecords++ }

// TestReapplyAfterDeferredMACRecordsDebtOnFailure is the #5134 daemon contract:
// the MANDATORY re-apply that arms the deferred AF_XDP workers after a live
// RETH virtual-MAC change must NOT swallow its ApplyConfig error into a
// successful commit. On failure it records generation debt so status
// reconciliation retries with DeferWorkers=false and eventually binds workers.
//
// RED-on-revert: reverting reapplyAfterDeferredMAC to the old `slog.Warn(...)`
// (drop the error) makes debtRecords stay 0 — the workerless snapshot then
// stays published while the commit reports success (the silent forwarding
// outage).
func TestReapplyAfterDeferredMACRecordsDebtOnFailure(t *testing.T) {
	withTempTransitForwardSysctls(t, "1") // #9725: the reapply re-reads the transit gate
	dp := &deferredMACReapplyTestDP{applyErr: errors.New("helper rejected apply_snapshot")}
	d := &Daemon{}
	d.setDataplane(dp) // #2114: publish through the cell

	d.reapplyAfterDeferredMAC(&config.Config{})

	if dp.applyCalls != 1 {
		t.Fatalf("ApplyConfig calls = %d, want 1", dp.applyCalls)
	}
	if dp.debtRecords != 1 {
		t.Fatalf("worker-arm debt records = %d, want 1 (failed re-apply must record debt, not swallow)", dp.debtRecords)
	}
}

// TestReapplyAfterDeferredMACNoDebtOnSuccess verifies the happy path records no
// debt: a successful re-apply arms the workers directly, so there is nothing
// for the reconcile loop to retry.
func TestReapplyAfterDeferredMACNoDebtOnSuccess(t *testing.T) {
	withTempTransitForwardSysctls(t, "1") // #9725: the reapply re-reads the transit gate
	dp := &deferredMACReapplyTestDP{}
	d := &Daemon{}
	d.setDataplane(dp) // #2114: publish through the cell

	d.reapplyAfterDeferredMAC(&config.Config{})

	if dp.applyCalls != 1 {
		t.Fatalf("ApplyConfig calls = %d, want 1", dp.applyCalls)
	}
	if dp.debtRecords != 0 {
		t.Fatalf("worker-arm debt records = %d, want 0 on a successful re-apply", dp.debtRecords)
	}
}
