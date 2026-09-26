package userspace

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/networkd"
)

// TestApplyConfigPreservesPartialResultOnLateFailure10759 is the #10759
// regression cell: a day-0 import commits (bootstrap-import `ok`) but the first
// boot apply's dataplane step fails LATE — after Compile built the
// interface/networkd models but before the helper accepted the snapshot
// (helper start, apply_snapshot, HA/forwarding sync). Compile returns the built
// result alongside the error, and ApplyConfig must preserve it as a PARTIAL
// ApplyResult instead of discarding it.
//
// The daemon's networkd.Apply call site requires a non-nil result; the old
// ApplyConfig error path discarded its result, so a day-0 failure configured ZERO
// interfaces while import status stayed ok:
// device-map and static-management boxes are console-only with in-band signals
// claiming success. The partial result carries this generation's models so
// networkd still runs; the commit still fails closed via the joined error.
//
// RED-on-revert: restore `if _, err := m.Compile(cfg); err != nil { return nil,
// err }` in Manager.ApplyConfig and `res` below is nil.
func TestApplyConfigPreservesPartialResultOnLateFailure10759(t *testing.T) {
	cfg := scheduledPolicyConfig9520()
	ucfg := deriveUserspaceConfig(cfg)
	m := New()
	// Seeds mirror TestDeferredReplayRetainsMetadataAfterFirstPublishFailure:
	// a live-looking helper so the apply reaches apply_snapshot publication.
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg = ucfg
	m.syncCancel = func() {}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.clearHelperHAStateHook = func() error { return nil }
	m.lastStatus = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
	m.helperStatusObserved = true
	m.xskLivenessProven = true
	seed := mustBuildSnapshot(t, cfg, ucfg, 7, 0)
	m.lastSnapshot = seed
	m.generation = 7
	m.publishedSnapshot = 7
	m.publishedPlanKey = snapshotBindingPlanKey(seed)
	if h, ok := snapshotContentHash(seed); ok {
		m.lastSnapshotHash = h
	}
	// The shim leg succeeds and builds this generation's models — the day-0
	// static-mgmt interface whose .network file must still be written.
	m.compileUserspaceShimHook = func(*config.Config) (*dataplane.CompileResult, error) {
		return &dataplane.CompileResult{
			ManagedInterfaces: []networkd.InterfaceConfig{{
				Name:      "fxp0",
				Addresses: []string{"192.0.2.2/24"},
			}},
			ZoneIDs: map[string]uint16{"trust": 3},
		}, nil
	}
	injected := errors.New("apply_snapshot: connection reset")
	publishes := 0
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			publishes++
			return injected
		}
		if status != nil {
			*status = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
		}
		return nil
	}

	res, err := m.ApplyConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("ApplyConfig with a failing publish must return the error (fail-closed); got nil")
	}
	if publishes == 0 {
		t.Fatalf("reached no apply_snapshot publish (err=%v); the failure fired before the models were consumed and this cell proves nothing", err)
	}
	if res == nil {
		t.Fatal("ApplyConfig discarded the built result on a late failure (got nil result): " +
			"the daemon skips networkd.Apply on a nil result, so a day-0 boot whose " +
			"dataplane step fails configures zero interfaces while import status stays ok (#10759)")
	}
	if len(res.ManagedInterfaces) != 1 || res.ManagedInterfaces[0].Name != "fxp0" {
		t.Fatalf("partial ManagedInterfaces = %+v, want this generation's [fxp0] models", res.ManagedInterfaces)
	}
	if len(res.ManagedInterfaces[0].Addresses) != 1 || res.ManagedInterfaces[0].Addresses[0] != "192.0.2.2/24" {
		t.Fatalf("partial fxp0 addresses = %v, want [192.0.2.2/24]", res.ManagedInterfaces[0].Addresses)
	}
	if res.ZoneIDs["trust"] != 3 {
		t.Fatalf("partial ZoneIDs = %v, want map[trust:3]", res.ZoneIDs)
	}
	// The retained authority must NOT advance: the helper never accepted this
	// snapshot, so LastApplyResult keeps serving the previous (here: none).
	// Publishing the partial as last-good would tell later readers the failed
	// generation is live.
	if got := m.LastApplyResult(); got != nil {
		t.Fatalf("LastApplyResult after a failed apply = %+v, want nil (the partial result must not become the retained authority)", got)
	}
}
