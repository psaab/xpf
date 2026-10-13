package userspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
)

// #7468 / #6707 consequence 1: a rejected policy snapshot disabled
// userspace_ctrl instead of performing an atomic retain.
//
// On the samePlanRefresh path the classifier BPF maps are rewritten to the NEW
// plan BEFORE the publish, so when the helper refuses the snapshot and keeps
// the old one the maps and the enforced snapshot disagree. The pre-#7468
// response was to disable ctrl — correct, but it drops ALL transit for up to a
// second (until the 1 Hz tick re-syncs from m.lastSnapshot) on every rejected
// policy update, and on a FIRST apply it returned before the status loop was
// ever started, so nothing ever re-synced and transit stayed dropped.
//
// #6707's own fix direction — "do not disable ctrl when the helper retained a
// usable snapshot" — is UNSAFE as written and is not what this implements: it
// would leave the maps a generation AHEAD of the enforced snapshot, which is
// the #4959 fail-open. The fix rolls the maps BACK so ctrl can stay enabled
// against a plan that MATCHES what the helper is enforcing.
//
// The discriminator is the error class, and it is the part most worth reading.
// Only an in-band {"ok":false} proves the helper still holds m.lastSnapshot. A
// transport failure proves nothing: controlRoundtripDeadline exists because a
// fixed 3s deadline once "reported the apply FAILED while the dataplane had
// applied it live". Rolling the maps back there would put them a generation
// BEHIND the enforced snapshot — the same fail-open with the sign flipped.

// TestHelperInBandRefusalIsClassified7468 binds the sentinel to the REAL
// control-socket path rather than to a hand-built error.
//
// Without this, every other cell here could pass against a classification the
// production decoder never actually applies: the tests below reach
// retainPreviousClassifierPlanLocked through controlRequestHook, which bypasses
// requestDetailedLocked entirely.
func TestHelperInBandRefusalIsClassified7468(t *testing.T) {
	cases := []struct {
		name string
		// reply is written back to the client; empty means close the
		// connection without answering (the transport-failure control).
		reply       string
		wantInBand  bool
		wantMessage string
	}{
		{
			name:        "helper_nack_is_in_band",
			reply:       `{"ok":false,"error":"snapshot integrity preflight rejected policy content"}`,
			wantInBand:  true,
			wantMessage: "snapshot integrity preflight rejected policy content",
		},
		{
			// The helper answered, but with no message. Still in-band: it
			// decoded and refused, so previous-good is still retained.
			name:       "helper_nack_without_message_is_still_in_band",
			reply:      `{"ok":false}`,
			wantInBand: true,
		},
		{
			// Closed with no response. requestDetailedLocked turns this into
			// the #1961 EOF hint. The helper may or may not have applied it —
			// unknown state, so NOT in-band.
			name:       "eof_without_reply_is_not_in_band",
			reply:      "",
			wantInBand: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock := filepath.Join(shortSockDir9322(t), "ctl.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatalf("listen refusal socket: %v", err)
			}
			defer ln.Close()
			go func() {
				conn, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				defer conn.Close()
				var req ControlRequest
				_ = json.NewDecoder(conn).Decode(&req)
				if tc.reply != "" {
					_, _ = conn.Write([]byte(tc.reply + "\n"))
				}
			}()

			m := New()
			m.cfg.ControlSocket = sock
			_, err = m.requestDetailedLocked(ControlRequest{Type: "apply_snapshot"})
			if err == nil {
				t.Fatal("requestDetailedLocked returned nil; the fixture did not produce a failure")
			}
			if got := errors.Is(err, errHelperRejected); got != tc.wantInBand {
				t.Fatalf("errors.Is(err, errHelperRejected) = %v, want %v (err = %v).\n"+
					"This classification is what gates the atomic retain: a false "+
					"positive here rolls the classifier maps back while the helper "+
					"may already be enforcing the NEW snapshot, which is a fail-open.",
					got, tc.wantInBand, err)
			}
			// The helper's own message must survive verbatim — the sentinel is
			// added beside it, never in front of it.
			if tc.wantMessage != "" && err.Error() != tc.wantMessage {
				t.Fatalf("err.Error() = %q, want the helper's message verbatim %q",
					err.Error(), tc.wantMessage)
			}
		})
	}
}

// TestClassifierPlanRetainablePredicate7468 is the truth table. Each conjunct
// is varied ALONE against an otherwise-retainable input, so a cell names the
// conjunct that was dropped rather than "the predicate broke".
func TestClassifierPlanRetainablePredicate7468(t *testing.T) {
	retained := &ConfigSnapshot{Generation: 7}
	inBand := fmt.Errorf("publish userspace snapshot: %w", newHelperRejection("nope"))
	transport := fmt.Errorf("publish userspace snapshot: %w", errors.New("dial: connection refused"))

	cases := []struct {
		name         string
		mapsMutated  bool
		retained     *ConfigSnapshot
		published    uint64
		cause        error
		want         bool
		whyItMatters string
	}{
		{
			name:        "in_band_refusal_with_a_retained_snapshot_after_an_inplace_refresh",
			mapsMutated: true, retained: retained, published: 7, cause: inBand, want: true,
			whyItMatters: "the only combination in which the helper is known to still hold `retained`",
		},
		{
			name:        "transport_error_is_not_retainable",
			mapsMutated: true, retained: retained, published: 7, cause: transport, want: false,
			whyItMatters: "the helper may already be enforcing the NEW snapshot; " +
				"rolling the maps back would leave them a generation BEHIND it (fail-open)",
		},
		{
			name:        "no_retained_snapshot_is_not_retainable",
			mapsMutated: true, retained: nil, published: 7, cause: inBand, want: false,
			whyItMatters: "a first apply has no previous-good plan; a rollback against nil " +
				"would clear the classifier maps with ctrl still enabled (fail-open)",
		},
		{
			name:        "bootstrap_path_is_not_retainable",
			mapsMutated: false, retained: retained, published: 7, cause: inBand, want: false,
			whyItMatters: "the maps were never rewritten to the new plan and ctrl is already 0",
		},
		{
			// #9337. The deferred-publish path: applyCompiledSnapshot's
			// pendingXSKStartup branch advanced m.lastSnapshot to 7 and
			// returned, so the helper is still enforcing generation 3.
			// "Rolling back" to 7 rewrites the plan that was just refused
			// and leaves ctrl enabled against a plan the helper never
			// accepted.
			name:        "retained_snapshot_the_helper_never_received_is_not_retainable",
			mapsMutated: true, retained: retained, published: 3, cause: inBand, want: false,
			whyItMatters: "an in-band refusal proves the helper still holds what it held BEFORE " +
				"the request — m.publishedSnapshot. When m.lastSnapshot has run ahead of it " +
				"(the pendingXSKStartup deferral) it is not a rollback target at all",
		},
		{
			// The conjunct is an EQUALITY, not an ordering. `>=` / `<=` would
			// pass a helper holding a DIFFERENT generation than `retained` in
			// one direction and stay green at exactly the value that collides
			// — the same shape ensureEgressZoneProtocolLocked argues for. The
			// Manager cannot currently reach published > lastSnapshot
			// (every site advances both together; only the pendingXSKStartup
			// deferral separates them, and it raises lastSnapshot), so this
			// cell pins the predicate's SHAPE rather than a reachable defect.
			name:        "a_helper_holding_a_newer_generation_is_not_retainable",
			mapsMutated: true, retained: retained, published: 9, cause: inBand, want: false,
			whyItMatters: "retainability is `the helper holds exactly this plan`; an ordering " +
				"test admits a helper holding some other plan and rolls the maps onto it",
		},
		{
			name:        "nothing_published_yet_is_not_retainable",
			mapsMutated: true, retained: &ConfigSnapshot{}, published: 0, cause: inBand, want: false,
			whyItMatters: "publishedGeneration 0 means this Manager published nothing, so the " +
				"helper holds no plan of ours; a zero-valued snapshot must not satisfy the equality",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifierPlanRetainable(tc.mapsMutated, tc.retained, tc.published, tc.cause); got != tc.want {
				t.Fatalf("classifierPlanRetainable = %v, want %v — %s", got, tc.want, tc.whyItMatters)
			}
		})
	}
}

// TestRejectedPublishRollsMapsBackOnlyForAnInBandRefusal7468 drives the real
// publish path and observes WHICH snapshot the classifier maps were synced to.
//
// The observable is the seam, not the BPF maps: unprivileged, every map write
// no-ops, so "rolled back to the retained plan" and "never attempted" would be
// indistinguishable. The assertion is on the snapshot IDENTITY — syncing to the
// refused snapshot would be a no-op dressed as a rollback.
func TestRejectedPublishRollsMapsBackOnlyForAnInBandRefusal7468(t *testing.T) {
	retained := &ConfigSnapshot{Generation: 41}
	refused := &ConfigSnapshot{Generation: 42}

	cases := []struct {
		name         string
		publishErr   error
		wantRollback bool
	}{
		{"in_band_refusal_rolls_back", newHelperRejection("integrity preflight rejected"), true},
		{"transport_failure_does_not_roll_back", errors.New("write: broken pipe"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.lastSnapshot = retained
			// #9337: the retain is only legitimate when the helper is actually
			// holding `retained` — i.e. when m.publishedSnapshot names it. The
			// ordinary Compile path always satisfies that (m.lastSnapshot and
			// m.publishedSnapshot advance together on success), so modelling it
			// is modelling production, not accommodating the predicate.
			m.publishedSnapshot = retained.Generation
			var syncedTo []*ConfigSnapshot
			m.syncClassifierMapsHook = func(s *ConfigSnapshot) error {
				syncedTo = append(syncedTo, s)
				return nil
			}
			m.controlRequestHook = func(ControlRequest, *ProcessStatus) error { return tc.publishErr }

			var status ProcessStatus
			prepareSnapshotForApply(refused)
			err := m.publishPreparedSnapshotFailClosedLocked(refused, &status, true)
			if m.syncCancel != nil {
				defer m.syncCancel()
			}

			// The apply still fails closed either way.
			if err == nil {
				t.Fatal("prepared fail-closed publish returned nil on a rejected publish")
			}
			if !errors.Is(err, tc.publishErr) {
				t.Fatalf("returned error = %v, want it to wrap the publish failure", err)
			}

			if tc.wantRollback {
				if len(syncedTo) != 1 {
					t.Fatalf("classifier maps synced %d times, want exactly 1 rollback. "+
						"Without it transit drops on EVERY rejected policy update until "+
						"the next 1 Hz tick re-syncs from m.lastSnapshot (#6707 criterion 1).",
						len(syncedTo))
				}
				if syncedTo[0] != retained {
					t.Fatalf("classifier maps rolled back to generation %d, want the RETAINED "+
						"snapshot (generation %d). Syncing to the refused snapshot re-applies "+
						"the plan the helper just refused — the maps stay a generation ahead "+
						"of what it enforces, which is the #4959 fail-open.",
						syncedTo[0].Generation, retained.Generation)
				}
				return
			}
			if len(syncedTo) != 0 {
				t.Fatalf("classifier maps were rolled back after a TRANSPORT failure "+
					"(synced to generation %d). The helper's state is unknown there and it "+
					"may already be enforcing the refused snapshot — controlRoundtripDeadline "+
					"exists because a deadline once reported an apply FAILED while the "+
					"dataplane had applied it live. Rolling back leaves the maps a "+
					"generation BEHIND: fail-open.", syncedTo[0].Generation)
			}
		})
	}
}

// TestRollbackFailureFallsBackToTheCtrlDisable7468: if the rollback itself
// fails the maps are an unknown mix of two plans, which is worse than either.
// Both errors must reach the caller — the rollback failure is the actionable
// one and must not be swallowed by the publish error that preceded it.
func TestRollbackFailureFallsBackToTheCtrlDisable7468(t *testing.T) {
	m := New()
	m.lastSnapshot = &ConfigSnapshot{Generation: 41}
	m.publishedSnapshot = 41 // #9337: the helper is holding the retained plan
	rollbackErr := errors.New("ingress ifindex map update: EPERM")
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return rollbackErr }
	publishErr := newHelperRejection("integrity preflight rejected")
	m.controlRequestHook = func(ControlRequest, *ProcessStatus) error { return publishErr }

	var status ProcessStatus
	publishSnap := &ConfigSnapshot{Generation: 42}
	prepareSnapshotForApply(publishSnap)
	err := m.publishPreparedSnapshotFailClosedLocked(publishSnap, &status, true)
	if m.syncCancel != nil {
		defer m.syncCancel()
	}
	if err == nil {
		t.Fatal("prepared fail-closed publish returned nil after a failed rollback")
	}
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("returned error = %v, want it to carry the ROLLBACK failure; "+
			"that is the actionable one and the operator cannot act on a publish "+
			"error that hides it", err)
	}
	if !errors.Is(err, publishErr) {
		t.Fatalf("returned error = %v, want it to still carry the publish refusal", err)
	}
}

// TestRejectedFirstPublishStartsTheReconcileWorker7468 is #6707 acceptance
// criterion 2's second half.
//
// The normal m.ensureStatusLoopLocked() call sits FURTHER DOWN
// applyCompiledSnapshot than the publish-rejection return, so a first-apply
// rejection left the manager inert: no status tick, no classifier re-sync, no
// retry-debt consumer, and transit dropped until the operator commits again.
// This is the same hazard #5873 fixed one branch away for the HA-clear debt.
//
// syncCancel is the established unprivileged observable for "a reconcile worker
// exists" (manager_ha_clear_debt_5873_test.go).
func TestRejectedFirstPublishStartsTheReconcileWorker7468(t *testing.T) {
	for _, mapsMutatedInPlace := range []bool{false, true} {
		name := "bootstrap_path"
		if mapsMutatedInPlace {
			name = "same_plan_path"
		}
		t.Run(name, func(t *testing.T) {
			m := New()
			if m.syncCancel != nil {
				t.Fatal("test precondition: syncCancel should be nil before any apply")
			}
			m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
			m.controlRequestHook = func(ControlRequest, *ProcessStatus) error {
				return newHelperRejection("integrity preflight rejected")
			}
			var status ProcessStatus
			publishSnap := &ConfigSnapshot{Generation: 1}
			prepareSnapshotForApply(publishSnap)
			if err := m.publishPreparedSnapshotFailClosedLocked(publishSnap, &status, mapsMutatedInPlace); err == nil {
				t.Fatal("prepared fail-closed publish returned nil on a rejected publish")
			}
			if m.syncCancel == nil {
				t.Fatal("no reconcile worker after a rejected publish (syncCancel == nil): " +
					"the manager is inert — nothing re-syncs the classifier maps, " +
					"nothing consumes a retry debt, and on a first apply transit stays " +
					"dropped until the operator commits again (#6707 criterion 2)")
			}
			m.syncCancel()
		})
	}
}

// TestNoSnapshotCannotEnableCtrl7468 is the SAFETY PRECONDITION for starting
// that worker, and the open question #7468 said had to be settled first.
//
// Starting a reconcile worker behind a rejected FIRST snapshot would be a
// fail-open if the tick could arm ctrl with m.lastSnapshot == nil: the shim
// would steer against empty classifier maps, i.e. XDP_PASS to the kernel for
// transit. It cannot, and the reason is on the helper side —
// `status.enabled = forwarding_armed && ... && !bindings.is_empty() && ...`
// (userspace-dp/src/server/helpers/status.rs). A helper holding no snapshot
// reports no bindings, so Enabled is false and resolveCtrlEnableLocked never
// reaches its arming branch.
//
// Asserted here against resolveCtrlEnableLocked directly so the claim is a
// test, not a sentence in a comment.
func TestNoSnapshotCannotEnableCtrl7468(t *testing.T) {
	m := New()
	if m.lastSnapshot != nil {
		t.Fatal("test precondition: lastSnapshot should be nil on a fresh manager")
	}
	// A helper with no snapshot: no bindings, so it reports Enabled=false.
	status := ProcessStatus{Enabled: false}
	ctrl := userspaceCtrlValue{Enabled: 0}
	m.resolveCtrlEnableLocked(&status, &ctrl)
	if ctrl.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d with no applied snapshot; the shim would steer "+
			"transit against empty classifier maps and pass it to the kernel unfiltered",
			ctrl.Enabled)
	}

	// Positive control: the gate is not simply stuck at 0. With the helper
	// reporting Enabled the function enters its arming branch and consults the
	// readiness gates — which is the behaviour the cell above must be
	// distinguishing itself from, not an accident of a dead code path.
	armed := ProcessStatus{Enabled: true}
	ctrl2 := userspaceCtrlValue{Enabled: 1}
	m.resolveCtrlEnableLocked(&armed, &ctrl2)
	if !m.neighborsPrewarmed {
		t.Fatal("resolveCtrlEnableLocked did not reach its arming branch for an " +
			"Enabled helper (neighborsPrewarmed still false); the negative cell " +
			"above is then vacuous — it would pass against a gate that is simply " +
			"stuck at 0 for every input")
	}
}
