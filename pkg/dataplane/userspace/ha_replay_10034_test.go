package userspace

import (
	"errors"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #10034: a timeout-but-landed apply_snapshot is retained as retry debt. The
// debt retry in syncSnapshotLocked must replay the same HA tail as Compile:
// refresh the clustered inventory from maps and publish it, or clear stale HA
// state on a standalone transition. These cells deliberately model a helper
// respawn (helperHAStatePublished=false) so watchdog/election timing cannot
// satisfy the property by accident.

type haReplayRecorder10034 struct {
	mu            sync.Mutex
	refreshCalls  int
	stateRequests []HAStateUpdateRequest
	haErrors      []error
}

func (r *haReplayRecorder10034) install(h *debtHarness9642, clustered bool) {
	h.m.clusterHA = clustered
	h.m.haGroups = map[int]HAGroupStatus{
		1: {RGID: 1, Active: false, WatchdogTimestamp: 101},
		2: {RGID: 2, Active: true, WatchdogTimestamp: 202},
	}
	// The process may have been respawned while the snapshot was debt. A new
	// helper starts with no inventory even though m.haGroups remains authoritative.
	h.m.helperHAStatePublished = false
	h.m.refreshHAStateFromMapsHook = func() error {
		r.mu.Lock()
		r.refreshCalls++
		r.mu.Unlock()
		return nil
	}
	baseHook := h.m.controlRequestHook
	h.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "update_ha_state" && req.HAState != nil {
			r.mu.Lock()
			r.stateRequests = append(r.stateRequests, HAStateUpdateRequest{
				Groups: append([]HAGroupStatus(nil), req.HAState.Groups...),
			})
			var err error
			if len(r.haErrors) > 0 {
				err = r.haErrors[0]
				r.haErrors = r.haErrors[1:]
			}
			r.mu.Unlock()
			if err != nil {
				return err
			}
		}
		return baseHook(req, status)
	}
}

func (r *haReplayRecorder10034) setHAErrors(errs []error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.haErrors = append([]error(nil), errs...)
}

func (r *haReplayRecorder10034) snapshot() (int, []HAStateUpdateRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.refreshCalls, append([]HAStateUpdateRequest(nil), r.stateRequests...)
}

func setupDebtConvergence10034(t *testing.T, clustered bool) (*debtHarness9642, *haReplayRecorder10034) {
	t.Helper()
	h := newDebtHarness9642(t)
	recorder := &haReplayRecorder10034{}
	retained, attempted := buildDebtPair9642(t, false /* same plan: no restart branch */)
	h.seedPublished(t, retained)
	h.m.mu.Lock()
	recorder.install(h, clustered)
	h.m.mu.Unlock()

	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, true); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: transport failure must fail the publish")
	}
	h.m.mu.Unlock()
	// The failed publish starts the status worker as the production retry
	// consumer. Join it before changing the scripted helper response.
	h.stopLoop(t)

	h.mu.Lock()
	h.applyErr = nil
	h.statusGen = attempted.Generation
	h.mu.Unlock()
	return h, recorder
}

func startSleep10034(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

func setupChangedPlanDebtConvergence10034(t *testing.T, clustered bool) (*debtHarness9642, *haReplayRecorder10034) {
	t.Helper()
	h := newDebtHarness9642(t)
	recorder := &haReplayRecorder10034{}
	retained, attempted := buildDebtPair9642(t, true /* changed plan: exercise restart */)
	h.seedPublished(t, retained)
	sleep1 := startSleep10034(t)
	sleep2 := startSleep10034(t)
	h.m.mu.Lock()
	h.m.proc = sleep1
	recorder.install(h, clustered)
	h.m.restartBringupHook = func(config.UserspaceConfig) error {
		h.m.proc = sleep2
		return nil
	}
	h.m.mu.Unlock()

	h.mu.Lock()
	h.applyErr = transportTimeout9642()
	h.statusGen = attempted.Generation
	h.mu.Unlock()
	h.m.mu.Lock()
	var status ProcessStatus
	if err := h.m.publishSnapshotFailClosedLocked(attempted, &status, false); err == nil {
		h.m.mu.Unlock()
		t.Fatal("premise: changed-plan transport failure must fail the publish")
	}
	h.m.mu.Unlock()
	h.stopLoop(t)

	h.mu.Lock()
	h.applyErr = nil
	h.statusGen = attempted.Generation
	h.mu.Unlock()
	return h, recorder
}

// RED-on-revert: remove the HA replay tail from syncSnapshotLocked and this
// cell leaves the respawned clustered helper without an inventory.
func TestRetryDebtConvergenceReplaysClusterHAInventory10034(t *testing.T) {
	h, recorder := setupChangedPlanDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	if err := h.m.syncSnapshotLocked(); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("syncSnapshotLocked convergence: %v", err)
	}
	h.m.mu.Unlock()

	refreshCalls, requests := recorder.snapshot()
	if refreshCalls != 1 {
		t.Fatalf("refreshHAStateFromMapsLocked called %d times, want exactly once", refreshCalls)
	}
	if len(requests) != 1 {
		t.Fatalf("update_ha_state requests = %d, want exactly one inventory replay", len(requests))
	}
	got := requests[0].Groups
	want := []HAGroupStatus{
		{RGID: 1, Active: false, WatchdogTimestamp: 101},
		{RGID: 2, Active: true, WatchdogTimestamp: 202},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("replayed HA inventory = %+v, want full inventory %+v", got, want)
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if !h.m.helperHAStatePublished {
		t.Fatal("successful debt convergence did not record the respawned helper's HA inventory")
	}
	if h.m.snapshotRetryDebtLocked() {
		t.Fatal("snapshot retry debt remained after successful convergence")
	}
}

// A failed inventory RPC must not be mistaken for a settled snapshot. The
// independent replay obligation is consumed by the same retry method the
// status tick invokes, then clears only after the next inventory RPC succeeds.
func TestRetryDebtConvergenceRetriesFailedClusterHAReplay10034(t *testing.T) {
	t.Parallel()
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)
	recorder.setHAErrors([]error{transportTimeout9642()})

	h.m.mu.Lock()
	// Model an old inventory on the same helper, not only the respawn case.
	// Debt convergence must retire it while the replacement inventory is
	// outstanding.
	h.m.helperHAStatePublished = true
	h.m.haWatchdogHelperInventory = []HAGroupStatus{{RGID: 99, Active: true}}
	h.m.publishHAWatchdogSnapshotLocked()
	err := h.m.syncSnapshotLocked()
	pendingAfterFailure := h.m.pendingHAStateReplay
	publishedAfterFailure := h.m.publishedSnapshot
	debtAfterFailure := h.m.snapshotRetryDebtLocked()
	helperPublishedAfterFailure := h.m.helperHAStatePublished
	helperInventoryAfterFailure := len(h.m.haWatchdogHelperInventory)
	ctrlHeldAfterFailure := h.m.ctrlMustStayDisabledLocked(true)
	ctrlStoredAfterFailure := h.statusCtrl.haveStored && h.statusCtrl.stored.Enabled == 0
	h.m.mu.Unlock()
	if err == nil {
		t.Fatal("snapshot convergence returned nil after the HA replay failed")
	}
	if !pendingAfterFailure {
		t.Fatal("failed clustered HA replay did not retain its independent retry obligation")
	}
	if helperPublishedAfterFailure || helperInventoryAfterFailure != 0 {
		t.Fatalf("stale helper inventory survived a failed replay: published=%v entries=%d",
			helperPublishedAfterFailure, helperInventoryAfterFailure)
	}
	if !ctrlHeldAfterFailure {
		t.Fatal("ctrl gate was not held fail-closed while clustered HA replay remained pending")
	}
	if !ctrlStoredAfterFailure {
		t.Fatal("production ctrl map was not written disabled while replay debt was pending")
	}
	if publishedAfterFailure != 9 || debtAfterFailure {
		t.Fatalf("snapshot state after HA-only failure = published %d, debt %v; want published 9 and no snapshot debt",
			publishedAfterFailure, debtAfterFailure)
	}

	h.m.mu.Lock()
	err = h.m.retryPendingHAStateReplayLocked()
	pendingAfterSuccess := h.m.pendingHAStateReplay
	ctrlStoredAfterSuccess := h.statusCtrl.haveStored && h.statusCtrl.stored.Enabled == 1
	h.m.mu.Unlock()
	if err != nil {
		t.Fatalf("clustered HA replay retry: %v", err)
	}
	if pendingAfterSuccess {
		t.Fatal("successful clustered HA replay left its retry obligation pending")
	}
	if !ctrlStoredAfterSuccess {
		t.Fatal("production ctrl map did not re-enable after the acknowledged replay")
	}
	_, requests := recorder.snapshot()
	if len(requests) != 2 {
		t.Fatalf("update_ha_state requests = %d, want failed attempt plus successful retry", len(requests))
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if !h.m.helperHAStatePublished {
		t.Fatal("successful clustered HA replay did not mark the helper inventory published")
	}
}

// An election transition can publish the full inventory while a prior
// retry-debt replay is outstanding. Its successful ACK must settle that
// obligation so the next status tick does not send the same inventory again.
func TestRetryDebtConvergenceElectionACKClearsReplay10034(t *testing.T) {
	t.Parallel()
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)
	recorder.setHAErrors([]error{transportTimeout9642()})

	h.m.mu.Lock()
	h.m.haRGActiveMapWrite = func(int, bool) error { return nil }
	err := h.m.syncSnapshotLocked()
	pendingAfterFailure := h.m.pendingHAStateReplay
	h.m.mu.Unlock()
	if err == nil {
		t.Fatal("snapshot convergence returned nil after the HA replay failed")
	}
	if !pendingAfterFailure {
		t.Fatal("failed replay did not leave election recovery debt pending")
	}

	if err := h.m.UpdateRGActive(1, true); err != nil {
		t.Fatalf("election inventory ACK: %v", err)
	}
	h.m.mu.Lock()
	pendingAfterElection := h.m.pendingHAStateReplay
	helperPublished := h.m.helperHAStatePublished
	err = h.m.retryPendingHAStateReplayLocked()
	h.m.mu.Unlock()
	if err != nil {
		t.Fatalf("retry after election ACK: %v", err)
	}
	if pendingAfterElection {
		t.Fatal("election inventory ACK left replay debt pending")
	}
	if !helperPublished {
		t.Fatal("election inventory ACK did not record helper inventory publication")
	}
	if _, requests := recorder.snapshot(); len(requests) != 2 {
		t.Fatal("election ACK was followed by a redundant HA inventory replay")
	}
}

func assertDirectRepublishArmsHAReplay10034(t *testing.T, h *debtHarness9642, recorder *haReplayRecorder10034) {
	t.Helper()
	h.m.mu.Lock()
	pending := h.m.pendingHAStateReplay
	helperPublished := h.m.helperHAStatePublished
	helperInventoryLen := len(h.m.haWatchdogHelperInventory)
	h.m.mu.Unlock()
	if !pending {
		t.Fatal("direct full-snapshot republish did not retain HA replay debt")
	}
	if helperPublished || helperInventoryLen != 0 {
		t.Fatalf("direct republish retained stale helper inventory: published=%v entries=%d",
			helperPublished, helperInventoryLen)
	}
	if refreshCalls, requests := recorder.snapshot(); refreshCalls != 0 || len(requests) != 0 {
		t.Fatalf("direct republish unexpectedly replayed HA immediately: refreshes=%d requests=%d",
			refreshCalls, len(requests))
	}
}

func TestRetryDebtConvergenceDeferredWorkerRepublishArmsHAReplay10034(t *testing.T) {
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	h.m.pendingWorkerArm = true
	h.m.lastSnapshot.DeferWorkers = true
	err := h.m.retryDeferredWorkerArmLocked()
	h.m.mu.Unlock()
	if err != nil {
		t.Fatalf("deferred-worker republish: %v", err)
	}
	assertDirectRepublishArmsHAReplay10034(t, h, recorder)
}

func TestRetryDebtConvergencePolicyRepublishArmsHAReplay10034(t *testing.T) {
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	cfg := h.m.lastSnapshot.Config
	h.m.mu.Unlock()
	if err := h.m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": true}); err != nil {
		t.Fatalf("policy-schedule republish: %v", err)
	}
	assertDirectRepublishArmsHAReplay10034(t, h, recorder)
}

func TestRetryDebtConvergenceRouteRepublishArmsHAReplay10034(t *testing.T) {
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	cfg := h.m.lastSnapshot.Config
	h.m.mu.Unlock()
	if published, err := h.m.PublishRouteOverlaySnapshot(cfg, nil, nil); err != nil {
		t.Fatalf("route-overlay republish: %v", err)
	} else if !published {
		t.Fatal("route-overlay republish reported published=false")
	}
	assertDirectRepublishArmsHAReplay10034(t, h, recorder)
}

// RED-on-revert: arm the replay obligation only after applyHelperStatusLocked
// succeeds and this cell loses the obligation before the status reconcile can
// retry it.
func TestRetryDebtConvergenceRetainsHAReplayAfterStatusFailure10034(t *testing.T) {
	t.Parallel()
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	h.statusCtrl.updateErr = errors.New("status map reconcile failed")
	err := h.m.syncSnapshotLocked()
	pendingAfterFailure := h.m.pendingHAStateReplay
	h.m.mu.Unlock()
	if err == nil {
		t.Fatal("snapshot convergence returned nil after helper-status reconciliation failed")
	}
	if !pendingAfterFailure {
		t.Fatal("apply-status failure lost the clustered HA replay obligation")
	}
	if _, requests := recorder.snapshot(); len(requests) != 0 {
		t.Fatal("HA replay ran after apply-status failure; the snapshot tail must stop at the failed reconcile")
	}

	h.m.mu.Lock()
	h.statusCtrl.updateErr = nil
	err = h.m.retryPendingHAStateReplayLocked()
	pendingAfterSuccess := h.m.pendingHAStateReplay
	h.m.mu.Unlock()
	if err != nil {
		t.Fatalf("clustered HA replay after status failure: %v", err)
	}
	if pendingAfterSuccess {
		t.Fatal("successful retry after status failure left the HA obligation pending")
	}
	if _, requests := recorder.snapshot(); len(requests) != 1 {
		t.Fatal("status failure recovery did not send exactly one HA inventory replay")
	}
}

// Once update_ha_state has been acknowledged, a later status/forwarding
// reconcile failure must not leave the replay marked pending. Retrying an
// acknowledged inventory would duplicate the control-plane apply.
func TestRetryDebtConvergenceDoesNotRepeatAckedHAAfterStatusFailure10034(t *testing.T) {
	t.Parallel()
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	baseHook := h.m.controlRequestHook
	h.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		err := baseHook(req, status)
		if req.Type == "update_ha_state" && err == nil {
			// The first status reconcile already completed before this
			// request. Fail only the status reconcile returned by HA replay.
			h.statusCtrl.updateErr = errors.New("post-ACK status reconcile failed")
		}
		return err
	}
	err := h.m.syncSnapshotLocked()
	pendingAfterFailure := h.m.pendingHAStateReplay
	h.m.mu.Unlock()
	if err == nil {
		t.Fatal("snapshot convergence returned nil after post-ACK status reconciliation failed")
	}
	if pendingAfterFailure {
		t.Fatal("post-ACK status failure left HA replay pending; the inventory was already acknowledged")
	}
	if _, requests := recorder.snapshot(); len(requests) != 1 {
		t.Fatal("post-ACK status failure did not send exactly one HA inventory update")
	}

	h.m.mu.Lock()
	err = h.m.retryPendingHAStateReplayLocked()
	h.m.mu.Unlock()
	if err != nil {
		t.Fatalf("retry of an already acknowledged HA inventory: %v", err)
	}
	if _, requests := recorder.snapshot(); len(requests) != 1 {
		t.Fatal("already acknowledged HA inventory was sent again after a status failure")
	}
}

// A forwarding-state failure after the HA ACK is another trailing reconcile
// failure. The ACK boundary, not the final syncDesiredForwardingStateLocked
// return, owns replay-debt clearing.
func TestRetryDebtConvergenceDoesNotRepeatAckedHAAfterForwardingFailure10034(t *testing.T) {
	t.Parallel()
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	baseHook := h.m.controlRequestHook
	failForwarding := false
	h.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "set_forwarding_state" && failForwarding {
			return errors.New("post-ACK forwarding reconcile failed")
		}
		err := baseHook(req, status)
		if status != nil {
			status.Capabilities.ForwardingSupported = true
			status.ForwardingArmed = false
		}
		if req.Type == "update_ha_state" && err == nil {
			failForwarding = true
		}
		return err
	}
	err := h.m.syncSnapshotLocked()
	pendingAfterFailure := h.m.pendingHAStateReplay
	h.m.mu.Unlock()
	if err == nil {
		t.Fatal("snapshot convergence returned nil after post-ACK forwarding failure")
	}
	if pendingAfterFailure {
		t.Fatal("post-ACK forwarding failure left HA replay pending")
	}
	if _, requests := recorder.snapshot(); len(requests) != 1 {
		t.Fatal("post-ACK forwarding failure did not send exactly one HA update")
	}

	h.m.mu.Lock()
	err = h.m.retryPendingHAStateReplayLocked()
	h.m.mu.Unlock()
	if err != nil {
		t.Fatalf("retry after acknowledged forwarding failure: %v", err)
	}
	if _, requests := recorder.snapshot(); len(requests) != 1 {
		t.Fatal("forwarding failure caused an already acknowledged HA update to repeat")
	}
}

// The status loop must not run its periodic HA backstop after the convergence
// path has already published the inventory in the same tick. The helper status
// deliberately reports the new inventory only on the next poll, exposing a
// same-tick duplicate if the local debt bit is not preserved.
func TestRetryDebtConvergenceStatusTickPublishesHAOnce10034(t *testing.T) {
	oldInterval := statusLoopInterval
	statusLoopInterval = 100 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = oldInterval })

	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	baseHook := h.m.controlRequestHook
	h.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		err := baseHook(req, status)
		if req.Type == "status" && status != nil {
			_, requests := recorder.snapshot()
			if len(requests) > 0 {
				status.HAGroups = []HAGroupStatus{
					{RGID: 1, Active: false, WatchdogTimestamp: 101},
					{RGID: 2, Active: true, WatchdogTimestamp: 202},
				}
			}
		}
		return err
	}
	h.m.mu.Lock()
	h.m.ensureStatusLoopLocked()
	h.m.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		statusPolls := 0
		for _, typ := range h.sentTypes {
			if typ == "status" {
				statusPolls++
			}
		}
		h.mu.Unlock()
		if statusPolls >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("status loop did not complete a second poll after HA replay")
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.stopLoop(t)

	refreshCalls, requests := recorder.snapshot()
	if refreshCalls != 1 || len(requests) != 1 {
		t.Fatalf("status-tick replay = refreshes %d, update_ha_state requests %d; want exactly one each",
			refreshCalls, len(requests))
	}
}

// A failed HA replay must not be retried immediately by the same status tick.
// The first error remains retry debt for the next tick, rather than becoming
// two control-socket attempts hidden behind one snapshot convergence.
func TestRetryDebtConvergenceStatusTickFailedHAReplayOnce10034(t *testing.T) {
	oldInterval := statusLoopInterval
	statusLoopInterval = 100 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = oldInterval })

	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)
	recorder.setHAErrors([]error{transportTimeout9642()})

	firstRequest := make(chan struct{}, 1)
	baseHook := h.m.controlRequestHook
	h.m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		err := baseHook(req, status)
		if req.Type == "update_ha_state" {
			select {
			case firstRequest <- struct{}{}:
			default:
			}
		}
		return err
	}
	h.m.mu.Lock()
	h.m.ensureStatusLoopLocked()
	h.m.mu.Unlock()

	select {
	case <-firstRequest:
	case <-time.After(2 * time.Second):
		t.Fatal("status loop did not attempt the failed HA replay")
	}
	h.stopLoop(t)

	_, requests := recorder.snapshot()
	if len(requests) != 1 {
		t.Fatalf("failed status-tick replay sent %d HA updates; want exactly one before next tick", len(requests))
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if !h.m.pendingHAStateReplay {
		t.Fatal("failed status-tick replay did not retain the HA obligation")
	}
	if !h.m.ctrlMustStayDisabledLocked(true) {
		t.Fatal("failed status-tick replay did not keep ctrl fail-closed")
	}
}

// A generation-only deferred convergence without unknown-outcome debt must keep
// its existing consumers: this path is not permission to replay HA state.
func TestNonDebtDeferredConvergenceDoesNotReplayHA10034(t *testing.T) {
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	h.m.applySnapshotOutcomeUnknown = false
	h.m.retryDebtSince = time.Time{}
	err := h.m.syncSnapshotLocked()
	published := h.m.publishedSnapshot
	pending := h.m.pendingHAStateReplay
	h.m.mu.Unlock()
	if err != nil {
		t.Fatalf("non-debt deferred convergence: %v", err)
	}
	if published != 9 {
		t.Fatalf("non-debt deferred convergence published generation %d, want 9", published)
	}
	if pending {
		t.Fatal("non-debt deferred convergence armed HA replay debt")
	}
	if refreshCalls, requests := recorder.snapshot(); refreshCalls != 0 || len(requests) != 0 {
		t.Fatalf("non-debt deferred convergence replayed HA: refreshes=%d requests=%d",
			refreshCalls, len(requests))
	}
}

// A clustered retry with no valid redundancy groups cannot be acknowledged by
// syncHAStateLocked: its empty-inventory early return is intentionally not a
// publish under #7465. Keep the obligation and fail-closed gate visible so a
// later map refresh can supply a real inventory.
func TestRetryDebtConvergenceKeepsEmptyClusterInventoryFailClosed10034(t *testing.T) {
	t.Parallel()
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	h.m.haGroups = map[int]HAGroupStatus{}
	h.m.helperHAStatePublished = true
	h.m.haWatchdogHelperInventory = []HAGroupStatus{{RGID: 99, Active: true}}
	h.m.publishHAWatchdogSnapshotLocked()
	err := h.m.syncSnapshotLocked()
	pending := h.m.pendingHAStateReplay
	helperPublished := h.m.helperHAStatePublished
	helperInventoryLen := len(h.m.haWatchdogHelperInventory)
	debt := h.m.snapshotRetryDebtLocked()
	ctrlHeld := h.m.ctrlMustStayDisabledLocked(true)
	h.m.mu.Unlock()
	if err != nil {
		t.Fatalf("empty-inventory debt convergence: %v", err)
	}
	if !pending {
		t.Fatal("empty clustered inventory incorrectly settled the replay obligation")
	}
	if helperPublished || helperInventoryLen != 0 {
		t.Fatalf("empty replay helper inventory state = published %v, entries %d; want published false and empty",
			helperPublished, helperInventoryLen)
	}
	if !ctrlHeld {
		t.Fatal("empty clustered inventory replay did not keep ctrl fail-closed")
	}
	if debt {
		t.Fatal("empty-inventory convergence left snapshot retry debt pending")
	}
	if refreshCalls, requests := recorder.snapshot(); refreshCalls != 1 || len(requests) != 0 {
		t.Fatalf("empty clustered replay = refreshes %d, requests %+v; want one refresh and no empty publish",
			refreshCalls, requests)
	}
}

// RED-on-revert: remove the standalone clear from the debt-convergence tail and
// this cell leaves the prior clustered helper inventory stranded.
func TestRetryDebtConvergenceClearsStandaloneHAState10034(t *testing.T) {
	t.Parallel()
	h, recorder := setupDebtConvergence10034(t, false)
	defer h.stopLoop(t)

	h.m.mu.Lock()
	if err := h.m.syncSnapshotLocked(); err != nil {
		h.m.mu.Unlock()
		t.Fatalf("syncSnapshotLocked convergence: %v", err)
	}
	h.m.mu.Unlock()

	refreshCalls, requests := recorder.snapshot()
	if refreshCalls != 0 {
		t.Fatalf("standalone convergence refreshed clustered maps %d times, want 0", refreshCalls)
	}
	if len(requests) != 1 {
		t.Fatalf("update_ha_state requests = %d, want exactly one standalone clear", len(requests))
	}
	if len(requests[0].Groups) != 0 {
		t.Fatalf("standalone clear groups = %+v, want empty inventory", requests[0].Groups)
	}
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	if h.m.pendingHAStateClear {
		t.Fatal("successful standalone debt convergence left HA clear debt pending")
	}
	if h.m.helperHAStatePublished {
		t.Fatal("standalone clear left helperHAStatePublished set")
	}
}

// Control: once the debt is settled, a repeated syncSnapshotLocked call is a
// no-op. The HA replay must not become a second update_ha_state publication.
func TestRetryDebtConvergenceHAReplayIsIdempotent10034(t *testing.T) {
	t.Parallel()
	h, recorder := setupDebtConvergence10034(t, true)
	defer h.stopLoop(t)

	for i := range 2 {
		h.m.mu.Lock()
		err := h.m.syncSnapshotLocked()
		h.m.mu.Unlock()
		if err != nil {
			t.Fatalf("syncSnapshotLocked convergence call %d: %v", i+1, err)
		}
	}
	refreshCalls, requests := recorder.snapshot()
	if refreshCalls != 1 || len(requests) != 1 {
		t.Fatalf("repeated settled convergence replayed HA state: refreshes=%d requests=%d", refreshCalls, len(requests))
	}
}

