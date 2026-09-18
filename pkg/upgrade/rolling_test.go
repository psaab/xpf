package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCluster is an in-memory RollingCluster for orchestration tests.
type fakeCluster struct {
	peerAlive    bool
	synced       bool
	compatible   bool
	peerReady    bool
	localPri     bool
	drainAfter   int // become drained after this many DrainComplete polls
	drainPolls   int
	syncErrPolls int // SyncEstablished returns a transient error for this many polls
	syncPolls    int
	forced       bool
	resetCalled  bool
	// #5845 test seam: when set, ResetFailover (failback) returns this error,
	// modeling a failback that FAILS after ForceSecondary already demoted the
	// node — so the drain-abort must surface it and warn stranded-demoted rather
	// than falsely claim the node is still forwarding.
	resetErr error
	// #5138 per-RG rejoin gate. Default (zero value) reports rejoin COMPLETE
	// so the many existing healthy-cluster tests keep passing without edits;
	// a test sets rejoinIncomplete=true to model a configured RG still held in
	// the ForceSecondary drain after ResetFailover, or rejoinErr for a
	// persistent enumeration/transport failure surfaced at the deadline.
	rejoinIncomplete bool
	rejoinErr        error
	// #6557: how many times LocalRejoinComplete was consulted. TestRolling_
	// HappyPath asserted only that ResetFailover was CALLED, which a step 7
	// that never confirms satisfies just as well; this counter is what
	// distinguishes "requested the rejoin" from "confirmed it".
	rejoinChecks int
	// #10261: existing tests default bulk priming to the same healthy value as
	// SyncEstablished. A test opts into an explicit false to model a daemon
	// whose transport is up before its inbound bulk snapshot arrives.
	bulkPrimed    bool
	bulkPrimedSet bool
	// #4717 test seams: when set, the predicate returns this error on EVERY
	// poll (persistent transport failure), so a deadline miss must surface it.
	peerAliveErr error
	syncErr      error
	// #7990 seams. syncWireIncompat makes SessionSyncWireCompatible refuse;
	// syncWireErr makes it fail transport-side. Both default to the healthy
	// value so every pre-#7990 case keeps exercising what it was written for.
	syncWireIncompat bool
	syncWireErr      error
	syncWireChecks   int
}

func (f *fakeCluster) PeerAlive() (bool, error) { return f.peerAlive, f.peerAliveErr }
func (f *fakeCluster) SyncEstablished() (bool, error) {
	f.syncPolls++
	if f.syncErr != nil {
		return false, f.syncErr
	}
	// Poll #1 is the PRE-cut precondition check (daemon up) — always OK.
	// Polls #2..#(1+syncErrPolls) model the POST-cut gRPC-startup gap: the
	// local socket refuses connections while xpfd restarts. After that the
	// daemon is up and sync re-establishes.
	if f.syncPolls > 1 && f.syncPolls-1 <= f.syncErrPolls {
		return false, errors.New("dial xpfd gRPC 127.0.0.1:50051: connection refused")
	}
	return f.synced, nil
}
func (f *fakeCluster) HAProtocolCompatible() (bool, error) { return f.compatible, nil }

func (f *fakeCluster) SessionSyncBulkPrimed() (bool, error) {
	if f.bulkPrimedSet {
		return f.bulkPrimed, nil
	}
	return f.synced, nil
}
func (f *fakeCluster) SessionSyncWireCompatible() (bool, string, error) {
	f.syncWireChecks++
	if f.syncWireErr != nil {
		return false, "", f.syncWireErr
	}
	if f.syncWireIncompat {
		return false, "peer session-sync wire version differs", nil
	}
	return true, "peer session-sync wire version matches", nil
}
func (f *fakeCluster) PeerTakeoverReady() (bool, error) { return f.peerReady, nil }
func (f *fakeCluster) ForceSecondary() error            { f.forced = true; return nil }
func (f *fakeCluster) DrainComplete() (bool, error) {
	f.drainPolls++
	return f.drainPolls >= f.drainAfter, nil
}
func (f *fakeCluster) ResetFailover() error        { f.resetCalled = true; return f.resetErr }
func (f *fakeCluster) LocalPrimary() (bool, error) { return f.localPri, nil }
func (f *fakeCluster) LocalRejoinComplete() (bool, error) {
	f.rejoinChecks++
	if f.rejoinErr != nil {
		return false, f.rejoinErr
	}
	return !f.rejoinIncomplete, nil
}

func fastRC() RollingConfig {
	return RollingConfig{
		DrainDeadline:  2 * time.Second,
		RejoinDeadline: 2 * time.Second,
		PollInterval:   time.Millisecond,
	}
}

// seedInitialCurrent models the post-#1964 reality that every node — HA
// included — has its versioned runtime seeded at install (mechanism A), so
// versions/current exists and the rolling cut has a real rollback target
// (PreviousVersion != ""). Without it a rolling cut would hit the
// refuse-before-STOP invariant (#1964 mechanism C), which is exactly the
// behavior an UNSEEDED node should get. The rolling tests that proceed to
// the cut seed an initial current; the abort-early tests do not need it.
func seedInitialCurrent(t *testing.T, r *Runner, cfg Config, ver string) {
	t.Helper()
	verDir := filepath.Join(cfg.VersionsDir, ver)
	for _, b := range managedBins {
		writeFakeBin(t, filepath.Join(verDir, b), "binary-"+b+"-"+ver)
	}
	if err := os.MkdirAll(cfg.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ver, filepath.Join(cfg.VersionsDir, currentLink)); err != nil {
		t.Fatal(err)
	}
}

func TestRolling_HappyPath(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0") // post-#1964: node already seeded
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 2}

	if err := runRollingWith(r, cl, fastRC()); err != nil {
		t.Fatalf("rolling: %v", err)
	}
	if !cl.forced {
		t.Error("ForceSecondary not called")
	}
	if !cl.resetCalled {
		t.Error("ResetFailover (failback) not called")
	}
	// The cut must have completed (current -> 2.0.0).
	if fs.dropinContent == "" {
		t.Error("no cut happened (no drop-in)")
	}
}

func TestRolling_AbortsIfPeerDead(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	cl := &fakeCluster{peerAlive: false, synced: true, compatible: true, peerReady: true, drainAfter: 1}

	err := runRollingWith(r, cl, fastRC())
	if err == nil || !strings.Contains(err.Error(), "peer is not alive") {
		t.Fatalf("expected peer-dead abort, got %v", err)
	}
	if cl.forced {
		t.Error("ForceSecondary called despite dead peer — would strand the only forwarding node")
	}
	if fs.dropinContent != "" {
		t.Error("cut happened despite dead peer")
	}
}

func TestRolling_AbortsIfProtocolIncompatible(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: false, peerReady: true, drainAfter: 1}

	err := runRollingWith(r, cl, fastRC())
	if err == nil || !strings.Contains(err.Error(), "not rolling-upgradable") {
		t.Fatalf("expected protocol-incompatible abort, got %v", err)
	}
	if cl.forced {
		t.Error("ForceSecondary called despite incompatible protocol")
	}
}

func TestRolling_RefusesDemoteIfPeerNotReady(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: false, drainAfter: 1}

	err := runRollingWith(r, cl, fastRC())
	if err == nil || !strings.Contains(err.Error(), "takeover-ready") {
		t.Fatalf("expected peer-not-ready abort, got %v", err)
	}
	if cl.forced {
		t.Error("ForceSecondary called despite peer not takeover-ready — VIP stranding risk")
	}
	if fs.dropinContent != "" {
		t.Error("cut happened despite peer not ready")
	}
}

func TestRolling_AbortsAndFailsBackIfDrainTimesOut(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	// drainAfter huge so the predicate never holds within the deadline.
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1 << 30}

	err := runRollingWith(r, cl, RollingConfig{DrainDeadline: 20 * time.Millisecond, PollInterval: time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "drain predicate not satisfied") {
		t.Fatalf("expected drain-timeout abort, got %v", err)
	}
	// #5845: ResetFailover SUCCEEDS here (resetErr unset), so the failback
	// undid the demotion and the "node still forwarding" claim is TRUE — the
	// abort must keep it and must NOT warn stranded-demoted.
	if !strings.Contains(err.Error(), "still forwarding") {
		t.Errorf("failback succeeded, so the abort must report the node still forwarding, got %v", err)
	}
	if strings.Contains(err.Error(), "STRANDED DEMOTED") {
		t.Errorf("failback succeeded — the abort must NOT warn stranded-demoted, got %v", err)
	}
	if !cl.forced {
		t.Error("ForceSecondary should have been called before the drain wait")
	}
	if !cl.resetCalled {
		t.Error("ResetFailover (failback) not called after drain timeout — node left half-drained")
	}
	if fs.dropinContent != "" {
		t.Error("cut happened despite drain timeout (node was still forwarding)")
	}
}

// TestRolling_DrainTimeoutFailbackFailsStrandedDemoted_5845 pins the #5845
// fail-closed contract: when the drain times out AND the failback
// (ResetFailover) FAILS, the abort error must (a) SURFACE the failback failure
// (it used to be discarded, `_ = cl.ResetFailover()`) and (b) warn the node may
// be STRANDED DEMOTED — it must NOT keep falsely claiming the node is "still
// forwarding". ForceSecondary already demoted the node, so a failed failback can
// leave it force-secondary with peer takeover unproven (both-nodes-secondary
// outage). Mirrors the kernel-roll drain contract (kernel_drain.go).
//
// FAIL-ON-REVERT: reverting to `_ = cl.ResetFailover()` + the unconditional
// "node still forwarding" message makes the surfaces-resetErr and
// stranded-demoted assertions fail (and the not-still-forwarding assertion).
func TestRolling_DrainTimeoutFailbackFailsStrandedDemoted_5845(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)
	resetFail := errors.New("injected: ResetFailover control-socket EIO")
	// drainAfter huge so the predicate never holds; resetErr makes the failback
	// after the timeout FAIL.
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true,
		drainAfter: 1 << 30, resetErr: resetFail}

	err := runRollingWith(r, cl, RollingConfig{DrainDeadline: 20 * time.Millisecond, PollInterval: time.Millisecond})
	if err == nil {
		t.Fatal("expected an abort error when the drain times out and the failback fails")
	}
	// (a) The failback failure must be surfaced, not discarded.
	if !errors.Is(err, resetFail) {
		t.Fatalf("abort error must surface the ResetFailover failure (#5845 discarded it), got %v", err)
	}
	// The underlying drain error must also still be surfaced (both reported).
	if !strings.Contains(err.Error(), "drain predicate not satisfied") {
		t.Fatalf("abort error must still report the drain failure too, got %v", err)
	}
	// (b) Must warn stranded-demoted and must NOT falsely claim still-forwarding.
	if !strings.Contains(err.Error(), "STRANDED DEMOTED") {
		t.Fatalf("abort error must warn the node may be stranded demoted, got %v", err)
	}
	if strings.Contains(err.Error(), "still forwarding") {
		t.Fatalf("abort error must NOT claim the node is still forwarding when the failback failed, got %v", err)
	}
	// The failback WAS attempted, and no cut happened.
	if !cl.resetCalled {
		t.Error("ResetFailover should still be attempted before reporting the failure")
	}
	if fs.dropinContent != "" {
		t.Error("cut happened despite drain timeout")
	}
}

// TestRolling_RejoinToleratesTransientSyncErr proves the post-cut rejoin
// wait survives the gRPC-startup gap. The cut restarts xpfd, so the local
// gRPC socket refuses connections for the first several polls; the wait
// must treat that as "not ready yet" and keep polling until the daemon is
// up — NOT abort on the first dial error. Regression for the live #1933
// rolling-upgrade false-negative abort ("connection refused on
// 127.0.0.1:50051" surfaced ~immediately, never using RejoinDeadline).
func TestRolling_RejoinToleratesTransientSyncErr(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0") // post-#1964: node already seeded
	// SyncEstablished errors (connection refused) for the first 5 polls,
	// then succeeds — mimicking the daemon coming up ~6 polls after the cut.
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 2, syncErrPolls: 5}

	if err := runRollingWith(r, cl, fastRC()); err != nil {
		t.Fatalf("rolling aborted on a transient post-cut sync error (should tolerate until RejoinDeadline): %v", err)
	}
	if cl.syncPolls <= cl.syncErrPolls {
		t.Errorf("rejoin wait did not keep polling past the transient errors: syncPolls=%d, syncErrPolls=%d", cl.syncPolls, cl.syncErrPolls)
	}
	if !cl.resetCalled {
		t.Error("ResetFailover (failback) not called — rejoin must complete after sync re-establishes")
	}
	if fs.dropinContent == "" {
		t.Error("cut did not happen")
	}
}

// TestRolling_RejoinTimesOutSurfacesLastErr proves a PERSISTENT rejoin
// error still aborts at RejoinDeadline (tolerance is bounded) and surfaces
// the last observed error for operator diagnosis.
func TestRolling_RejoinTimesOutSurfacesLastErr(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0") // post-#1964: node already seeded
	// Never re-establishes sync (huge syncErrPolls), short RejoinDeadline.
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 2, syncErrPolls: 1 << 30}

	err := runRollingWith(r, cl, RollingConfig{DrainDeadline: 2 * time.Second, RejoinDeadline: 20 * time.Millisecond, PollInterval: time.Millisecond})
	if err == nil {
		t.Fatal("expected rejoin timeout, got nil")
	}
	if !strings.Contains(err.Error(), "re-establish session sync") {
		t.Errorf("expected rejoin-timeout wrapper, got %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("expected the last observed error surfaced, got %v", err)
	}
	// The cut DID happen (we are past it) — the rejoin wait is reached only
	// after the single-node cut wrote the version drop-in.
	if fs.dropinContent == "" {
		t.Error("cut did not happen before the rejoin wait (timeout was not in step 6)")
	}
	// Post-cut polling must have actually occurred (poll #1 is the pre-cut
	// precheck), so the timeout is genuinely the rejoin wait exhausting
	// RejoinDeadline, not a precheck failure.
	if cl.syncPolls <= 1 {
		t.Errorf("rejoin wait did not poll post-cut: syncPolls=%d", cl.syncPolls)
	}
	// The node is left secondary, not failed back — ResetFailover (rejoin
	// election) must NOT have run.
	if cl.resetCalled {
		t.Error("ResetFailover (failback) ran despite the rejoin never completing — node should be left secondary")
	}
}
