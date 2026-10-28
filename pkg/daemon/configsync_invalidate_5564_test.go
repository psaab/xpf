// #5564: on the HA receive side, syncAndApply promotes the peer config to
// active and arms the dataplane snapshot BEFORE it runs the three session
// invalidators (clearSessionsForPolicyChanges: the #4234 deletion-clear, the
// modified-policy re-eval, and the #4342 default-policy change). Before the fix
// it returned early on ANY applyConfigLocked error — so a NON-FATAL best-effort
// tail failure (host-inbound/lo0 nft, networkd, ...) left surviving established
// sessions forwarding under their OLD authorization on an armed standby
// (security fail-open). Because the store already holds the incoming text, the
// next equal-active-text re-push takes handleConfigSync's fast path and never
// re-enters syncAndApply, making the omission PERMANENT (visible at failover).
//
// These tests pin the fix: a non-fatal tail apply error on the RECEIVE path
// STILL invalidates the sessions of a peer-deleted policy (and surfaces the tail
// error), while a genuinely-FATAL apply (dataplane disarmed / daemon-stop abort
// — the config is not live-forwarding) does NOT invalidate (no spurious clear)
// yet still surfaces the error. RED-on-revert: restoring the early
// `return nil, err` before the invalidators leaves the non-fatal test's sessions
// installed under stale authorization (and drops the promoted config).
package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// newSyncReadyStore commits a baseline with two trust->untrust permit policies
// (p-first at the overloaded id 0, p-web at id 1) so a peer-pushed config that
// DELETES p-web has a real, non-overloaded clear set {webID}. It returns the
// store (active = baseline WITH p-web), the hierarchical peer text WITHOUT p-web
// (what SyncApply promotes), and p-web's runtime id.
func newSyncReadyStore(t *testing.T) (*configstore.Store, string, uint32) {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
	}
	for _, p := range []string{"p-first", "p-web"} {
		lines = append(lines,
			"security policies from-zone trust to-zone untrust policy "+p+" match source-address any",
			"security policies from-zone trust to-zone untrust policy "+p+" match destination-address any",
			"security policies from-zone trust to-zone untrust policy "+p+" match application any",
			"security policies from-zone trust to-zone untrust policy "+p+" then permit",
		)
	}
	for _, line := range lines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	compiled, err := s.Commit()
	if err != nil {
		t.Fatalf("commit baseline: %v", err)
	}
	webID := dpuserspace.PolicyIDsByStableKey(compiled)["trust->untrust/p-web"]
	if webID == 0 {
		t.Fatalf("precondition: p-web must have a non-overloaded runtime id; got %d", webID)
	}
	// Build the peer text WITHOUT p-web from the candidate; active still holds it
	// (a delete only touches the candidate until the next commit).
	if err := s.DeleteFromInput("security policies from-zone trust to-zone untrust policy p-web"); err != nil {
		t.Fatalf("delete p-web from candidate: %v", err)
	}
	return s, s.ShowCandidate(), webID
}

// syncSessionDP builds a fake dataplane holding one v4 and one v6 ESTABLISHED
// session admitted under the deleted policy (webID) — the surviving synced
// sessions the receive-side invalidators must drop when p-web is peer-deleted.
func syncSessionDP(webID uint32) (dp *policyInvalTestDP, v4 dataplane.SessionKey, v6 dataplane.SessionKeyV6) {
	v4 = dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	v6 = dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0x02},
		SrcPort: 40003, DstPort: 80, Protocol: 6,
	}
	dp = &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			v4: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			v6: {State: dataplane.SessStateEstablished, PolicyID: webID},
		},
	}
	return dp, v4, v6
}

// TestSyncAndApplyRunsInvalidatorsOnNonFatalApplyError is the #5564
// RED-on-revert pin: a peer config sync whose applyConfigLocked returns a
// NON-FATAL best-effort tail error STILL invalidates the sessions of the
// peer-deleted policy AND surfaces the tail error. Restoring the pre-fix early
// `return nil, err` leaves the sessions installed under stale authorization
// (fail-open) and drops the promoted config → RED.
func TestSyncAndApplyRunsInvalidatorsOnNonFatalApplyError(t *testing.T) {
	s, peerText, webID := newSyncReadyStore(t)
	dp, v4, v6 := syncSessionDP(webID)

	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.setDataplane(dp) // #2114: publish through the cell
	d.applyBodyForTest = func(*config.Config) {}
	// Exactly the shape applyConfigLocked's tail joins (networkd/nft/Kea): the
	// config is active + the dataplane armed, only a best-effort subsystem failed.
	nonFatal := errors.New("apply host-inbound filter: simulated best-effort failure")
	d.applyErrForTest = nonFatal

	compiled, err := d.syncAndApplyForTest(context.Background(), peerText, nil)

	// The non-fatal tail error must be SURFACED (not swallowed) up the sync path.
	if !errors.Is(err, nonFatal) {
		t.Fatalf("syncAndApply must surface the non-fatal tail apply error; got %v", err)
	}
	// RED-on-revert (the core security signal): the sessions of the peer-DELETED
	// policy MUST be invalidated even though the apply's tail returned a non-fatal
	// error. The pre-fix early `return nil, err` skips the invalidators, leaving
	// them installed under stale authorization (fail-open).
	if _, ok := dp.v4[v4]; ok {
		t.Errorf("v4 session under peer-DELETED policy (id %d) survived the receive-side "+
			"invalidation on a non-fatal tail error (fail-open: stale authorization keeps forwarding)", webID)
	}
	if _, ok := dp.v6[v6]; ok {
		t.Errorf("v6 session under peer-DELETED policy (id %d) survived the receive-side "+
			"invalidation on a non-fatal tail error (fail-open)", webID)
	}
	// The invalidator's session scan must have actually run.
	if dp.iterateCalls == 0 {
		t.Errorf("the session table was never scanned on a non-fatal tail error; the three " +
			"invalidators must run once the config reached active+armed")
	}
	// The peer config is still active locally (promoted before the tail hiccup),
	// so the promoted config is returned alongside the error (mark-and-continue).
	if compiled == nil {
		t.Errorf("syncAndApply must return the promoted peer config on a non-fatal tail error; got nil")
	}
	// The peer config is promoted to active locally regardless of the tail hiccup.
	if _, ok := dpuserspace.PolicyIDsByStableKey(s.ActiveConfig())["trust->untrust/p-web"]; ok {
		t.Errorf("p-web is still in the active config after the sync; SyncApply must have promoted the peer delete")
	}
}

// TestSyncAndApplySkipsInvalidatorsOnFatalApplyError proves a genuinely-FATAL
// apply (a required-protocol-gate error that DISARMS the dataplane — the config
// is not live-forwarding) does NOT run the invalidators: there is no armed
// session state to invalidate, so a spurious clear must be avoided. The fatal
// error is still surfaced and the config discarded (nil), matching the primary
// applyAndSyncCommitted fatal branch.
func TestSyncAndApplySkipsInvalidatorsOnFatalApplyError(t *testing.T) {
	s, peerText, webID := newSyncReadyStore(t)
	dp, v4, v6 := syncSessionDP(webID)

	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.setDataplane(dp) // #2114: publish through the cell
	d.applyBodyForTest = func(*config.Config) {}
	d.applyErrForTest = dpuserspace.ErrPolicySchedulerProtocolIncompatible

	compiled, err := d.syncAndApplyForTest(context.Background(), peerText, nil)

	if !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("a fatal apply error must be surfaced; got %v", err)
	}
	if compiled != nil {
		t.Fatalf("a fatal apply error must return a nil config; got %+v", compiled)
	}
	// No spurious invalidation: the dataplane is disarmed (fail-closed), so the
	// sessions must NOT be swept and the session table must not even be scanned.
	if _, ok := dp.v4[v4]; !ok {
		t.Errorf("v4 session was invalidated on a FATAL (dataplane-disarmed) apply; the " +
			"invalidators must NOT run when the config never went live-forwarding")
	}
	if _, ok := dp.v6[v6]; !ok {
		t.Errorf("v6 session was invalidated on a FATAL (dataplane-disarmed) apply")
	}
	if dp.iterateCalls != 0 {
		t.Errorf("the session table was scanned (%d iterate calls) on a fatal apply; the "+
			"invalidators must be skipped entirely", dp.iterateCalls)
	}
}

// TestSyncAndApplyRunsInvalidatorsOnCleanApply guards against over-suppression:
// a clean apply (no tail error) on the receive path still invalidates the
// peer-deleted policy's sessions and returns a nil error.
func TestSyncAndApplyRunsInvalidatorsOnCleanApply(t *testing.T) {
	s, peerText, webID := newSyncReadyStore(t)
	dp, v4, v6 := syncSessionDP(webID)

	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.setDataplane(dp) // #2114: publish through the cell
	d.applyBodyForTest = func(*config.Config) {}
	// applyErrForTest nil = clean apply.

	compiled, err := d.syncAndApplyForTest(context.Background(), peerText, nil)
	if err != nil {
		t.Fatalf("a clean peer sync must succeed; got %v", err)
	}
	if compiled == nil {
		t.Fatalf("a clean peer sync must return the promoted config; got nil")
	}
	if _, ok := dp.v4[v4]; ok {
		t.Errorf("v4 session under peer-DELETED policy (id %d) survived a clean sync invalidation", webID)
	}
	if _, ok := dp.v6[v6]; ok {
		t.Errorf("v6 session under peer-DELETED policy (id %d) survived a clean sync invalidation", webID)
	}
}

// TestSyncAndApplySurfacesPartialInvalidationError is the #5578 pin on the
// RECEIVE path: a clean apply whose post-apply session invalidation FAILS (the
// batch delete errors, leaving the matched sessions installed under stale
// authorization) must surface that error up the sync path, joined into the
// return through the deferred invalidation.
func TestSyncAndApplySurfacesPartialInvalidationError(t *testing.T) {
	s, peerText, webID := newSyncReadyStore(t)
	dp, v4, v6 := syncSessionDP(webID)
	errBoom := errors.New("batch delete failed")
	dp.delErr = errBoom

	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.setDataplane(dp) // #2114: publish through the cell
	d.applyBodyForTest = func(*config.Config) {}

	compiled, err := d.syncAndApplyForTest(context.Background(), peerText, nil)
	if err == nil {
		t.Fatal("syncAndApply swallowed a failed policy session invalidation; the stale-" +
			"authorization gap must be surfaced up the sync-recv path (#5578)")
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("sync error %v does not carry the invalidation failure", err)
	}
	// Mark-and-continue: the config is still promoted to active and returned.
	if compiled == nil {
		t.Fatalf("a partial-invalidation error must not drop the promoted config; got nil")
	}
	// The stale-authorization gap: the delete failed, so the sessions remain.
	if _, ok := dp.v4[v4]; !ok {
		t.Error("precondition: v4 session should still be present after a failed delete (models stale authorization)")
	}
	if _, ok := dp.v6[v6]; !ok {
		t.Error("precondition: v6 session should still be present after a failed delete (models stale authorization)")
	}
}
