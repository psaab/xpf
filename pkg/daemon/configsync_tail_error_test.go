// #4034: HA config divergence when a NON-FATAL error in the tail of the config
// apply path skips the peer config-sync.
//
// commitAndApply / commitConfirmedAndApply promote+persist the compiled config,
// run applyConfigLocked, then push the config to the standby via
// syncConfigToPeer. applyConfigLocked's tail deliberately JOINS the best-effort
// subsystem failures (networkd file write #2987, Kea restart #1778/#1835,
// host-inbound #3333 / lo0 #3392 nft apply) and returns them so the operator
// sees a fail-closed commit — but the config is still committed + active and the
// dataplane is armed and forwarding. Before the fix, that non-fatal error
// short-circuited before syncConfigToPeer, so the standby never received the new
// config and the nodes DIVERGED (a failover then served stale config).
//
// These tests pin the fix: a non-fatal tail apply error STILL syncs to the peer,
// a clean commit syncs once, and the two error classes that MUST NOT propagate
// (a required-protocol-gate error → dataplane disarmed; a daemon-stop context
// abort) still skip the sync. RED-on-revert: dropping the applyAndSyncCommitted
// non-fatal branch leaves the non-fatal test at 0 pushes (standby stays stale).
package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// newCommitReadyStore builds a store with a committed baseline and a staged
// candidate change, so a subsequent commitAndApply / commitConfirmedAndApply has
// a real diff to promote.
func newCommitReadyStore(t *testing.T, baseline, staged string) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput(baseline); err != nil {
		t.Fatalf("set baseline %q: %v", baseline, err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit baseline: %v", err)
	}
	// Commit() leaves the store in configure mode with the candidate recloned
	// from active, so stage the next change directly.
	if err := s.SetFromInput(staged); err != nil {
		t.Fatalf("set staged %q: %v", staged, err)
	}
	return s
}

// TestCommitAndApplySyncsPeerOnNonFatalApplyError is the #4034 pin: a commit
// whose tail subsystem apply returns a NON-FATAL error still pushes the
// committed config to the standby. RED-on-revert — removing the fix skips the
// push (syncCalls==0) and the standby keeps the OLD config.
func TestCommitAndApplySyncsPeerOnNonFatalApplyError(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}

	// Exactly the shape applyConfigLocked's tail joins (networkd/Kea/nft): the
	// config is committed + active and the dataplane armed, only a best-effort
	// subsystem write failed.
	nonFatal := errors.New("apply networkd config: simulated best-effort failure")
	d.applyErrForTest = nonFatal

	var (
		syncCalls  int
		syncedText string
	)
	d.syncPeerForTest = func() {
		syncCalls++
		syncedText = d.store.ShowActive()
	}

	compiled, err := d.commitAndApply(t.Context(), configstore.InternalCommitter(), "", peerSyncAlways)

	// The apply error must surface to the operator (fail-closed commit).
	if !errors.Is(err, nonFatal) {
		t.Fatalf("commitAndApply must surface the non-fatal apply error; got %v", err)
	}
	// The peer sync must STILL have fired exactly once (the #4034 fix).
	if syncCalls != 1 {
		t.Fatalf("a non-fatal tail apply error must STILL push the committed config to the "+
			"peer exactly once (#4034); got %d pushes (standby stays stale → HA divergence)", syncCalls)
	}
	// It must carry the NEW committed config, not OLD.
	if !strings.Contains(syncedText, "host-name NEW") {
		t.Fatalf("peer sync must carry the committed config (host-name NEW); got:\n%s", syncedText)
	}
	if strings.Contains(syncedText, "host-name OLD") {
		t.Fatalf("peer sync carried the stale pre-commit config (host-name OLD):\n%s", syncedText)
	}
	// The committed config is returned alongside the non-fatal error.
	if compiled == nil || compiled.System.HostName != "NEW" {
		t.Fatalf("commitAndApply must return the committed config on a non-fatal error; got %+v", compiled)
	}
	// The local store is committed to NEW regardless of the subsystem hiccup.
	if got := s.ActiveConfig().System.HostName; got != "NEW" {
		t.Fatalf("local active host-name = %q, want NEW", got)
	}
}

// TestCommitAndApplySyncsPeerOnCleanCommit proves the ordinary success path
// still syncs exactly once (guards against the fix over-suppressing).
func TestCommitAndApplySyncsPeerOnCleanCommit(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}
	// applyErrForTest nil = clean apply.

	var syncCalls int
	d.syncPeerForTest = func() { syncCalls++ }

	compiled, err := d.commitAndApply(t.Context(), configstore.InternalCommitter(), "", peerSyncAlways)
	if err != nil {
		t.Fatalf("clean commit must succeed; got %v", err)
	}
	if syncCalls != 1 {
		t.Fatalf("a clean commit must sync to the peer exactly once; got %d", syncCalls)
	}
	if compiled == nil || compiled.System.HostName != "NEW" {
		t.Fatalf("clean commit must return the committed config; got %+v", compiled)
	}
}

// TestCommitAndApplySkipsPeerSyncOnFatalApplyError proves a FATAL
// required-protocol-gate error (dataplane disarmed, fail-closed) does NOT push a
// disarm-config to the standby. #16828: the store has already promoted the
// config, so the promoted config is returned with an
// ErrCommittedNotApplied-wrapped error (previously nil, which the
// REST/gRPC classifiers misread as a pre-promotion reject).
func TestCommitAndApplySkipsPeerSyncOnFatalApplyError(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}
	d.applyErrForTest = dpuserspace.ErrPolicySchedulerProtocolIncompatible

	var syncCalls int
	d.syncPeerForTest = func() { syncCalls++ }

	compiled, err := d.commitAndApply(t.Context(), configstore.InternalCommitter(), "", peerSyncAlways)
	if !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("fatal apply error must surface; got %v", err)
	}
	if !errors.Is(err, configstore.ErrCommittedNotApplied) {
		t.Fatalf("fatal post-promotion error must wrap ErrCommittedNotApplied (#16828); got %v", err)
	}
	if syncCalls != 0 {
		t.Fatalf("a fatal (dataplane-disarmed) apply error must NOT push a disarm-config "+
			"to the peer; got %d pushes", syncCalls)
	}
	if compiled == nil || compiled.System.HostName != "NEW" {
		t.Fatalf("fatal post-promotion abort must return the promoted config (#16828); got %+v", compiled)
	}
}

// TestCommitAndApplySkipsPeerSyncOnContextAbort proves a daemon-stop context
// abort (#2926 boundary) does NOT push during teardown — the reverse-sync on
// reconnect converges the peer on next boot.
func TestCommitAndApplySkipsPeerSyncOnContextAbort(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}
	d.applyErrForTest = context.Canceled

	var syncCalls int
	d.syncPeerForTest = func() { syncCalls++ }

	_, err := d.commitAndApply(t.Context(), configstore.InternalCommitter(), "", peerSyncAlways)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context abort must surface; got %v", err)
	}
	if syncCalls != 0 {
		t.Fatalf("a daemon-stop context abort must NOT push to the peer; got %d pushes", syncCalls)
	}
}

// TestCommitConfirmedAndApplySyncsPeerOnNonFatalApplyError proves the
// commit-confirmed path shares the same non-fatal-error sync behavior via
// applyAndSyncCommitted.
func TestCommitConfirmedAndApplySyncsPeerOnNonFatalApplyError(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name OLD", "system host-name NEW")
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}
	nonFatal := errors.New("apply DHCP server config: simulated best-effort failure")
	d.applyErrForTest = nonFatal

	var syncCalls int
	d.syncPeerForTest = func() { syncCalls++ }

	compiled, err := d.commitConfirmedAndApply(t.Context(), configstore.InternalCommitter(), 1, peerSyncAlways)
	if !errors.Is(err, nonFatal) {
		t.Fatalf("commitConfirmedAndApply must surface the non-fatal apply error; got %v", err)
	}
	if syncCalls != 1 {
		t.Fatalf("commit-confirmed with a non-fatal tail error must still sync to the peer "+
			"exactly once (#4034); got %d pushes", syncCalls)
	}
	if compiled == nil || compiled.System.HostName != "NEW" {
		t.Fatalf("commit-confirmed must return the committed config on a non-fatal error; got %+v", compiled)
	}
}
