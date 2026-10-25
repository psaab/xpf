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
)

// #16668: a nested `commit confirmed` (re-issuing it to extend a pending
// window) must pre-flight the store's RETAINED original rollback target,
// not the unconfirmed active config. The store keeps confirmPrevCfg on a
// nested arm (store_commit.go), so the timer would restore C1, but the
// daemon gate read ActiveConfig (C2). When C2 binds a feed that has not
// fetched yet the mirror refuses it, so extending the window was falsely
// refused with an error naming dyn1 — a binding that exists only in the
// unconfirmed config the timer would NOT restore. The opposite direction
// (true target unappliable, unconfirmed config clean) was never checked.
//
// FAIL-ON-REVERT: restore `rollbackTarget := d.store.ActiveConfig()` (and
// the deviceMap argument) in commitConfirmedAndApply and the nested-arm
// cell reds (refused naming dyn1) while the unappliable-C1 cell also reds
// (wrongly armed).

// stage16668 applies lines to the candidate of a store already in
// configure mode.
func stage16668(t *testing.T, s *configstore.Store, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
}

func feedLines16668(host string) []string {
	return []string{
		"system host-name " + host,
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"security dynamic-address address-name dyn1 profile feed-name malware",
		"security policies from-zone trust to-zone untrust policy p1 match source-address dyn1",
		"security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"security policies from-zone trust to-zone untrust policy p1 match application any",
		"security policies from-zone trust to-zone untrust policy p1 then deny",
	}
}

func healthyLines16668(host string) []string {
	return []string{
		"system host-name " + host,
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"security policies from-zone trust to-zone untrust policy p1 match application any",
		"security policies from-zone trust to-zone untrust policy p1 then permit",
	}
}

func healthyText16668(host string) string {
	return "system { host-name " + host + "; }\n" +
		"security { zones { security-zone trust; security-zone untrust; } " +
		"policies { from-zone trust to-zone untrust { policy p1 { match { source-address any; destination-address any; application any; } then { permit; } } } } }\n"
}

// refusedLines16668 is a tolerant-only config the helper refuses as a
// whole snapshot (#9410: a zone pair naming an undefined zone). It can
// only become active via SyncApply, never via a strict commit.
const refusedTarget16668 = `system { host-name c1-refused; }
security { zones { security-zone trust; security-zone untrust; }
  policies { from-zone trust to-zone gone { policy bad1 { match { source-address any; destination-address any; application any; } then { permit; } } } } }
`

func newDaemon16668(t *testing.T) (*Daemon, *configstore.Store) {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}
	t.Cleanup(func() { _ = s.ConfirmCommit() })
	return d, s
}

// TestNestedCommitConfirmedPreflightsRetainedTarget16668 is the probe:
// C1 (healthy) is committed, C2 (feed-bound, no feed snapshot on this
// daemon) is armed with commit confirmed, then a nested commit confirmed
// of C3 must SUCCEED because the timer would restore healthy C1.
func TestNestedCommitConfirmedPreflightsRetainedTarget16668(t *testing.T) {
	d, s := newDaemon16668(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer s.ExitConfigure()

	stage16668(t, s, healthyLines16668("c1-healthy")...)
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit C1: %v", err)
	}

	// First arm: C2 binds dyn1 with no installed feed snapshot. The
	// rollback target here is healthy C1, so this arm must succeed even
	// though C2 itself is not yet appliable (commit confirmed does not
	// gate the candidate's own appliability, only the target's).
	if err := s.DeleteFromInput("security policies from-zone trust to-zone untrust policy p1 then permit"); err != nil {
		t.Fatalf("delete C1 permit: %v", err)
	}
	stage16668(t, s, feedLines16668("c2-feed")...)
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever); err != nil {
		t.Fatalf("first commit confirmed (C2 over healthy C1) must succeed: %v", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "c2-feed" {
		t.Fatalf("active = %q, want c2-feed", got)
	}
	if !s.IsConfirmPending() {
		t.Fatal("window must be pending after first arm")
	}
	// Premise: the retained target really is C1, and the unconfirmed
	// active (C2) really is the config the mirror refuses naming dyn1.
	target, pending, first := s.RollbackTargetForArm()
	if !pending || first || target == nil || target.System.HostName != "c1-healthy" {
		t.Fatalf("RollbackTargetForArm = (%v, pending=%v, first=%v), want c1-healthy pending target", target, pending, first)
	}
	if rerr := rollbackTargetAppliablePreflight(s.ActiveConfig(), d.feedSnapshotsForConfig(s.ActiveConfig())); rerr == nil ||
		!strings.Contains(rerr.Error(), "dyn1") {
		t.Fatalf("premise: unconfirmed C2 must be refused naming dyn1, got %v", rerr)
	}

	// Nested arm: extend the window with C3. Pre-fix this was refused
	// naming dyn1 (from C2); the true target C1 pre-flights clean.
	stage16668(t, s, "system host-name c3-extend")
	if _, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever); err != nil {
		t.Fatalf("nested commit confirmed must succeed (target is healthy C1): %v", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "c3-extend" {
		t.Fatalf("active = %q, want c3-extend", got)
	}
	if !s.IsConfirmPending() {
		t.Fatal("nested arm must keep the window pending")
	}
	// Extending must not have replaced the rollback target.
	target, pending, _ = s.RollbackTargetForArm()
	if !pending || target == nil || target.System.HostName != "c1-healthy" {
		t.Fatalf("after nested arm target = %v pending=%v, want retained c1-healthy", target, pending)
	}
}

// TestNestedCommitConfirmedRefusesUnappliableRetainedTarget16668 is the
// opposite direction: C1 is unappliable (installed via the tolerant sync
// ingress), C2 is clean, and a nested arm over C2 must be REFUSED naming
// C1's refusal — the true target is never skipped.
func TestNestedCommitConfirmedRefusesUnappliableRetainedTarget16668(t *testing.T) {
	d, s := newDaemon16668(t)
	if _, err := s.SyncApply(refusedTarget16668, nil); err != nil {
		t.Fatalf("SyncApply(C1): %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer s.ExitConfigure()

	// Arm C2 directly at store level: the daemon gate would (correctly)
	// refuse to arm over unappliable C1, so set up the pending window
	// the way a pre-gate or recovered window could exist, then exercise
	// only the NESTED arm through the daemon. LoadOverride replaces the
	// candidate wholesale so the strict commit-check does not compile
	// C1's unresolvable `gone` zone into the candidate.
	if err := s.LoadOverride(healthyText16668("c2-clean")); err != nil {
		t.Fatalf("LoadOverride(C2): %v", err)
	}
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatalf("store CommitConfirmed(C2): %v", err)
	}
	if got := s.ActiveConfig().System.HostName; got != "c2-clean" {
		t.Fatalf("active = %q, want c2-clean", got)
	}
	target, pending, _ := s.RollbackTargetForArm()
	if !pending || target == nil || target.System.HostName != "c1-refused" {
		t.Fatalf("retained target = %v pending=%v, want c1-refused", target, pending)
	}

	stage16668(t, s, "system host-name c3-extend")
	_, err := d.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 5, peerSyncNever)
	if err == nil {
		t.Fatal("nested commit confirmed over unappliable retained target C1 must be refused")
	}
	if !errors.Is(err, errRollbackTargetUnappliable) {
		t.Errorf("error %v does not wrap errRollbackTargetUnappliable", err)
	}
	if !strings.Contains(err.Error(), "gone") {
		t.Errorf("refusal must name C1's refusal (zone gone), got: %v", err)
	}
	if strings.Contains(err.Error(), "c2-clean") {
		t.Errorf("refusal must not blame the unconfirmed config: %v", err)
	}
	// The refused nested arm must not have promoted C3 or cleared the window.
	if got := s.ActiveConfig().System.HostName; got != "c2-clean" {
		t.Fatalf("active = %q after refused nested arm, want c2-clean", got)
	}
	if !s.IsConfirmPending() {
		t.Fatal("refused nested arm must leave the original window pending")
	}
}

// TestRollbackTargetForArmNonNested16668 pins the non-nested contract:
// with no window pending the arm target is the active config, and with a
// first-commit window pending it is the nil first-commit target.
func TestRollbackTargetForArmNonNested16668(t *testing.T) {
	_, s := newDaemon16668(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer s.ExitConfigure()
	stage16668(t, s, healthyLines16668("only")...)
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	target, pending, first := s.RollbackTargetForArm()
	if pending || first || target == nil || target.System.HostName != "only" {
		t.Fatalf("no window: target=%v pending=%v first=%v, want active only", target, pending, first)
	}
	stage16668(t, s, "system host-name second")
	if _, err := s.CommitConfirmed(5); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	target, pending, first = s.RollbackTargetForArm()
	if !pending || first || target == nil || target.System.HostName != "only" {
		t.Fatalf("pending window: target=%v pending=%v first=%v, want retained only", target, pending, first)
	}
}
