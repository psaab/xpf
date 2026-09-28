package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/daemon"
)

// holdMarkerLock10751 simulates a live owner: it opens path and holds an
// exclusive flock until the test ends. An unlocked-but-present marker file
// simulates prior-process state surviving failed cleanup (stale).
func holdMarkerLock10751(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		t.Fatalf("flock %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
}

// holdMarkerSharedLock10751 simulates a LOCK_SH forgery attempt: it opens
// path and holds a shared flock until the test ends. The liveness probe
// must NOT read shared-only contention as a live exclusive owner.
func holdMarkerSharedLock10751(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		t.Fatalf("shared flock %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
}

func TestInputBarrierCommand10751(t *testing.T) {
	if got := classifyCommand([]string{"xpfd", "input-barrier"}); got != cmdInputBarrier {
		t.Fatalf("classifyCommand input-barrier = %d, want %d", got, cmdInputBarrier)
	}
	for _, args := range [][]string{{}, {"open"}, {"close", "extra"}, {"remove", "extra"}, {"ensure", "extra"}, {"ensure", "--force"}} {
		if err := parseInputBarrierArgs(args); err == nil {
			t.Errorf("parseInputBarrierArgs(%q) unexpectedly succeeded", args)
		}
	}
	for _, args := range [][]string{{"close"}, {"remove"}, {"close", "--force"}, {"ensure"}} {
		if err := parseInputBarrierArgs(args); err != nil {
			t.Errorf("parseInputBarrierArgs(%q): %v", args, err)
		}
	}
}

func TestInputBarrierCommandReportsInstallAndRemoveResults10751(t *testing.T) {
	oldInstall, oldRemove := earlyInputBarrierInstall, earlyInputBarrierRemove
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierRemove = oldInstall, oldRemove
	})

	var stdout, stderr bytes.Buffer
	var installs, removes int
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierRemove = func() error { removes++; return nil }
	if code := runInputBarrierSubcommand([]string{"close"}, &stdout, &stderr); code != 0 {
		t.Fatalf("successful install exit code = %d (stderr=%q)", code, stderr.String())
	}
	if installs != 1 || !strings.Contains(stdout.String(), "early input barrier installed") || stderr.Len() != 0 {
		t.Fatalf("successful install: calls=%d stdout=%q stderr=%q", installs, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	installErr := errors.New("nftables permission denied")
	earlyInputBarrierInstall = func() error { installs++; return installErr }
	if code := runInputBarrierSubcommand([]string{"close"}, &stdout, &stderr); code != 1 {
		t.Fatalf("failed install exit code = %d, want 1", code)
	}
	if installs != 2 || !strings.Contains(stderr.String(), installErr.Error()) || stdout.Len() != 0 {
		t.Fatalf("failed install: calls=%d stdout=%q stderr=%q", installs, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runInputBarrierSubcommand([]string{"remove"}, &stdout, &stderr); code != 0 {
		t.Fatalf("successful remove exit code = %d (stderr=%q)", code, stderr.String())
	}
	if removes != 1 || !strings.Contains(stdout.String(), "early input barrier removed") || stderr.Len() != 0 {
		t.Fatalf("successful remove: calls=%d stdout=%q stderr=%q", removes, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	removeErr := errors.New("nftables delete denied")
	earlyInputBarrierRemove = func() error { removes++; return removeErr }
	if code := runInputBarrierSubcommand([]string{"remove"}, &stdout, &stderr); code != 1 {
		t.Fatalf("failed remove exit code = %d, want 1", code)
	}
	if removes != 2 || !strings.Contains(stderr.String(), removeErr.Error()) || stdout.Len() != 0 {
		t.Fatalf("failed remove: calls=%d stdout=%q stderr=%q", removes, stdout.String(), stderr.String())
	}
}

func TestInputBarrierCloseRefusesAfterHandoff10751(t *testing.T) {
	oldInstall := earlyInputBarrierInstall
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall = oldInstall
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"close"}, &stdout, &stderr); code != 0 {
		t.Fatalf("close without marker exit = %d, want 0", code)
	}
	if installs != 1 {
		t.Fatalf("installs = %d, want 1 pre-handoff install", installs)
	}
	if err := os.WriteFile(daemon.EarlyInputHandoffMarkerPath, []byte("handed-off\n"), 0644); err != nil {
		t.Fatalf("stage marker: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runInputBarrierSubcommand([]string{"close"}, &stdout, &stderr); code != 1 {
		t.Fatalf("close with marker exit = %d, want 1", code)
	}
	if installs != 1 {
		t.Fatal("refused close must not install")
	}
	if !strings.Contains(stderr.String(), "already handed off") {
		t.Fatalf("refusal stderr = %q, want handoff explanation", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runInputBarrierSubcommand([]string{"close", "--force"}, &stdout, &stderr); code != 0 {
		t.Fatalf("close --force exit = %d, want 0", code)
	}
	if installs != 2 {
		t.Fatalf("installs = %d, want forced reinstall to proceed", installs)
	}
}

// TestInputBarrierEnsure10751 pins the ExecStart verb (#10751 R4-4):
// post-handoff it is a verified no-op SUCCESS (never install into a live
// daemon, never fail an xpfd start behind its Requires edge); pre-handoff
// it installs fail-closed like close.
func TestInputBarrierEnsure10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive, oldFirst := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive, hostInboundFirstApplied
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		hostInboundFirstApplied = oldFirst
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	hostInboundDropsInput = func() (bool, error) { return false, nil }
	xpfdUnitActive = func() bool { return false }
	hostInboundFirstApplied = func() bool { return false }
	var stdout, stderr bytes.Buffer
	// Pre-handoff (no marker): install, fail-closed on error.
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure without marker exit = %d, want 0", code)
	}
	if installs != 1 || !strings.Contains(stdout.String(), "early input barrier installed") {
		t.Fatalf("ensure without marker: installs=%d stdout=%q, want an install", installs, stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	installErr := errors.New("nftables permission denied")
	earlyInputBarrierInstall = func() error { installs++; return installErr }
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 1 {
		t.Fatalf("failed ensure exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), installErr.Error()) {
		t.Fatalf("failed ensure stderr = %q, want the install error", stderr.String())
	}
	// Post-handoff (live marker): no-op success, no install. The lock
	// simulates the live owner; a merely present marker is stale (M2).
	earlyInputBarrierInstall = func() error { installs++; return nil }
	if err := os.WriteFile(daemon.EarlyInputHandoffMarkerPath, []byte("handed-off\n"), 0644); err != nil {
		t.Fatalf("stage marker: %v", err)
	}
	holdMarkerLock10751(t, daemon.EarlyInputHandoffMarkerPath)
	stdout.Reset()
	stderr.Reset()
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure with marker exit = %d, want 0 (verified no-op success)", code)
	}
	if installs != 2 {
		t.Fatalf("installs = %d, want 2: post-handoff ensure must not install", installs)
	}
	if !strings.Contains(stdout.String(), "nothing to do") || stderr.Len() != 0 {
		t.Fatalf("ensure with marker stdout=%q stderr=%q, want no-op note on stdout only", stdout.String(), stderr.String())
	}
}

// TestInputBarrierEnsurePreservesLiveEnforcement10751 (#10751 R5-C
// lifecycle check 1): marker absent (write failed or cleared) but
// host-inbound enforcement live — a unit start must NO-OP, never install
// global DROP into the live handed-off daemon.
func TestInputBarrierEnsurePreservesLiveEnforcement10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive, oldFirst := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive, hostInboundFirstApplied
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		hostInboundFirstApplied = oldFirst
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	hostInboundDropsInput = func() (bool, error) { return true, nil }
	xpfdUnitActive = func() bool { return true }
	hostInboundFirstApplied = func() bool { return true }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure with live enforcement exit = %d, want 0", code)
	}
	if installs != 0 {
		t.Fatal("ensure must not install when enforcement is live despite the missing marker")
	}
	if !strings.Contains(stdout.String(), "enforcement is live") || !strings.Contains(stdout.String(), "next pre-apply") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want live-enforcement no-op note with stale caveat on stdout only", stdout.String(), stderr.String())
	}
}

// TestInputBarrierEnsurePreservesStandingBarrier10751 (#10751 R5-C
// lifecycle check 2): marker absent, no enforcement, barrier already
// present (a live bootstrap lifeline guard) — a reload/start must NO-OP,
// never replace the guard with the global form.
func TestInputBarrierEnsurePreservesStandingBarrier10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive, oldFirst := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive, hostInboundFirstApplied
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		hostInboundFirstApplied = oldFirst
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierEnforcing = func() (bool, error) { return true, nil }
	hostInboundDropsInput = func() (bool, error) { return false, nil }
	xpfdUnitActive = func() bool { return false }
	hostInboundFirstApplied = func() bool { return false }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure with standing barrier exit = %d, want 0", code)
	}
	if installs != 0 {
		t.Fatal("ensure must not reinstall over a standing barrier (would clobber a lifeline guard)")
	}
	if !strings.Contains(stdout.String(), "already present") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want already-present no-op note on stdout only", stdout.String(), stderr.String())
	}
}

// TestInputBarrierEnsureReadErrorFallsThrough10751: unreadable readbacks
// prove nothing live, so ensure falls through to the fail-closed install
// (pre-handoff boot path preserved).
func TestInputBarrierEnsureReadErrorFallsThrough10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive, oldFirst := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive, hostInboundFirstApplied
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		hostInboundFirstApplied = oldFirst
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, errors.New("list denied") }
	hostInboundDropsInput = func() (bool, error) { return false, errors.New("list denied") }
	xpfdUnitActive = func() bool { return false }
	hostInboundFirstApplied = func() bool { return false }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure with unreadable state exit = %d, want 0 via fail-closed install", code)
	}
	if installs != 1 {
		t.Fatalf("installs = %d, want 1: unreadable state must install fail-closed", installs)
	}
}

// TestInputBarrierEnsureInstallsOverStaleTable10751 (#10751 R6-B service-
// order fixture): marker absent, no xpfd unit, no barrier, but an
// enforcing-shaped xpf_hostinbound table restored by nftables.service with
// stale coverage. Table shape alone must NOT no-op — only a RUNNING xpfd
// proves currentness — so ensure INSTALLS the barrier before networkd.
// RED on revert: drop the xpfd-active check and ensure no-ops over stale.
func TestInputBarrierEnsureInstallsOverStaleTable10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive, oldFirst := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive, hostInboundFirstApplied
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		hostInboundFirstApplied = oldFirst
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	hostInboundDropsInput = func() (bool, error) { return true, nil }
	xpfdUnitActive = func() bool { return false }
	hostInboundFirstApplied = func() bool { return true }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure over stale table exit = %d, want 0 via install", code)
	}
	if installs != 1 || !strings.Contains(stdout.String(), "early input barrier installed") {
		t.Fatalf("installs=%d stdout=%q, want a barrier install over the stale table", installs, stdout.String())
	}
}

// TestInputBarrierEnsureInstallsOverShellTable10751 (shell-table advisory):
// a present-but-flushed host-inbound table (no input chain/rules) reads
// non-enforcing even with xpfd live — ensure must INSTALL, not no-op over
// an open shell. Same for a shelled barrier table.
func TestInputBarrierEnsureInstallsOverShellTable10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive, oldFirst := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive, hostInboundFirstApplied
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		hostInboundFirstApplied = oldFirst
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	hostInboundDropsInput = func() (bool, error) { return false, nil }
	xpfdUnitActive = func() bool { return true }
	hostInboundFirstApplied = func() bool { return true }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure over shell tables exit = %d, want 0 via install", code)
	}
	if installs != 1 {
		t.Fatalf("installs = %d, want 1: shell tables must install, never no-op", installs)
	}
}

// TestInputBarrierEnsureInstallsAdmitsOnlyPreApply10751 (Opus7 R4-4 exact
// conjunction): marker absent, barrier absent, an ADMITS-ONLY policy-accept
// host table (mandatory admits, zero DROP — enforcing-shaped but not
// dropping), and xpfd is-active true BEFORE its first apply (Type=simple
// is active-at-fork). ensure MUST install: admits without DROP admit
// everything unmatched, and ACTIVE alone never proves current ownership.
// RED on revert: DROP-blind presence (rules>0) + bare ACTIVE no-ops here.
func TestInputBarrierEnsureInstallsAdmitsOnlyPreApply10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive, oldFirst := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive, hostInboundFirstApplied
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		hostInboundFirstApplied = oldFirst
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	hostInboundDropsInput = func() (bool, error) { return false, nil }
	hostInboundFirstApplied = func() bool { return false }
	xpfdUnitActive = func() bool { return true }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure over admits-only pre-apply exit = %d, want 0 via install", code)
	}
	if installs != 1 {
		t.Fatalf("installs = %d, want 1: admits-only + active-pre-apply must install, never no-op", installs)
	}
}

// TestInputBarrierEnsureInstallsStalePreFirstApply10751: DROP-ful table
// (stale restore with drops) + first-apply FALSE + xpfd active (forked
// but not yet applied — the Type=simple readiness gap) → MUST install.
// First-apply attestation, not process liveness, proves currentness.
func TestInputBarrierEnsureInstallsStalePreFirstApply10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive, oldFirst := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive, hostInboundFirstApplied
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		hostInboundFirstApplied = oldFirst
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	hostInboundDropsInput = func() (bool, error) { return true, nil }
	hostInboundFirstApplied = func() bool { return false }
	xpfdUnitActive = func() bool { return true }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure stale pre-first-apply exit = %d, want 0 via install", code)
	}
	if installs != 1 {
		t.Fatalf("installs = %d, want 1: DROP-ful but unapplied must install", installs)
	}
}

// TestInputBarrierEnsureRejectsStaleOwnership10751 (Opus8 R4-4a): a
// same-boot restart whose markers survive failed best-effort removal
// (prior-process files, no live holder) plus an old DROP-bearing table,
// no barrier, and ACTIVE xpfd must NOT read as current ownership —
// ensure installs fail-closed. A HELD marker (live owner) still no-ops,
// and a live first-apply with a stale handoff trusts the live half.
// hostInboundFirstApplied is deliberately NOT stubbed: the real
// file-backed wiring is under test.
func TestInputBarrierEnsureRejectsStaleOwnership10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive
	oldHandoff, oldFirst := daemon.EarlyInputHandoffMarkerPath, daemon.HostInboundFirstApplyMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		daemon.EarlyInputHandoffMarkerPath, daemon.HostInboundFirstApplyMarkerPath = oldHandoff, oldFirst
	})
	dir := t.TempDir()
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(dir, "early-input-handoff.done")
	daemon.HostInboundFirstApplyMarkerPath = filepath.Join(dir, "host-inbound-applied.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	hostInboundDropsInput = func() (bool, error) { return true, nil }
	xpfdUnitActive = func() bool { return true }
	stage := func(t *testing.T) {
		t.Helper()
		if err := os.WriteFile(daemon.EarlyInputHandoffMarkerPath, []byte("handed-off\n"), 0644); err != nil {
			t.Fatalf("stage handoff: %v", err)
		}
		if err := os.WriteFile(daemon.HostInboundFirstApplyMarkerPath, []byte("applied\n"), 0644); err != nil {
			t.Fatalf("stage first-apply: %v", err)
		}
	}
	run := func(t *testing.T) (int, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr)
		if stderr.Len() != 0 {
			t.Fatalf("ensure stderr = %q, want empty", stderr.String())
		}
		return code, stdout.String()
	}
	t.Run("stale installs", func(t *testing.T) {
		stage(t) // no locks: prior-process files surviving failed removal
		before := installs
		code, out := run(t)
		if code != 0 || installs-before != 1 || !strings.Contains(out, "early input barrier installed") {
			t.Fatalf("stale ownership: code=%d installs-delta=%d out=%q, want a fail-closed install", code, installs-before, out)
		}
	})
	t.Run("live no-ops", func(t *testing.T) {
		stage(t)
		holdMarkerLock10751(t, daemon.EarlyInputHandoffMarkerPath)
		holdMarkerLock10751(t, daemon.HostInboundFirstApplyMarkerPath)
		before := installs
		code, out := run(t)
		if code != 0 || installs-before != 0 || !strings.Contains(out, "nothing to do") {
			t.Fatalf("live ownership: code=%d installs-delta=%d out=%q, want a verified no-op", code, installs-before, out)
		}
	})
	t.Run("mixed trusts live half", func(t *testing.T) {
		stage(t)
		holdMarkerLock10751(t, daemon.HostInboundFirstApplyMarkerPath)
		before := installs
		code, out := run(t)
		if code != 0 || installs-before != 0 || !strings.Contains(out, "enforcement is live") {
			t.Fatalf("mixed ownership: code=%d installs-delta=%d out=%q, want the live-enforcement no-op", code, installs-before, out)
		}
	})
	t.Run("shared-lock forgery installs", func(t *testing.T) {
		stage(t)
		holdMarkerSharedLock10751(t, daemon.EarlyInputHandoffMarkerPath)
		holdMarkerSharedLock10751(t, daemon.HostInboundFirstApplyMarkerPath)
		before := installs
		code, out := run(t)
		if code != 0 || installs-before != 1 || !strings.Contains(out, "early input barrier installed") {
			t.Fatalf("SH forgery: code=%d installs-delta=%d out=%q, want a fail-closed install (shared-only is not ownership)", code, installs-before, out)
		}
	})
}
