package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/daemon"
)

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
	oldInstall, oldPresent, oldHost, oldActive := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing, xpfdUnitActive
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	hostInboundEnforcing = func() (bool, error) { return false, nil }
	xpfdUnitActive = func() bool { return false }
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
	// Post-handoff (marker): no-op success, no install.
	earlyInputBarrierInstall = func() error { installs++; return nil }
	if err := os.WriteFile(daemon.EarlyInputHandoffMarkerPath, []byte("handed-off\n"), 0644); err != nil {
		t.Fatalf("stage marker: %v", err)
	}
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
	oldInstall, oldPresent, oldHost, oldActive := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing, xpfdUnitActive
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	hostInboundEnforcing = func() (bool, error) { return true, nil }
	xpfdUnitActive = func() bool { return true }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure with live enforcement exit = %d, want 0", code)
	}
	if installs != 0 {
		t.Fatal("ensure must not install when enforcement is live despite the missing marker")
	}
	if !strings.Contains(stdout.String(), "enforcement is live") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want live-enforcement no-op note on stdout only", stdout.String(), stderr.String())
	}
}

// TestInputBarrierEnsurePreservesStandingBarrier10751 (#10751 R5-C
// lifecycle check 2): marker absent, no enforcement, barrier already
// present (a live bootstrap lifeline guard) — a reload/start must NO-OP,
// never replace the guard with the global form.
func TestInputBarrierEnsurePreservesStandingBarrier10751(t *testing.T) {
	oldInstall, oldPresent, oldHost, oldActive := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing, xpfdUnitActive
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierEnforcing = func() (bool, error) { return true, nil }
	hostInboundEnforcing = func() (bool, error) { return false, nil }
	xpfdUnitActive = func() bool { return false }
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
	oldInstall, oldPresent, oldHost, oldActive := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing, xpfdUnitActive
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, errors.New("list denied") }
	hostInboundEnforcing = func() (bool, error) { return false, errors.New("list denied") }
	xpfdUnitActive = func() bool { return false }
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
	oldInstall, oldPresent, oldHost, oldActive := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing, xpfdUnitActive
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	hostInboundEnforcing = func() (bool, error) { return true, nil }
	xpfdUnitActive = func() bool { return false }
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
	oldInstall, oldPresent, oldHost, oldActive := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing, xpfdUnitActive
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundEnforcing = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	installs := 0
	earlyInputBarrierInstall = func() error { installs++; return nil }
	hostInboundEnforcing = func() (bool, error) { return false, nil }
	xpfdUnitActive = func() bool { return true }
	earlyInputBarrierEnforcing = func() (bool, error) { return false, nil }
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure over shell tables exit = %d, want 0 via install", code)
	}
	if installs != 1 {
		t.Fatalf("installs = %d, want 1: shell tables must install, never no-op", installs)
	}
}
