package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/daemon"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #18746, AG on #18759: both ensure probes are generation-bracketed since
// c6cde9d858, so an nft commit landing during a probe makes it unreadable,
// and an unreadable probe falls through to the global install. Without a
// re-read, one concurrent commit (the live daemon's own apply) would install
// global DROP into a live daemon, or replace a standing lifeline guard with
// the global form. Both are the outcomes runInputBarrierEnsure exists to
// prevent.

// ensureProbes18746 installs scripted probes. Each probe returns its
// scripted results in order, then repeats the last one.
func ensureProbes18746(t *testing.T, host, barrier []probeResult18746, active bool) (installs, hostReads, barrierReads *int) {
	t.Helper()
	oldInstall, oldPresent, oldHost, oldActive, oldFirst := earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput, xpfdUnitActive, hostInboundFirstApplied
	oldMarker := daemon.EarlyInputHandoffMarkerPath
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierEnforcing, hostInboundDropsInput = oldInstall, oldPresent, oldHost
		xpfdUnitActive = oldActive
		hostInboundFirstApplied = oldFirst
		daemon.EarlyInputHandoffMarkerPath = oldMarker
	})
	daemon.EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	var i, h, b int
	earlyInputBarrierInstall = func() error { i++; return nil }
	script := func(results []probeResult18746, n *int) func() (bool, error) {
		return func() (bool, error) {
			r := results[min(*n, len(results)-1)]
			*n++
			return r.ok, r.err
		}
	}
	hostInboundDropsInput = script(host, &h)
	earlyInputBarrierEnforcing = script(barrier, &b)
	xpfdUnitActive = func() bool { return active }
	hostInboundFirstApplied = func() bool { return active }
	return &i, &h, &b
}

type probeResult18746 struct {
	ok  bool
	err error
}

var (
	moved18746 = probeResult18746{err: &xnft.GenerationChangedError{CommitsObserved: 1, Before: 4, After: 5}}
	yes18746   = probeResult18746{ok: true}
	no18746    = probeResult18746{}
)

func runEnsure18746(t *testing.T) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := runInputBarrierSubcommand([]string{"ensure"}, &stdout, &stderr); code != 0 {
		t.Fatalf("ensure exit = %d (stderr %q), want 0", code, stderr.String())
	}
	return stdout.String()
}

// Live daemon enforcing host input; one commit lands during the first probe.
func TestEnsureRereadsLiveEnforcementAcrossAMovedGeneration18746(t *testing.T) {
	installs, hostReads, _ := ensureProbes18746(t, []probeResult18746{moved18746, yes18746}, []probeResult18746{no18746}, true)
	runEnsure18746(t)
	if *installs != 0 {
		t.Fatal("one commit during the host-inbound probe installed global DROP into a live daemon")
	}
	if *hostReads != 2 {
		t.Errorf("host-inbound probe read %d times, want 2", *hostReads)
	}
}

// A standing lifeline guard; one commit lands during the barrier probe.
func TestEnsureRereadsStandingGuardAcrossAMovedGeneration18746(t *testing.T) {
	installs, _, barrierReads := ensureProbes18746(t, []probeResult18746{no18746}, []probeResult18746{moved18746, yes18746}, false)
	runEnsure18746(t)
	if *installs != 0 {
		t.Fatal("one commit during the barrier probe replaced a standing guard with the global form")
	}
	if *barrierReads != 2 {
		t.Errorf("barrier probe read %d times, want 2", *barrierReads)
	}
}

// Steady churn: the re-reads are bounded and ensure still fails closed, as
// documented on runInputBarrierEnsure.
func TestEnsureUnderChurnStillFailsClosed18746(t *testing.T) {
	installs, hostReads, barrierReads := ensureProbes18746(t, []probeResult18746{moved18746}, []probeResult18746{moved18746}, true)
	runEnsure18746(t)
	if *installs != 1 {
		t.Errorf("installs = %d under constant churn, want 1 (fail-closed)", *installs)
	}
	want := 1 + xnft.GenerationChangeRereads
	if *hostReads != want || *barrierReads != want {
		t.Errorf("probes read host=%d barrier=%d times, want %d each (bounded)", *hostReads, *barrierReads, want)
	}
}

// A real read error is not re-read.
func TestEnsureDoesNotRereadARealError18746(t *testing.T) {
	denied := probeResult18746{err: errors.New("list denied")}
	installs, hostReads, barrierReads := ensureProbes18746(t, []probeResult18746{denied, yes18746}, []probeResult18746{denied, yes18746}, true)
	runEnsure18746(t)
	if *hostReads != 1 || *barrierReads != 1 {
		t.Errorf("a non-generation error was re-read: host=%d barrier=%d reads, want 1 each", *hostReads, *barrierReads)
	}
	if *installs != 1 {
		t.Errorf("installs = %d, want the documented fail-closed install", *installs)
	}
}
