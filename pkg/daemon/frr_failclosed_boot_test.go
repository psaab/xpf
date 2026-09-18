package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
)

// seededFRRConf writes a temp frr.conf carrying an xpf-managed section with a
// sentinel route line, and returns the conf path plus the sentinel so a test
// can assert the section was (or was not) stripped. The base "log syslog
// informational" line stands in for operator-owned content outside the markers,
// which must always survive.
func seededFRRConf(t *testing.T) (path, sentinel string) {
	t.Helper()
	begin, end := frr.ManagedSectionMarkersForTest()
	sentinel = "ip route 10.99.0.0/24 192.0.2.1"
	content := "log syslog informational\n" +
		begin + "\n" +
		sentinel + "\n" +
		end + "\n"
	path = filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("seed frr.conf: %v", err)
	}
	return path, sentinel
}

func readConf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frr.conf: %v", err)
	}
	return string(b)
}

func withFailClosedBootPinnedXDPProbe(t *testing.T, fn func() (bool, error)) {
	t.Helper()
	prev := failClosedBootHasPinnedXDPLinks
	failClosedBootHasPinnedXDPLinks = fn
	t.Cleanup(func() { failClosedBootHasPinnedXDPLinks = prev })
}

// withFailClosedBootArmedProbe overrides the authoritative live-forwarding
// probe (control-socket Enabled && ForwardingArmed). The default probe dials a
// real unix socket that does not exist in the test sandbox, so every test that
// reaches stage 2 MUST set this seam to make the decision deterministic.
func withFailClosedBootArmedProbe(t *testing.T, fn func() (bool, error)) {
	t.Helper()
	prev := failClosedBootForwardingArmed
	failClosedBootForwardingArmed = fn
	t.Cleanup(func() { failClosedBootForwardingArmed = prev })
}

// TestColdBootCompileFailedClearsFRR proves the #1993 fix: on a compile-failure
// cold boot (configCompileFailed=true), the daemon strips the last-good
// xpf-managed section from frr.conf and reloads FRR exactly once, so peers fail
// over to the HA partner instead of routing transit into this unarmed node.
//
// Non-tautological: without the clearFRRForFailClosedBoot call wired into the
// boot path the managed section survives, so this test fails on the unpatched
// tree.
func TestColdBootCompileFailedClearsFRR(t *testing.T) {
	withFailClosedBootPinnedXDPProbe(t, func() (bool, error) { return false, nil })
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{} // healthy reload (nil error)
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	d.clearFRRForFailClosedBoot(true)

	got := readConf(t, confPath)
	if strings.Contains(got, sentinel) {
		t.Fatalf("compile-failed cold boot must strip the managed section; frr.conf still has %q:\n%s", sentinel, got)
	}
	begin, _ := frr.ManagedSectionMarkersForTest()
	if strings.Contains(got, begin) {
		t.Fatalf("managed begin marker must be gone after clear; frr.conf:\n%s", got)
	}
	if !strings.Contains(got, "log syslog informational") {
		t.Fatalf("operator content outside the managed section must survive the clear; frr.conf:\n%s", got)
	}
	if rec.ReloadCalls != 1 {
		t.Fatalf("expected exactly one FRR reload, got %d", rec.ReloadCalls)
	}
}

// TestColdBootNormalDoesNotClearFRR is the critical "don't wipe a healthy node"
// guard: on a normal / no-config bootstrap boot (configCompileFailed=false) the
// managed section must be UNTOUCHED and FRR must NOT be reloaded.
func TestColdBootNormalDoesNotClearFRR(t *testing.T) {
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{}
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	d.clearFRRForFailClosedBoot(false)

	got := readConf(t, confPath)
	if !strings.Contains(got, sentinel) {
		t.Fatalf("a normal boot must NOT touch the managed section; sentinel %q missing:\n%s", sentinel, got)
	}
	if rec.ReloadCalls != 0 {
		t.Fatalf("a normal boot must NOT reload FRR; got %d reloads", rec.ReloadCalls)
	}
}

// TestColdBootCompileFailedNilFRRIsSafe guards the NoDataplane / pre-manager
// path: clearing with a nil d.frr must not panic and must be a no-op.
func TestColdBootCompileFailedNilFRRIsSafe(t *testing.T) {
	withFailClosedBootPinnedXDPProbe(t, func() (bool, error) { return false, nil })
	d := &Daemon{} // d.frr == nil
	// Must not panic.
	d.clearFRRForFailClosedBoot(true)
}

// TestCompileFailedRestartWithLiveForwardingKeepsFRR is the genuine
// crash-survivor case: pins are present AND the helper control socket reports
// forwarding is live (Enabled && ForwardingArmed). Only then is the managed
// section preserved across the restart.
func TestCompileFailedRestartWithLiveForwardingKeepsFRR(t *testing.T) {
	withFailClosedBootPinnedXDPProbe(t, func() (bool, error) { return true, nil })
	withFailClosedBootArmedProbe(t, func() (bool, error) { return true, nil })
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{}
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	d.clearFRRForFailClosedBoot(true)

	got := readConf(t, confPath)
	if !strings.Contains(got, sentinel) {
		t.Fatalf("live forwarding must preserve the managed section on restart; sentinel %q missing:\n%s", sentinel, got)
	}
	if rec.ReloadCalls != 0 {
		t.Fatalf("live forwarding must suppress FRR reloads; got %d reloads", rec.ReloadCalls)
	}
}

// TestCompileFailedRestartPinsPresentButNotArmedClearsFRR is the EXACT
// #1993-review gap the pin-only guard missed: on a GRACEFUL hitless shutdown the
// pinned XDP links are intentionally preserved while forwarding is STOPPED. A
// pin-only guard reads "pins exist" and wrongly PRESERVES FRR, recreating the
// blackhole. The armed probe (helper reachable but ForwardingArmed=false) is
// the authoritative signal: pins present + NOT armed MUST CLEAR.
//
// Non-tautological against the pin-only code: the pre-fix
// clearFRRForFailClosedBoot returns early on pinnedXDPLinks==true WITHOUT
// consulting any forwarding signal, so it would PRESERVE here and this test
// would FAIL. It only passes once the armed probe gates the preserve decision.
func TestCompileFailedRestartPinsPresentButNotArmedClearsFRR(t *testing.T) {
	withFailClosedBootPinnedXDPProbe(t, func() (bool, error) { return true, nil })
	withFailClosedBootArmedProbe(t, func() (bool, error) { return false, nil }) // helper up, not forwarding
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{}
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	d.clearFRRForFailClosedBoot(true)

	got := readConf(t, confPath)
	if strings.Contains(got, sentinel) {
		t.Fatalf("pins present but forwarding NOT armed must CLEAR the managed section "+
			"(graceful-stop false positive); frr.conf still has %q:\n%s", sentinel, got)
	}
	begin, _ := frr.ManagedSectionMarkersForTest()
	if strings.Contains(got, begin) {
		t.Fatalf("managed begin marker must be gone after clear; frr.conf:\n%s", got)
	}
	if rec.ReloadCalls != 1 {
		t.Fatalf("expected exactly one FRR reload, got %d", rec.ReloadCalls)
	}
}

// TestCompileFailedRestartPinsPresentArmedProbeUnreachableClearsFRR covers a
// crash-or-graceful case where the pins survive but the control socket is gone
// (probe error: socket missing / connect-refused / timeout). Fail toward
// clearing: an unknown helper means no live forwarding, so peers must fail over.
func TestCompileFailedRestartPinsPresentArmedProbeUnreachableClearsFRR(t *testing.T) {
	withFailClosedBootPinnedXDPProbe(t, func() (bool, error) { return true, nil })
	withFailClosedBootArmedProbe(t, func() (bool, error) {
		return false, errors.New("dial unix control.sock: connect: no such file or directory")
	})
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{}
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	d.clearFRRForFailClosedBoot(true)

	got := readConf(t, confPath)
	if strings.Contains(got, sentinel) {
		t.Fatalf("an unreachable armed probe must CLEAR (fail toward fail-over), not preserve; frr.conf still has %q:\n%s", sentinel, got)
	}
	if rec.ReloadCalls != 1 {
		t.Fatalf("expected exactly one FRR reload, got %d", rec.ReloadCalls)
	}
}

// TestCompileFailedPinProbeErrorFallsThroughToArmedProbe verifies a pin
// pre-filter error does NOT short-circuit to preserve (the old behavior). It is
// conservatively treated as "pins may exist" and the authoritative armed probe
// decides: armed → preserve.
func TestCompileFailedPinProbeErrorFallsThroughToArmedProbe(t *testing.T) {
	withFailClosedBootPinnedXDPProbe(t, func() (bool, error) {
		return false, errors.New("pin readdir failed")
	})
	withFailClosedBootArmedProbe(t, func() (bool, error) { return true, nil }) // forwarding live
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{}
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	d.clearFRRForFailClosedBoot(true)

	got := readConf(t, confPath)
	if !strings.Contains(got, sentinel) {
		t.Fatalf("pin-probe error + live forwarding must preserve via the armed probe; sentinel %q missing:\n%s", sentinel, got)
	}
	if rec.ReloadCalls != 0 {
		t.Fatalf("pin-probe error + live forwarding must suppress FRR reloads; got %d reloads", rec.ReloadCalls)
	}
}

// TestClearFRRReloadDegradedDoesNotAbortBoot proves a degraded reload
// (frr-reload.py unavailable → ErrFRRReloadDegraded) is tolerated: the on-disk
// managed section is still stripped (Clear writes before it reloads) and the
// helper returns normally so boot proceeds. The on-disk strip is what lets a
// later FRR restart converge even when the live reload degraded.
func TestClearFRRReloadDegradedDoesNotAbortBoot(t *testing.T) {
	withFailClosedBootPinnedXDPProbe(t, func() (bool, error) { return false, nil })
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{ReloadErr: frr.ErrFRRReloadDegraded}
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	// Returns normally (no panic / no propagated error path) even on degraded.
	d.clearFRRForFailClosedBoot(true)

	got := readConf(t, confPath)
	if strings.Contains(got, sentinel) {
		t.Fatalf("degraded reload must still strip the managed section on disk; frr.conf:\n%s", got)
	}
	if rec.ReloadCalls != 1 {
		t.Fatalf("expected one reload attempt on the degraded path, got %d", rec.ReloadCalls)
	}
}
