package userspace

import (
	"net/netip"
	"testing"
)

// #13300 (D5-11): manager-owned maps-sync failure telemetry must be
// observable on ProcessStatus so Prometheus can export it.
func TestMapsSyncTelemetryStampedOnStatus13300(t *testing.T) {
	m := New()
	m.mapsSyncTelemetry.rstSuppressionFailures.Store(3)
	m.mapsSyncTelemetry.bindingsWatchdogRepairs.Store(5)
	m.mapsSyncTelemetry.bindingsWatchdogErrors.Store(2)
	m.mapsSyncTelemetry.localAddrPruneSkipped.Store(7)
	m.lastRSTv4 = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	status := ProcessStatus{PID: 1}
	m.recordHelperStatusLocked(&status)
	if !status.RSTSuppressionDegraded {
		t.Fatal("RSTSuppressionDegraded = false, want true when last install failed")
	}
	if status.RSTSuppressionFailures != 3 || status.BindingsWatchdogRepairs != 5 ||
		status.BindingsWatchdogErrors != 2 || status.LocalAddrPruneSkipped != 7 {
		t.Fatalf("stamped telemetry = %+v, want 3/5/2/7", status)
	}
	// Complete install clears degraded.
	m.lastRSTInstallOK = true
	status2 := ProcessStatus{PID: 1}
	m.recordHelperStatusLocked(&status2)
	if status2.RSTSuppressionDegraded {
		t.Fatal("RSTSuppressionDegraded = true after successful install")
	}
}
