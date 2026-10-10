package frr

import (
	"context"
	"io"
	"strings"
)

// This file exposes a narrow, EXPORTED test seam so packages outside pkg/frr
// (notably pkg/daemon, which owns the boot path that calls Clear()) can drive a
// Manager against a temp frr.conf WITHOUT shelling out to vtysh/frr-reload.py.
// Production code never references these symbols; they exist only so the
// #1993 fail-closed-boot FRR-clear can be unit-tested at the daemon layer.

// RecordingExecutor is an exported frrExecutor double for cross-package tests.
// It records FrrReloadPy invocations and returns a programmable error so a test
// can simulate a healthy reload (nil) or a degraded one (ErrFRRReloadDegraded)
// without running any external process. It is NOT safe for concurrent use
// beyond the single reload commitManagedSection performs synchronously under
// reloadMu (Clear's only call site).
type RecordingExecutor struct {
	// ReloadErr is returned by FrrReloadPy on every call.
	ReloadErr error
	// ReloadCalls counts FrrReloadPy invocations.
	ReloadCalls int
	// LastConf is the conf path of the most recent FrrReloadPy call.
	LastConf string
}

func (r *RecordingExecutor) Vtysh(context.Context, string) (string, error) { return "", nil }

func (r *RecordingExecutor) FrrReloadPy(_ context.Context, conf string) error {
	r.ReloadCalls++
	r.LastConf = conf
	return r.ReloadErr
}

func (r *RecordingExecutor) VtyshLoad(_ context.Context, conf string) ([]byte, error) {
	// The degraded fallback path; the daemon-layer test does not assert on it,
	// but it must not shell out, so return a benign success.
	return nil, nil
}

func (r *RecordingExecutor) VtyshLoadDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}
func (r *RecordingExecutor) VtyshDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func (r *RecordingExecutor) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	// The daemon-layer test does not exercise streaming reads; return an empty
	// stream so nothing shells out.
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

// ManagedSectionMarkersForTest returns the begin/end markers that bracket the
// xpf-managed section in frr.conf, so cross-package tests can seed a realistic
// frr.conf and assert the section was stripped without hardcoding the marker
// text (which is an on-disk contract owned by this package).
func ManagedSectionMarkersForTest() (begin, end string) {
	return markerBegin, markerEnd
}

// NewForTest constructs a Manager that writes/reads frr.conf at confPath and
// routes every reload through exec instead of the real frr-reload.py. The
// degraded-retry loop is DISABLED so the test does not spawn a background
// goroutine. Pass a *RecordingExecutor to observe reload calls.
//
// This mirrors how same-package tests build `&Manager{frrConf: ..., exec: ...}`
// directly, but keeps the unexported fields private while still letting the
// daemon package exercise the real Clear() → writeManagedSection → reload
// wiring against a temp file.
func NewForTest(confPath string, exec frrExecutor) *Manager {
	m := New()
	m.frrConf = confPath
	if exec != nil {
		m.exec = exec
	}
	m.DisableDegradedRetry()
	return m
}
