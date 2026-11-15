package frr

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
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
	// TestErr, when non-nil, is returned by FrrReloadPyTest (#15203 re-check).
	TestErr error
	// TestCalls counts FrrReloadPyTest invocations.
	TestCalls int

	// ConfigBatches records every non-empty VtyshConfigLines batch (the
	// #19083 static-NHT rebind and restore); ConfigBatchErr fails them. When
	// ConfigBatchGate is non-nil a batch waits for it before returning, so a
	// cell can hold a re-evaluation in flight. Guarded by mu: the #19083
	// re-evaluation runs on its own goroutine. Read with ConfigBatchesSnapshot.
	mu              sync.Mutex
	ConfigBatches   [][]string
	ConfigBatchErr  error
	ConfigBatchGate chan struct{}
	// nhtV4/nhtV6 model zebra's static NHT binding per family (guarded by
	// mu; "" = none): binding lines in a batch set them, a successful reload
	// converges them to frr.conf, and `show ip|ipv6 nht route-map` reports
	// them, so the #19083 binding restore sees a readable zebra.
	nhtV4, nhtV6 string
}

// applyNHTBindingLocked models one `ip|ipv6 nht static route-map NAME` line.
// Caller holds r.mu.
func (r *RecordingExecutor) applyNHTBindingLocked(line string) {
	switch {
	case strings.HasPrefix(line, "ip nht static route-map "):
		r.nhtV4 = strings.TrimPrefix(line, "ip nht static route-map ")
	case strings.HasPrefix(line, "ipv6 nht static route-map "):
		r.nhtV6 = strings.TrimPrefix(line, "ipv6 nht static route-map ")
	}
}

// VtyshConfigLines records a configuration batch.
func (r *RecordingExecutor) VtyshConfigLines(_ context.Context, lines []string) ([]byte, error) {
	if len(lines) == 0 {
		return nil, nil
	}
	r.mu.Lock()
	r.ConfigBatches = append(r.ConfigBatches, append([]string(nil), lines...))
	err, gate := r.ConfigBatchErr, r.ConfigBatchGate
	if err == nil {
		for _, l := range lines {
			r.applyNHTBindingLocked(l)
		}
	}
	r.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return nil, err
}

// ConfigBatchesSnapshot returns a copy of the recorded configuration batches.
func (r *RecordingExecutor) ConfigBatchesSnapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]string(nil), r.ConfigBatches...)
}

// Vtysh answers `show ip|ipv6 nht route-map` from the modelled binding (the
// FRR 10.6.0 row layout) and every other command with "".
func (r *RecordingExecutor) Vtysh(_ context.Context, cmd string) (string, error) {
	if cmd != "show ip nht route-map" && cmd != "show ipv6 nht route-map" {
		return "", nil
	}
	r.mu.Lock()
	v := r.nhtV4
	if strings.HasPrefix(cmd, "show ipv6") {
		v = r.nhtV6
	}
	r.mu.Unlock()
	if v == "" {
		v = "none"
	}
	return "VRF: default\nProtocol                  : route-map\n-------------------------------------\n" +
		"static                    : " + v + "\n", nil
}

func (r *RecordingExecutor) FrrReloadPy(_ context.Context, conf string) error {
	r.ReloadCalls++
	r.LastConf = conf
	if r.ReloadErr == nil {
		// A converged reload leaves zebra's static NHT binding as frr.conf
		// renders it.
		data, _ := os.ReadFile(conf)
		r.mu.Lock()
		r.nhtV4, r.nhtV6 = "", ""
		for _, l := range strings.Split(string(data), "\n") {
			r.applyNHTBindingLocked(strings.TrimSpace(l))
		}
		r.mu.Unlock()
	}
	return r.ReloadErr
}

func (r *RecordingExecutor) FrrReloadPyTest(_ context.Context, conf string) error {
	r.TestCalls++
	r.LastConf = conf
	if r.TestErr != nil {
		return r.TestErr
	}
	// Default: a diff remains, so the re-check never certifies a reload
	// this double was not told converged (#15203 fail-closed default).
	return errors.New("frr-reload.py --test: diff remains")
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

// SetFRRGroupResolverForTest replaces the frr-group resolver (the seam
// planFRRWrite consults exactly once per frr.conf write, #16046) and
// returns a restore func. It lets cross-package tests (daemon boot
// paths writing through NewForTest managers, factoryreset wipe) run
// deterministically without root or a host frr group: pass a resolver
// returning the test process's egid so seeded 0644 files tighten by
// pure preserve. Test-only; production never calls it, and it is not
// safe under t.Parallel (process-global seam).
func SetFRRGroupResolverForTest(fn func() (int, bool)) (restore func()) {
	prev := resolveFRRGroup
	resolveFRRGroup = fn
	return func() { resolveFRRGroup = prev }
}
