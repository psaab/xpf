package api

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #5045: the xpf_counter_read_errors_total scrape-error sample must be emitted
// on EVERY return path of Collect so the #3345/#3462 omit-plus-error contract
// (a series OMITTED because its read failed => the SAME scrape MUST carry the
// error signal) holds even in a config-only / degraded boot. Before the fix the
// only emit site sat AFTER the `dp == nil || !dp.IsLoaded()` early return, while
// the pre-gate host-inbound / lo0 collectors bump counterReadErrors on an nft
// read failure BEFORE that gate — so an unloaded-dataplane scrape with a failing
// pre-gate read carried NEITHER the data series NOR the error sample. The fix
// establishes `defer c.emitCounterReadErrors(ch)` at the top of Collect, so the
// sample is emitted exactly once at function exit on every path.

// stubPreGateNftReads points all four pre-gate kernel-nftables read package
// vars at controllable fakes and returns a restore func. The deny read fails
// iff denyFails; the other three always succeed with an empty result (so they
// never bump counterReadErrors in the sandbox, where the real netlink reads
// would otherwise fail non-deterministically).
func stubPreGateNftReads(t *testing.T, denyFails bool) func() {
	t.Helper()
	origDeny := readHostInboundDenyCounters
	origJunos := readHostInboundJunosHostDenyCounters
	origLo0 := readLo0Counters
	origAccept := readHostInboundAcceptCounters

	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, xnft.HostInboundTableState, error) {
		if denyFails {
			return nil, xnft.HostInboundTableAbsent, errors.New("netlink dial: permission denied")
		}
		// Table ABSENT (#5719): a clean, error-free empty read that must NOT bump
		// counterReadErrors — the deny read is the variable under test here.
		return nil, xnft.HostInboundTableAbsent, nil
	}
	readHostInboundJunosHostDenyCounters = func() ([]xnft.HostInboundJunosHostDenyCount, error) {
		return nil, nil
	}
	readLo0Counters = func() ([]xnft.Lo0Count, error) { return nil, nil }
	readHostInboundAcceptCounters = func() ([]xnft.HostInboundAcceptCount, error) { return nil, nil }

	return func() {
		readHostInboundDenyCounters = origDeny
		readHostInboundJunosHostDenyCounters = origJunos
		readLo0Counters = origLo0
		readHostInboundAcceptCounters = origAccept
	}
}

// gatherErrTotal runs the collector through a PEDANTIC registry and returns the
// error-total value, the number of samples in the xpf_counter_read_errors_total
// family (exactly-once guard — a true double-emit of the same name+labels makes
// pedantic Gather() hard-error, which t.Fatal's here), and whether the
// kernel-deny series was emitted. Matches on the exact metric-family NAME (not a
// substring of Desc.String()) so the xpf_INTERFACE_counter_read_errors_total
// family — whose help text references this metric — is not miscounted.
func gatherErrTotal(t *testing.T, s *Server) (errTotal float64, errTotalCount int, sawDenySeries bool) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		switch mf.GetName() {
		case "xpf_counter_read_errors_total":
			errTotalCount = len(mf.GetMetric())
			for _, m := range mf.GetMetric() {
				errTotal = m.GetCounter().GetValue()
			}
		case "xpf_host_inbound_kernel_denies_total":
			sawDenySeries = true
		}
	}
	return errTotal, errTotalCount, sawDenySeries
}

// TestCounterReadErrorsEmittedWhenDataplaneUnloaded is the #5045 RED-on-revert
// proof. With the dataplane UNLOADED (dp == nil, config-only / degraded boot)
// AND a pre-gate nft read that FAILS, the scrape must still carry
// xpf_counter_read_errors_total (with the bumped value) even though the failed
// series is omitted — the omit-plus-error contract holds on the early-return
// path.
//
// FAIL-ON-REVERT: move the emit back below the `dp == nil || !dp.IsLoaded()`
// gate (drop the top-of-Collect defer, restore the post-gate explicit call) and
// Collect returns before emitting, so xpf_counter_read_errors_total is ABSENT
// and sawErrTotal goes false (RED).
func TestCounterReadErrorsEmittedWhenDataplaneUnloaded(t *testing.T) {
	defer stubPreGateNftReads(t, true)() // deny read fails -> bump + skip series

	s := &Server{} // dp intentionally nil — degraded / config-only boot.
	errTotal, errTotalCount, sawDenySeries := gatherErrTotal(t, s)

	if errTotalCount == 0 {
		t.Fatal("xpf_counter_read_errors_total ABSENT on an unloaded-dataplane " +
			"scrape with a failed pre-gate nft read — the omit-plus-error " +
			"contract is violated on the early-return path (#5045). The emit " +
			"must run on EVERY return path, not only the loaded path.")
	}
	if errTotal < 1 {
		t.Errorf("xpf_counter_read_errors_total = %v, want >= 1 (the failed "+
			"pre-gate read must bump it and the bump must show THIS scrape)", errTotal)
	}
	if sawDenySeries {
		t.Error("xpf_host_inbound_kernel_denies_total present despite a read " +
			"failure — it must be OMITTED (#3345), so this scrape carries the " +
			"error signal in its place, not the data series")
	}
}

// TestCounterReadErrorsEmittedZeroWhenCleanUnloaded pins the healthy-unloaded
// behavior: with NO read errors and the dataplane unloaded, the scrape still
// carries xpf_counter_read_errors_total at 0 (the #3345 "always emitted, 0 when
// healthy" property, now honored on the early-return path too), and no error
// series is spuriously present.
func TestCounterReadErrorsEmittedZeroWhenCleanUnloaded(t *testing.T) {
	defer stubPreGateNftReads(t, false)() // all pre-gate reads succeed (empty)

	s := &Server{} // dp nil.
	errTotal, errTotalCount, sawDenySeries := gatherErrTotal(t, s)

	if errTotalCount == 0 {
		t.Fatal("xpf_counter_read_errors_total absent on a clean unloaded scrape " +
			"— it must always be emitted (0 when healthy) for alerting (#3345)")
	}
	if errTotal != 0 {
		t.Errorf("xpf_counter_read_errors_total = %v on a clean scrape, want 0", errTotal)
	}
	if sawDenySeries {
		t.Error("kernel-deny series present with an empty read result — want absent")
	}
}

// TestCounterReadErrorsEmittedExactlyOnceOnLoadedPath guards the loaded path
// against a double-emit regression from the deferred-emit restructure. A full
// Collect() on a LOADED dataplane with a failing pre-gate read must emit
// xpf_counter_read_errors_total EXACTLY ONCE (the defer replaced — did not
// duplicate — the former explicit post-gate call), and still reflect the bump.
//
// FAIL-ON-REVERT: reintroducing an explicit c.emitCounterReadErrors(ch) call in
// addition to the top-of-Collect defer emits the same name+labels twice, which
// makes the PEDANTIC registry Gather() hard-error ("collected metric ... was
// collected before with the same name and label values") — t.Fatal in the
// helper — so the test goes RED.
func TestCounterReadErrorsEmittedExactlyOnceOnLoadedPath(t *testing.T) {
	defer stubPreGateNftReads(t, true)() // deny read fails -> one bump on the pre-gate path

	store := newDescriptorCoverageStore(t)
	srv := &Server{
		store:     store,
		startTime: time.Now(),
	}
	srv.dp = &descriptorCoverageDP{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{
			ZoneIDs:   map[string]uint32{"trust": 1, "untrust": 2},
			FilterIDs: map[string]uint32{"inet:fin": 0, "inet6:fin6": 100},
		},
	}

	errTotal, errTotalCount, _ := gatherErrTotal(t, srv)

	if errTotalCount != 1 {
		t.Fatalf("xpf_counter_read_errors_total emitted %d times in one loaded-path "+
			"scrape; want exactly 1 (the deferred emit must REPLACE, not duplicate, "+
			"the former post-gate call) (#5045)", errTotalCount)
	}
	if errTotal < 1 {
		t.Errorf("xpf_counter_read_errors_total = %v on the loaded path with a failed "+
			"pre-gate read, want >= 1 (the bump must be reflected this scrape)", errTotal)
	}
}
