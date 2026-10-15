// #3464: a per-interface counter-read failure must be surfaced with a uniform
// degraded/unavailable signal across the REST surfaces and Prometheus, not
// handled divergently (one API drops the row, another shows a misleading clean
// 0, Prometheus silently omits the sample with no error metric). An operator
// must be able to tell "interface idle" (real 0) from "counter bridge
// unavailable" (read failed).
//
// Contract:
//   - REST /stats/interfaces (ifaceStatsHandler): KEEP the row with
//     InterfaceStats.Unavailable=true instead of dropping it (the old
//     `continue` made the interface vanish).
//   - REST /interfaces (interfacesHandler): KEEP the row, set Unavailable=true
//     instead of leaving a clean 0.
//   - Prometheus (collectInterfaceCounters): SKIP the per-interface sample (no
//     misleading 0) AND bump xpf_interface_counter_read_errors_total.
//
// FAIL-ON-REVERT:
//   - Restoring the `continue` in ifaceStatsHandler drops the lo row entirely,
//     so no row carries Unavailable=true -> the stats assertion goes RED.
//   - Dropping the interfacesHandler `else { is.Unavailable = true }` leaves the
//     resolved row at Unavailable=false -> the inventory assertion goes RED.
//   - Dropping the collectInterfaceCounters bump leaves
//     xpf_interface_counter_read_errors_total stuck at 0 -> the collector
//     assertion goes RED.
package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"

	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/dataplane"
)

// ifaceCounterErrAPIDP is a loaded apiRuntimeDataPlane whose per-interface
// counter reads always fail, modeling a degraded counter bridge / userspace
// shim. Other reads embed the real (empty) Manager.
type ifaceCounterErrAPIDP struct {
	*dataplane.Manager
}

func (d *ifaceCounterErrAPIDP) IsLoaded() bool { return true }

func (d *ifaceCounterErrAPIDP) ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error) {
	return dataplane.InterfaceCounterValue{}, errors.New("counter bridge degraded")
}

// requireLoopback skips the test when the loopback ("lo") cannot be resolved
// (a restricted sandbox may deny the netlink lookup). The descriptor-coverage
// store binds lo.0, and ResolveKernelIfName("lo.0")=="lo", so the read path is
// only reached where loopback resolves — same posture as
// TestCollectorDescriptorCoverage.
func requireLoopback(t *testing.T) {
	t.Helper()
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("net.InterfaceByName(\"lo\") unavailable in this environment (%v)", err)
	}
}

func decodeInterfaceStats(t *testing.T, body []byte) []InterfaceStats {
	t.Helper()
	var resp struct {
		Success bool             `json:"success"`
		Data    []InterfaceStats `json:"data"`
		Error   string           `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, body)
	}
	if !resp.Success {
		t.Fatalf("response success=false, error=%q", resp.Error)
	}
	return resp.Data
}

func TestIfaceStatsHandlerKeepsRowWithUnavailableOnReadError(t *testing.T) {
	requireLoopback(t)
	s := &Server{
		store: newDescriptorCoverageStore(t),
		dp:    &ifaceCounterErrAPIDP{Manager: dataplane.New()},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/stats/interfaces", nil)
	s.ifaceStatsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("ifaceStatsHandler status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	rows := decodeInterfaceStats(t, rr.Body.Bytes())

	var degraded *InterfaceStats
	for i := range rows {
		if rows[i].Ifindex > 0 && rows[i].Unavailable {
			degraded = &rows[i]
			break
		}
	}
	if degraded == nil {
		t.Fatalf("no interface row carried Unavailable=true on a counter read failure "+
			"— the row must be KEPT with a degraded marker, not dropped (#3464). rows=%+v", rows)
	}
	// Counters must stay 0 (not authoritative under Unavailable), and the row
	// must not have leaked stale data.
	if degraded.RxPackets != 0 || degraded.TxPackets != 0 || degraded.RxBytes != 0 || degraded.TxBytes != 0 {
		t.Errorf("unavailable row carried nonzero counters %+v; want all 0", *degraded)
	}
}

func TestInterfacesHandlerFlagsUnavailableOnReadError(t *testing.T) {
	requireLoopback(t)
	s := &Server{
		store: newDescriptorCoverageStore(t),
		dp:    &ifaceCounterErrAPIDP{Manager: dataplane.New()},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/interfaces", nil)
	s.interfacesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("interfacesHandler status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	rows := decodeInterfaceStats(t, rr.Body.Bytes())

	// The resolved interface row (lo, Ifindex>0) must be flagged Unavailable;
	// a clean 0 would be indistinguishable from a real idle interface.
	var sawResolved bool
	for _, r := range rows {
		if r.Ifindex > 0 {
			sawResolved = true
			if !r.Unavailable {
				t.Errorf("resolved interface %q reported counters as a clean 0 on a read "+
					"failure (Unavailable=false) — must be flagged degraded (#3464). row=%+v", r.Name, r)
			}
		}
	}
	if !sawResolved {
		t.Fatalf("no resolved interface row present; fixture/loopback not wired. rows=%+v", rows)
	}
}

func TestCollectInterfaceCountersSkipsAndCountsReadErrors(t *testing.T) {
	requireLoopback(t)
	srv := &Server{store: newDescriptorCoverageStore(t)}
	c := newCollector(srv)
	dp := &ifaceCounterErrAPIDP{Manager: dataplane.New()}

	ch := make(chan prometheus.Metric, 64)
	c.collectInterfaceCounters(ch, dp)
	// #3464: the error-total sample is emitted by emitInterfaceCounterReadErrors
	// (called after collectInterfaceCounters in Collect). Mirror that order.
	c.emitInterfaceCounterReadErrors(ch)
	close(ch)

	var perInterfaceEmitted int
	var errTotal float64
	var sawErrTotal bool
	for m := range ch {
		desc := m.Desc().String()
		var pbm dto.Metric
		if err := m.Write(&pbm); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		if strings.Contains(desc, "xpf_interface_counter_read_errors_total") {
			sawErrTotal = true
			errTotal = pbm.GetCounter().GetValue()
			continue
		}
		// Any xpf_interface_{packets,bytes}_total sample emitted on an
		// all-failing DP would be a misleading 0 — that is the bug.
		if strings.Contains(desc, "xpf_interface_") {
			perInterfaceEmitted++
		}
	}

	if perInterfaceEmitted != 0 {
		t.Errorf("collectInterfaceCounters emitted %d per-interface samples on an "+
			"all-failing DP; want 0 (skip, not a misleading 0)", perInterfaceEmitted)
	}
	if !sawErrTotal {
		t.Fatal("xpf_interface_counter_read_errors_total was not emitted")
	}
	if errTotal <= 0 {
		t.Errorf("xpf_interface_counter_read_errors_total = %v, want > 0 (a read failure "+
			"must bump the interface scrape-error counter)", errTotal)
	}
}
func TestCollectInterfaceCountersMissingLinkCountsReadError13273(t *testing.T) {
	const missingIfName = "ge-13273-absent"
	if _, err := net.InterfaceByName(missingIfName); err == nil {
		t.Fatalf("test precondition: %q unexpectedly exists", missingIfName)
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet("set interfaces " + missingIfName + " unit 0 family inet"); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	c := newCollector(&Server{store: store})
	ch := make(chan prometheus.Metric, 8)
	c.collectInterfaceCounters(ch, &ifaceCounterErrAPIDP{Manager: dataplane.New()})
	c.emitInterfaceCounterReadErrors(ch)
	close(ch)

	var errorTotal float64
	for metric := range ch {
		if !strings.Contains(metric.Desc().String(), "xpf_interface_counter_read_errors_total") {
			continue
		}
		var pbm dto.Metric
		if err := metric.Write(&pbm); err != nil {
			t.Fatalf("metric.Write(): %v", err)
		}
		errorTotal = pbm.GetCounter().GetValue()
	}
	if errorTotal != 1 {
		t.Fatalf("xpf_interface_counter_read_errors_total = %v for missing netdev, want 1", errorTotal)
	}
}
