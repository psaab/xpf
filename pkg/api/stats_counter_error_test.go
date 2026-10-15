// #3345: a global-counter read failure must be surfaced, not reported as a
// clean 0. REST returns 500; the Prometheus collector SKIPS the affected
// sample (rather than emitting 0) and bumps xpf_counter_read_errors_total.
//
// #3462: collectGlobalCounters no longer EMITS xpf_counter_read_errors_total
// itself — Collect emits it last via emitCounterReadErrors, after all
// sub-collectors that can bump it. This test mirrors that order
// (collectGlobalCounters then emitCounterReadErrors).
//
// FAIL-ON-REVERT: restoring `v, _ := dp.ReadGlobalCounter(idx)` in
// globalStatsHandler / collectGlobalCounters makes REST return 200 with a
// zero body and Prometheus emit the per-counter families as 0 with the error
// total stuck at 0 — both want-assertions below go RED.
package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/dataplane"
)

// counterErrAPIDP is a loaded apiRuntimeDataPlane whose global-counter reads
// always fail, modeling a degraded counter bridge / userspace shim.
type counterErrAPIDP struct {
	*dataplane.Manager
}

func (d *counterErrAPIDP) IsLoaded() bool { return true }

func (d *counterErrAPIDP) ReadGlobalCounter(uint32) (uint64, error) {
	return 0, errors.New("counter bridge degraded")
}

func TestGlobalStatsHandlerSurfacesReadError(t *testing.T) {
	s := &Server{dp: &counterErrAPIDP{Manager: dataplane.New()}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/stats/global", nil)
	s.globalStatsHandler(rr, req)

	// Assert exactly 500 so a future regression to 200/400/503 is caught
	// (a read error must surface as an internal failure, not a clean zero).
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("globalStatsHandler status = %d, want %d (read error must not "+
			"look like a clean zero). body=%s",
			rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

func TestCollectGlobalCountersSkipsAndCountsReadErrors(t *testing.T) {
	c := newCollector(&Server{})
	dp := &counterErrAPIDP{Manager: dataplane.New()}

	ch := make(chan prometheus.Metric, 64)
	c.collectGlobalCounters(ch, dp)
	// #3462: the error-total sample is emitted by emitCounterReadErrors (called
	// last in Collect), not by collectGlobalCounters. Mirror that order here.
	c.emitCounterReadErrors(ch)
	close(ch)

	var perCounterEmitted int
	var errTotal float64
	var sawErrTotal bool
	for m := range ch {
		desc := m.Desc().String()
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		if strings.Contains(desc, "xpf_counter_read_errors_total") {
			sawErrTotal = true
			errTotal = pb.GetCounter().GetValue()
			continue
		}
		// Any non-error per-counter sample emitted on an all-failing DP would
		// be a misleading 0 — that is exactly the bug.
		perCounterEmitted++
	}

	if perCounterEmitted != 0 {
		t.Errorf("collectGlobalCounters emitted %d per-counter samples on an "+
			"all-failing DP; want 0 (must not report 0 on read error)", perCounterEmitted)
	}
	if !sawErrTotal {
		t.Fatal("xpf_counter_read_errors_total was not emitted")
	}
	if errTotal <= 0 {
		t.Errorf("xpf_counter_read_errors_total = %v, want > 0", errTotal)
	}
}

type globalCounterUnsupportedDP13274 struct {
	*dataplane.Manager
}

func (d *globalCounterUnsupportedDP13274) IsLoaded() bool { return true }

func (d *globalCounterUnsupportedDP13274) ReadGlobalCounter(idx uint32) (uint64, error) {
	switch idx {
	case dataplane.GlobalCtrFlowCacheFlush, dataplane.GlobalCtrFlowCacheInvalidate,
		dataplane.GlobalCtrTCEgressPackets, dataplane.GlobalCtrFabricRedirect:
		return 0, dataplane.ErrCounterNotPopulated
	default:
		return uint64(idx) + 1, nil
	}
}

func TestCollectGlobalCountersUnsupportedIsNotReadFailure13274(t *testing.T) {
	c := newCollector(&Server{})
	dp := &globalCounterUnsupportedDP13274{Manager: dataplane.New()}
	ch := make(chan prometheus.Metric, 64)
	c.collectGlobalCounters(ch, dp)
	c.emitCounterReadErrors(ch)
	close(ch)

	var errorTotal float64
	var sawErrorTotal, sawFlowHit, sawFlowMiss, sawFlowFlush, sawFlowInvalidate, sawTCEgress bool
	for m := range ch {
		desc := m.Desc().String()
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		if strings.Contains(desc, "xpf_counter_read_errors_total") {
			sawErrorTotal = true
			errorTotal = pb.GetCounter().GetValue()
			continue
		}
		if strings.Contains(desc, "xpf_tc_egress_packets_total") {
			sawTCEgress = true
		}
		if strings.Contains(desc, "xpf_flow_cache_total") {
			for _, label := range pb.GetLabel() {
				if label.GetName() == "type" {
					switch label.GetValue() {
					case "hit":
						sawFlowHit = true
					case "miss":
						sawFlowMiss = true
					case "flush":
						sawFlowFlush = true
					case "invalidate":
						sawFlowInvalidate = true
					}
				}
			}
		}
	}
	if !sawErrorTotal || errorTotal != 0 {
		t.Errorf("error total emitted=%v value=%v, want present and zero", sawErrorTotal, errorTotal)
	}
	if !sawFlowHit || !sawFlowMiss {
		t.Errorf("supported flow-cache series hit/miss present = %v/%v, want both", sawFlowHit, sawFlowMiss)
	}
	if sawFlowFlush || sawFlowInvalidate || sawTCEgress {
		t.Errorf("unsupported series flush/invalidate/TC-egress present = %v/%v/%v, want omitted",
			sawFlowFlush, sawFlowInvalidate, sawTCEgress)
	}
	if got := c.counterReadErrors.Load(); got != 0 {
		t.Errorf("counterReadErrors = %d for unsupported reads, want 0", got)
	}
}
