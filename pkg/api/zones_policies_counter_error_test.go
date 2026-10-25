// #3408: per-zone / per-policy counter read failures must be surfaced, not
// reported as clean zeros — the same contract as the global counters (#3345).
// REST returns HTTP 500; the Prometheus collector SKIPS the affected sample
// and bumps xpf_counter_read_errors_total.
//
// FAIL-ON-REVERT: restoring the `err == nil` swallow (dropping the readErr
// capture / the counterReadErrors bump) makes REST return 200 with clean-zero
// counts and the collector emit policy samples without an error count — the
// want-assertions below go RED.
package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
)

// policyZoneErrAPIDP is a loaded apiRuntimeDataPlane whose per-zone and
// per-policy counter reads fail. It supplies a LastApplyResult so the zone
// handler reaches the read (zone IDs must resolve).
type policyZoneErrAPIDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *policyZoneErrAPIDP) IsLoaded() bool { return true }

func (d *policyZoneErrAPIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }

func (d *policyZoneErrAPIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

func (d *policyZoneErrAPIDP) ReadZoneCounters(uint32, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

func TestPoliciesHandlerSurfacesReadError(t *testing.T) {
	s := &Server{
		store: newDescriptorCoverageStore(t),
		dp:    &policyZoneErrAPIDP{Manager: dataplane.New()},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/policies", nil)
	s.policiesHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("policiesHandler status = %d, want %d on policy counter read failure. body=%s",
			rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

func TestZonesHandlerSurfacesReadError(t *testing.T) {
	s := &Server{
		store: newDescriptorCoverageStore(t),
		dp: &policyZoneErrAPIDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1, "untrust": 2}},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/zones", nil)
	s.zonesHandler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("zonesHandler status = %d, want %d on zone counter read failure. body=%s",
			rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
}

func TestCollectPolicyCountersCountsReadErrors(t *testing.T) {
	srv := &Server{store: newDescriptorCoverageStore(t)}
	c := newCollector(srv)
	dp := &policyZoneErrAPIDP{Manager: dataplane.New()}

	ch := make(chan prometheus.Metric, 64)
	c.collectPolicyCounters(ch, dp)
	close(ch)

	var policyEmitted int
	for m := range ch {
		// #7016: EXTRACT the fqName rather than substring-matching
		// Desc.String(), which embeds the HELP text -- the
		// xpf_policy_counters_unpublished_rules gauge collectPolicyCounters now
		// emits on every path cross-references xpf_policy_hits_total in its
		// HELP, so a Contains match counted it as a policy sample.
		if descFQName(m.Desc().String()) == "xpf_policy_hits_total" {
			policyEmitted++
		}
	}
	if policyEmitted != 0 {
		t.Errorf("collectPolicyCounters emitted %d policy samples on an all-failing DP; want 0", policyEmitted)
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("counterReadErrors not bumped on a per-policy read failure")
	}
}

// filterErrAPIDP fails the filter reads. cfgErr selects whether the
// ReadFilterConfig (gate) or ReadFilterCounters (per-term) read fails.
type filterErrAPIDP struct {
	*dataplane.Manager
	apply  *dataplane.ApplyResult
	cfgErr bool
}

func (d *filterErrAPIDP) IsLoaded() bool                          { return true }
func (d *filterErrAPIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *filterErrAPIDP) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	if d.cfgErr {
		return dataplane.FilterConfig{}, errors.New("counter bridge degraded")
	}
	return dataplane.FilterConfig{RuleStart: 0}, nil
}
func (d *filterErrAPIDP) ReadFilterCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

func filterApplyResult() *dataplane.ApplyResult {
	return &dataplane.ApplyResult{FilterIDs: map[string]uint32{"inet:fin": 0, "inet6:fin6": 100}}
}

func countFilterSamples(t *testing.T, c *xpfCollector, dp apiRuntimeDataPlane) int {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	c.collectFilterCounters(ch, dp, fetchUserspaceStatus(dp))
	close(ch)
	var n int
	for m := range ch {
		if strings.Contains(m.Desc().String(), "xpf_filter_hits_total") {
			n++
		}
	}
	return n
}

// MAJOR pin: on a ReadFilterCounters failure the collector must SKIP the
// xpf_filter_hits_total sample (a missing sample, not a stale 0) AND bump
// counterReadErrors — matching the zone/policy collectors.
// FAIL-ON-REVERT: dropping the `if termFailed { continue }` makes the sample
// emit and `emitted != 0` goes RED.
func TestCollectFilterCountersSkipsSampleOnCounterReadError(t *testing.T) {
	c := newCollector(&Server{store: newDescriptorCoverageStore(t)})
	dp := &filterErrAPIDP{Manager: dataplane.New(), apply: filterApplyResult()}

	emitted := countFilterSamples(t, c, dp)
	if emitted != 0 {
		t.Errorf("collectFilterCounters emitted %d filter samples on ReadFilterCounters failure; want 0 (skip on error)", emitted)
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("counterReadErrors not bumped on a filter counter read failure")
	}
}

func TestCollectFilterCountersSkipsSampleOnConfigReadError(t *testing.T) {
	c := newCollector(&Server{store: newDescriptorCoverageStore(t)})
	dp := &filterErrAPIDP{Manager: dataplane.New(), apply: filterApplyResult(), cfgErr: true}

	emitted := countFilterSamples(t, c, dp)
	if emitted != 0 {
		t.Errorf("collectFilterCounters emitted %d filter samples on ReadFilterConfig failure; want 0", emitted)
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("counterReadErrors not bumped on a filter config read failure")
	}
}

// #3643 removed TestCollectZoneCountersCountsReadErrors along with the
// collectZoneCounters collector: per-zone traffic metrics had no writer in the
// userspace era, and every stable-hash zone id >= MaxZones read OOB'd the dense
// BPF array, bumping xpf_counter_read_errors_total once per zone per scrape --
// a permanent FALSE alert.
//
// #3651 shipped the populate path and restored the collector, so the per-zone
// read-error contract is under test again -- in zone_counters_metrics_test.go
// rather than here, since it now needs the populated/unpopulated/failed
// three-way disposition rather than a single error case:
// TestCollectZoneCountersBumpsOnGenuineReadError (a genuine failure still
// skip-and-bumps, #3345/#3408), TestCollectZoneCountersOmitsUnpopulated
// RatherThanPublishingZero (ErrCounterNotPopulated must NOT bump -- that is the
// #3643 false alert), and TestCollectDoesNotFalseAlertOnZoneReads (the same
// guarantee at whole-Collect level, where the storm manifested).
