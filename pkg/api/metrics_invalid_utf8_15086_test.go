// #15086 (A44-01): a non-UTF-8 byte in a committed config identifier
// (here a policy rule named "web\xffallow", the probe spelling) reached
// prometheus.MustNewConstMetric as a label value. client_golang rejects
// invalid UTF-8 label values, Must* panics, and because Registry.Gather
// runs Collect in its own goroutine the panic killed the whole daemon on
// the next /metrics scrape — net/http recovery never applies.
//
// The fix has three legs, all pinned here:
//  1. Label values are sanitized at the single emit choke point
//     (emitConstMetric -> sanitizeMetricLabelValues): the bad sample is
//     still published, with U+FFFD standing in for the invalid byte, and
//     counted in xpf_metrics_invalid_label_values_total. Legitimate
//     values pass through byte-identical (control below).
//  2. metricsLane.Collect recovers any residual collector panic, counts
//     it in xpf_metrics_collector_panics_total, and returns the lane to
//     the pool, so a scrape fails instead of crashing the process.
//  3. The scrape after the incident still works (the lane was returned).
//
// FAIL-ON-REVERT: restoring MustNewConstMetric at the policy emit site
// (or dropping the sanitize) makes the direct-collect test panic inside
// collectPolicyCounters; dropping the lane recover makes the HTTP test
// crash the test process the same way the probe crashed the daemon.
package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// collectPolicyMetrics15086 drives collectPolicyCounters with one
// counter-eligible zone-pair rule carrying the given name and returns the
// emitted metrics plus the collector, so tests can inspect both the
// published series and the invalid-label counter.
func collectPolicyMetrics15086(t *testing.T, ruleName string) (*xpfCollector, []prometheus.Metric) {
	t.Helper()
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.PolicyStatsEnabled = true
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			{Name: ruleName, Action: config.PolicyPermit, Count: true},
		}},
	}
	cfg.Security.GlobalPolicies = nil
	dp := &schedulerCounterAPIDP{
		Manager: dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{
			policyCounterID(0, 0):             {Packets: 7, Bytes: 700},
			dataplane.DefaultPolicySentinelID: {Packets: 3, Bytes: 300},
		},
	}
	c := newCollector(&Server{store: store, dp: dp})
	ch := make(chan prometheus.Metric, 64)
	c.collectPolicyCounters(ch, dp)
	close(ch)
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}
	return c, got
}

func policyHitLabels15086(t *testing.T, got []prometheus.Metric) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, m := range got {
		if !strings.Contains(m.Desc().String(), "xpf_policy_hits_total") {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		labels := map[string]string{}
		for _, l := range pb.GetLabel() {
			if !utf8.ValidString(l.GetValue()) {
				t.Errorf("emitted label %q still holds invalid UTF-8 %q", l.GetName(), l.GetValue())
			}
			labels[l.GetName()] = l.GetValue()
		}
		out = append(out, labels)
	}
	return out
}

// The probe's exact mechanism: rule "web\xffallow" must not panic the
// collector; its sample is published with the invalid byte folded to
// U+FFFD and counted once in the invalid-label counter.
func TestCollectPolicyCountersInvalidUTF8RuleName15086(t *testing.T) {
	c, got := collectPolicyMetrics15086(t, "web\xffallow")

	hits := policyHitLabels15086(t, got)
	found := false
	for _, labels := range hits {
		if labels["rule"] == "web�allow" {
			found = true
		}
		if strings.Contains(labels["rule"], "\xff") {
			t.Errorf("raw invalid byte survived into labels: %v", labels)
		}
	}
	if !found {
		t.Errorf("no sanitized web�allow series in %v; the sample must be published sanitized, not dropped or panicking", hits)
	}
	if n := c.invalidLabelValues.Load(); n != 1 {
		t.Errorf("invalidLabelValues = %d, want 1 (one label value carried an invalid byte)", n)
	}
}

// CONTROL: a legitimate rule name passes through byte-identical and does
// not touch the invalid-label counter — sanitization must not rewrite
// healthy config.
func TestCollectPolicyCountersValidRuleNameUnchanged15086(t *testing.T) {
	c, got := collectPolicyMetrics15086(t, "web-allow")

	hits := policyHitLabels15086(t, got)
	found := false
	for _, labels := range hits {
		if labels["rule"] == "web-allow" {
			found = true
		}
	}
	if !found {
		t.Errorf("legitimate rule series missing from %v", hits)
	}
	if n := c.invalidLabelValues.Load(); n != 0 {
		t.Errorf("invalidLabelValues = %d, want 0 for a fully valid scrape", n)
	}
}

// End-to-end through the real HTTP handler and a real Registry.Gather
// (the goroutine that used to die): the bad-identifier scrape answers 200
// with the sanitized series, the panic counter stays 0 because nothing
// panicked, and a second scrape proves the lane returned to the pool.
func TestMetricsScrapeInvalidUTF8RuleName15086(t *testing.T) {
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.PolicyStatsEnabled = true
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			{Name: "web\xffallow", Action: config.PolicyPermit, Count: true},
		}},
	}
	cfg.Security.GlobalPolicies = nil
	dp := &schedulerCounterAPIDP{
		Manager: dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{
			policyCounterID(0, 0):             {Packets: 7, Bytes: 700},
			dataplane.DefaultPolicySentinelID: {Packets: 3, Bytes: 300},
		},
	}
	srv := &Server{store: store, dp: dp}
	collector := newCollector(srv)
	ts := httptest.NewServer(newMetricsHandler(collector, 5*time.Second))
	defer ts.Close()

	for scrape := 1; scrape <= 2; scrape++ {
		resp, err := ts.Client().Get(ts.URL)
		if err != nil {
			t.Fatalf("scrape %d: %v (pre-fix this connection dies with the process)", scrape, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("scrape %d: read body: %v", scrape, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("scrape %d: status = %d, want 200; body:\n%s", scrape, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "web�allow") {
			t.Errorf("scrape %d: sanitized series missing from body", scrape)
		}
		if strings.Contains(string(body), "web\xffallow") {
			t.Errorf("scrape %d: raw invalid byte in body", scrape)
		}
	}
	if n := collector.invalidLabelValues.Load(); n == 0 {
		t.Error("invalidLabelValues = 0 after two scrapes of a bad identifier, want > 0")
	}
}

// The recover leg, exercised directly: a collector with a nil srv but
// real descriptors panics deterministically inside collectContext (the
// pre-gate emit path dereferences c.srv.*Fn). Through the lane that must
// become a failed/empty scrape — Gather returns, the panic is counted,
// and the lane goes back to the pool so the NEXT scrape is admitted
// instead of 503ing forever. (A bare &xpfCollector{} cannot be used:
// newMetricsHandler registers the lane, and Describe on nil Descs
// panics at construction, before any scrape.)
func TestMetricsLaneCollectRecoversPanic15086(t *testing.T) {
	bad := newCollector(&Server{})
	bad.srv = nil // collectContext panics on the first c.srv.*Fn deref
	handler := newMetricsHandler(bad, 5*time.Second)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatalf("scrape of panicking collector: %v (Gather goroutine panic kills the process pre-fix)", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// promhttp answers 500 (no metrics gathered) or 200 with only the
	// deferred pre-gate samples; either is a failed scrape, never a crash.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 200 or 500", resp.StatusCode)
	}
	if n := bad.collectorPanics.Load(); n != 1 {
		t.Fatalf("collectorPanics = %d, want 1", n)
	}
	// Lane returned: a second scrape is admitted (not "too many
	// concurrent metric scrapes") and panics are counted again.
	resp2, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatalf("second scrape: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusServiceUnavailable {
		t.Fatal("second scrape got 503: the panicked lane was never returned to the pool")
	}
	if n := bad.collectorPanics.Load(); n != 2 {
		t.Errorf("collectorPanics = %d after second scrape, want 2", n)
	}
}
