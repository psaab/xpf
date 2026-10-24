package api

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
)

// errIterDP is an apiRuntimeDataPlane whose session iterators fail,
// modelling a backend (helper) error mid-scan. It embeds a
// *dataplane.Manager only to satisfy the methods the tests do not
// exercise; the IsLoaded/IterateSessions overrides drive the read paths.
type errIterDP struct {
	*dataplane.Manager
	iterErr error
}

func (d *errIterDP) IsLoaded() bool { return true }

func (d *errIterDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return d.iterErr
}

func (d *errIterDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return d.iterErr
}

// TestRESTSessionViewsFailOnIteratorError asserts the #2469 contract:
// when the session iterator errors, the REST session views must NOT
// return HTTP 200 with a partial/zero body — they must surface a 5xx so
// dashboards see a failure instead of a healthy-but-wrong picture.
//
// FAIL-ON-REVERT: reverting the `if err := ...; err != nil { writeError }`
// guard back to `_ = s.dp.IterateSessions(...)` makes each handler fall
// through to writeOK (HTTP 200), and every want-500 assertion below
// flips red.
func TestRESTSessionViewsFailOnIteratorError(t *testing.T) {
	iterErr := errors.New("helper restart: session map closed")
	s := &Server{
		dp: &errIterDP{Manager: dataplane.New(), iterErr: iterErr},
	}

	cases := []struct {
		name    string
		handler func(*httptest.ResponseRecorder)
	}{
		{
			name: "sessions list",
			handler: func(rr *httptest.ResponseRecorder) {
				s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/sessions", nil))
			},
		},
		{
			name: "sessions summary",
			handler: func(rr *httptest.ResponseRecorder) {
				s.sessionSummaryHandler(rr, httptest.NewRequest("GET", "/api/v1/sessions/summary", nil))
			},
		},
		{
			name: "sessions zone-pair",
			handler: func(rr *httptest.ResponseRecorder) {
				s.sessionZonePairHandler(rr, httptest.NewRequest("GET", "/api/v1/sessions/zone-pair", nil))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tc.handler(rr)
			if rr.Code != 500 {
				t.Fatalf("%s: status = %d, want 500 on iterator error; body: %s",
					tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

func newSessionGaugeCollector() *xpfCollector {
	gc := conntrack.NewGC(nil, time.Minute)
	return &xpfCollector{
		deps:                collectorDeps{gc: gc},
		sessionsActive:      prometheus.NewDesc("xpf_sessions_active", "test", nil, nil),
		sessionsEstablished: prometheus.NewDesc("xpf_sessions_established", "test", nil, nil),
		sessionsIPv4:        prometheus.NewDesc("xpf_sessions_ipv4", "test", nil, nil),
		sessionsIPv6:        prometheus.NewDesc("xpf_sessions_ipv6", "test", nil, nil),
		sessionsSNAT:        prometheus.NewDesc("xpf_sessions_snat", "test", nil, nil),
		sessionsDNAT:        prometheus.NewDesc("xpf_sessions_dnat", "test", nil, nil),
		sessionScrapeOK:     prometheus.NewDesc("xpf_sessions_breakdown_scrape_ok", "test", nil, nil),
		gcSweepDuration:     prometheus.NewDesc("xpf_gc_sweep_duration_seconds", "test", nil, nil),
	}
}

func gaugeValue(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	var pb dto.Metric
	if err := m.Write(&pb); err != nil {
		t.Fatalf("metric.Write: %v", err)
	}
	if pb.Gauge == nil {
		t.Fatalf("metric is not a gauge: %s", m.Desc().String())
	}
	return pb.Gauge.GetValue()
}

// TestPrometheusSessionBreakdownFailOnIteratorError asserts the #2469
// Prometheus contract: on iterator error the collector must NOT emit the
// session-breakdown gauges (ipv4/ipv6/snat/dnat) as if they were a
// healthy zero — it must instead emit xpf_sessions_breakdown_scrape_ok=0
// and OMIT the breakdown gauges, so an alert fires rather than graphs
// silently dropping to zero.
//
// FAIL-ON-REVERT: restoring `_ = dp.IterateSessions(...)` and the
// unconditional gauge emission makes the collector emit the breakdown
// descs with value 0 AND never emit scrape_ok=0 — both assertions flip.
func TestPrometheusSessionBreakdownFailOnIteratorError(t *testing.T) {
	c := newSessionGaugeCollector()
	dp := &errIterDP{Manager: dataplane.New(), iterErr: errors.New("helper restart")}

	ch := make(chan prometheus.Metric, 16)
	c.collectSessionGauges(ch, dp)
	close(ch)

	sawScrapeOKZero := false
	for m := range ch {
		desc := m.Desc().String()
		if strings.Contains(desc, "xpf_sessions_ipv4") ||
			strings.Contains(desc, "xpf_sessions_ipv6") ||
			strings.Contains(desc, "xpf_sessions_snat") ||
			strings.Contains(desc, "xpf_sessions_dnat") {
			t.Fatalf("breakdown gauge emitted on iterator error: %s", desc)
		}
		if strings.Contains(desc, "xpf_sessions_breakdown_scrape_ok") {
			if v := gaugeValue(t, m); v != 0 {
				t.Fatalf("scrape_ok = %v on iterator error, want 0", v)
			}
			sawScrapeOKZero = true
		}
	}
	if !sawScrapeOKZero {
		t.Fatal("xpf_sessions_breakdown_scrape_ok not emitted on iterator error; want value 0")
	}
}

// TestPrometheusSessionBreakdownHealthyEmitsGauges is the positive
// companion: a healthy (nil-error) scan must emit scrape_ok=1 AND the
// breakdown gauges, proving the failure path is the only one that omits
// them.
func TestPrometheusSessionBreakdownHealthyEmitsGauges(t *testing.T) {
	c := newSessionGaugeCollector()
	// nil iterErr => both iterators succeed (and enumerate nothing).
	dp := &errIterDP{Manager: dataplane.New(), iterErr: nil}

	ch := make(chan prometheus.Metric, 16)
	c.collectSessionGauges(ch, dp)
	close(ch)

	sawIPv4 := false
	sawScrapeOKOne := false
	for m := range ch {
		desc := m.Desc().String()
		if strings.Contains(desc, "xpf_sessions_ipv4") {
			sawIPv4 = true
		}
		if strings.Contains(desc, "xpf_sessions_breakdown_scrape_ok") {
			if v := gaugeValue(t, m); v != 1 {
				t.Fatalf("scrape_ok = %v on healthy scan, want 1", v)
			}
			sawScrapeOKOne = true
		}
	}
	if !sawIPv4 {
		t.Fatal("breakdown gauge xpf_sessions_ipv4 not emitted on healthy scan")
	}
	if !sawScrapeOKOne {
		t.Fatal("xpf_sessions_breakdown_scrape_ok=1 not emitted on healthy scan")
	}
}
