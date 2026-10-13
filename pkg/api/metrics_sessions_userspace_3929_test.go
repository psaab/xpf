package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
)

// userspaceSessionsDP models the userspace dataplane's live session table.
// It embeds *dataplane.Manager for the methods the tests do not exercise and
// yields a fixed set of forward + reverse session entries from the iterators
// (the same surface `show security flow session` reads). SessionCount returns
// the forward-only totals, matching the real Manager semantics.
type userspaceSessionsDP struct {
	*dataplane.Manager
	v4 []dataplane.SessionValue
	v6 []dataplane.SessionValueV6
}

func (d *userspaceSessionsDP) IsLoaded() bool { return true }

func (d *userspaceSessionsDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, v := range d.v4 {
		if !fn(dataplane.SessionKey{}, v) {
			break
		}
	}
	return nil
}

func (d *userspaceSessionsDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for _, v := range d.v6 {
		if !fn(dataplane.SessionKeyV6{}, v) {
			break
		}
	}
	return nil
}

func (d *userspaceSessionsDP) SessionCount() (int, int) {
	v4, v6 := 0, 0
	for _, v := range d.v4 {
		if v.IsReverse == 0 {
			v4++
		}
	}
	for _, v := range d.v6 {
		if v.IsReverse == 0 {
			v6++
		}
	}
	return v4, v6
}

func (d *userspaceSessionsDP) SessionCountContext(context.Context) (int, int, error) {
	v4, v6 := d.SessionCount()
	return v4, v6, nil
}

// newUserspaceSessionsDP builds a snapshot with:
//   - 3 forward v4 sessions (2 ESTABLISHED, 1 OPENING), one SNAT-flagged
//   - 1 reverse v4 entry (must NOT be counted)
//   - 1 forward v6 session (ESTABLISHED, DNAT-flagged)
//
// => active (forward total) = 4, established = 3, ipv4 = 3, ipv6 = 1,
// snat = 1, dnat = 1.
func newUserspaceSessionsDP() *userspaceSessionsDP {
	const opening = 1 // any non-ESTABLISHED session state
	return &userspaceSessionsDP{
		Manager: dataplane.New(),
		v4: []dataplane.SessionValue{
			{IsReverse: 0, State: dataplane.SessStateEstablished, Flags: dataplane.SessFlagSNAT},
			{IsReverse: 0, State: dataplane.SessStateEstablished},
			{IsReverse: 0, State: opening},
			{IsReverse: 1, State: dataplane.SessStateEstablished}, // reverse — ignored
		},
		v6: []dataplane.SessionValueV6{
			{IsReverse: 0, State: dataplane.SessStateEstablished, Flags: dataplane.SessFlagDNAT},
		},
	}
}

func gatherGaugesByName(t *testing.T, c *xpfCollector, dp apiRuntimeDataPlane) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 32)
	c.collectSessionGauges(ch, dp)
	close(ch)
	out := map[string]float64{}
	names := []string{
		"xpf_sessions_active", "xpf_sessions_established",
		"xpf_sessions_ipv4", "xpf_sessions_ipv6",
		"xpf_sessions_snat", "xpf_sessions_dnat",
		"xpf_sessions_breakdown_scrape_ok",
	}
	for m := range ch {
		desc := m.Desc().String()
		for _, n := range names {
			// Desc().String() renders as `fqName: "<name>"`; anchor the match
			// so xpf_sessions_ipv4 does not also match a superset name.
			if strings.Contains(desc, `"`+n+`"`) {
				out[n] = gaugeValue(t, m)
			}
		}
	}
	return out
}

// TestPrometheusSessionGaugesFromUserspaceTable is the #3929 RED-on-revert
// guard for the Prometheus session gauges. It derives active/established/
// breakdown from a userspace session snapshot (the live dataplane session
// table). Reverting collectSessionGauges to source xpf_sessions_active /
// xpf_sessions_established from gc.Stats() (permanently 0 on the userspace
// dataplane, which skips the BPF GC sweep per #333) drops active from 4 -> 0
// and established from 3 -> 0, flipping both assertions red.
func TestPrometheusSessionGaugesFromUserspaceTable(t *testing.T) {
	c := newSessionGaugeCollector() // gc present, never swept => Stats() all-zero
	dp := newUserspaceSessionsDP()

	g := gatherGaugesByName(t, c, dp)

	checks := []struct {
		name string
		want float64
	}{
		{"xpf_sessions_breakdown_scrape_ok", 1},
		{"xpf_sessions_active", 4},
		{"xpf_sessions_established", 3},
		{"xpf_sessions_ipv4", 3},
		{"xpf_sessions_ipv6", 1},
		{"xpf_sessions_snat", 1},
		{"xpf_sessions_dnat", 1},
	}
	for _, chk := range checks {
		got, ok := g[chk.name]
		if !ok {
			t.Fatalf("%s not emitted; want %v", chk.name, chk.want)
		}
		if got != chk.want {
			t.Errorf("%s = %v, want %v", chk.name, got, chk.want)
		}
	}
}

// TestPrometheusSessionGaugesEmptyTable proves the count tracks the snapshot:
// zero sessions => zero active/established (and scrape_ok=1, not omitted).
func TestPrometheusSessionGaugesEmptyTable(t *testing.T) {
	c := newSessionGaugeCollector()
	dp := &userspaceSessionsDP{Manager: dataplane.New()}

	g := gatherGaugesByName(t, c, dp)

	if g["xpf_sessions_breakdown_scrape_ok"] != 1 {
		t.Fatalf("scrape_ok = %v, want 1 on empty healthy scan", g["xpf_sessions_breakdown_scrape_ok"])
	}
	if g["xpf_sessions_active"] != 0 || g["xpf_sessions_established"] != 0 {
		t.Errorf("active/established = %v/%v, want 0/0 on empty table",
			g["xpf_sessions_active"], g["xpf_sessions_established"])
	}
}

// TestRESTStatusSessionCountFromUserspaceTable is the #3929 RED-on-revert
// guard for the REST /status SessionCount. It must reflect the live dataplane
// session count (forward-only = 4), NOT gc.Stats().TotalEntries (0 on the
// userspace dataplane). Reverting health.go to `resp.SessionCount =
// stats.TotalEntries` reports 0 and flips this assertion red.
func TestRESTStatusSessionCountFromUserspaceTable(t *testing.T) {
	s := &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    newUserspaceSessionsDP(),
	}

	rr := httptest.NewRecorder()
	s.statusHandler(rr, httptest.NewRequest("GET", "/api/v1/status", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	// StatusResponse serializes SessionCount as "session_count":4.
	if !strings.Contains(body, `"session_count":4`) {
		t.Fatalf(`REST /status body missing "session_count":4 (live userspace count); got: %s`, body)
	}
}
