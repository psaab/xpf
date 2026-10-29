// #16707: #15086's U+FFFD fold is many-to-one. Two committed identifiers
// that differ only in invalid bytes (web\xffallow vs web\xfeallow in the
// same trust->untrust scope) both sanitized to web�allow, emitted
// duplicate xpf_policy_hits_total series, Registry.Gather failed, and
// promhttp's default HTTPErrorOnError answered 500 for the WHOLE
// exposition — monitoring blind until an operator renamed one.
//
// Fix legs pinned here:
//  1. sanitizeMetricLabelValue escapes each invalid byte as \xNN, so the
//     colliding pair keeps two distinct series and the scrape is 200.
//  2. The handler serves with ContinueOnError via a counting gatherer:
//     any residual duplicate-series source (the Y49-03 zone-pair vs
//     scoped-global same-name case, reproduced below) drops only that
//     series, the scrape still answers 200, and the drop is counted in
//     xpf_metrics_gather_errors_total on the next scrape.
//
// FAIL-ON-REVERT: restoring ToValidUTF8 makes the colliding scrape 500
// (test 1); restoring HTTPErrorOnError makes the Y49-03 scrape 500 and
// leaves gatherErrors at 0 (test 2).
package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// collidingCollector16707 builds a collector whose config carries the two
// probe identifiers in one zone pair, with distinct counter values so the
// two series are distinguishable by value as well as by label.
func collidingStore16707(t *testing.T, ruleNames []string) (*xpfCollector, *schedulerCounterAPIDP) {
	t.Helper()
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.PolicyStatsEnabled = true
	policies := make([]*config.Policy, len(ruleNames))
	counters := map[uint32]dataplane.CounterValue{
		dataplane.DefaultPolicySentinelID: {Packets: 3, Bytes: 300},
	}
	for i, name := range ruleNames {
		policies[i] = &config.Policy{Name: name, Action: config.PolicyPermit, Count: true}
		counters[policyCounterID(0, i)] = dataplane.CounterValue{Packets: uint64(10 + i), Bytes: uint64(100 * (10 + i))}
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "untrust", Policies: policies},
	}
	cfg.Security.GlobalPolicies = nil
	dp := &schedulerCounterAPIDP{Manager: dataplane.New(), counters: counters}
	c := newCollector(&Server{store: store, dp: dp})
	return c, dp
}

func scrape16707(t *testing.T, ts *httptest.Server) (int, string) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func countSeries16707(body, prefix string) int {
	n := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return n
}

// TestSanitizeMetricLabelValueInjective16707 pins the original invalid-byte
// spelling contract; the #17753 test below covers valid escape lookalikes.
func TestSanitizeMetricLabelValueInjective16707(t *testing.T) {
	cases := []struct{ in, want string }{
		{"web\xffallow", "web\\xffallow"},
		{"web\xfeallow", "web\\xfeallow"},
		{"a\xffb\xfec", "a\\xffb\\xfec"},
		{"\xff", "\\xff"},
		{"ok\xc3\xa9\xffend", "oké\\xffend"},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		got, ok := sanitizeMetricLabelValue(tc.in)
		if ok {
			t.Errorf("sanitize(%q): ok=true, want false (invalid input)", tc.in)
		}
		if got != tc.want {
			t.Errorf("sanitize(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("sanitize collision: %q and %q both -> %q", prev, tc.in, got)
		}
		seen[got] = tc.in
	}
	if got, ok := sanitizeMetricLabelValue("web-allow"); !ok || got != "web-allow" {
		t.Errorf("valid value rewritten: got %q ok=%v, want byte-identical", got, ok)
	}
	// A valid literal escape remains valid UTF-8 but has its backslash
	// escaped, making it distinct from the invalid byte's \xNN spelling.
	if got, ok := sanitizeMetricLabelValue(`web\xffallow`); !ok || got != `web\x5cxffallow` {
		t.Errorf("valid literal-escape value = %q ok=%v, want escaped backslash", got, ok)
	}
	// Truncated multi-byte sequence: the stray lead byte is escaped.
	if got, _ := sanitizeMetricLabelValue("x\xc3y"); got != "x\\xc3y" {
		t.Errorf("truncated sequence: got %q, want %q", got, "x\\xc3y")
	}
}

// TestMetricsScrapeSanitizeCollision16707 is the probe reproduction:
// web\xffallow + web\xfeallow in trust->untrust must answer 200 with
// TWO distinct xpf_policy_hits_total series, not 500.
func TestMetricsScrapeSanitizeCollision16707(t *testing.T) {
	collector, _ := collidingStore16707(t, []string{"web\xffallow", "web\xfeallow"})
	ts := httptest.NewServer(newMetricsHandler(collector, 5*time.Second))
	defer ts.Close()

	status, body := scrape16707(t, ts)
	if status != http.StatusOK {
		t.Fatalf("colliding scrape status = %d, want 200; body:\n%s", status, body)
	}
	if n := countSeries16707(body, "xpf_policy_hits_total{"); n != 3 {
		// Two colliding rules + the implicit default-policy row.
		t.Errorf("xpf_policy_hits_total series = %d, want 3 (2 rules + default); body:\n%s", n, body)
	}
	// The exposition escapes the label-value backslash, so the sanitized
	// value web\xffallow appears on the wire as web\\xffallow.
	if !strings.Contains(body, `rule="web\\xffallow"`) {
		t.Errorf("escaped \\xff series missing; body:\n%s", body)
	}
	if !strings.Contains(body, `rule="web\\xfeallow"`) {
		t.Errorf("escaped \\xfe series missing; body:\n%s", body)
	}
	if strings.Contains(body, "web�allow") {
		t.Errorf("many-to-one U+FFFD spelling still emitted; body:\n%s", body)
	}
	if n := collector.invalidLabelValues.Load(); n != 2 {
		t.Errorf("invalidLabelValues = %d, want 2 (one per colliding rule, first scrape)", n)
	}
	if n := collector.gatherErrors.Load(); n != 0 {
		t.Errorf("gatherErrors = %d, want 0: injective sanitization must not drop any series", n)
	}
	// Control: the health counter itself is present and reports 0 drops.
	if !strings.Contains(body, "xpf_metrics_gather_errors_total 0") {
		t.Errorf("xpf_metrics_gather_errors_total 0 missing from healthy colliding scrape; body:\n%s", body)
	}
}

// TestMetricsScrapeDuplicateSeriesContinueOnError16707 reproduces the
// Y49-03 class with valid UTF-8: a zone-pair rule and a scoped global
// with the SAME name in the SAME zone pair emit identical label sets.
// Sanitization cannot help (nothing invalid); ContinueOnError must
// keep the scrape at 200, serve the rest of the exposition, drop the
// duplicate, and count it for the next scrape.
func TestMetricsScrapeDuplicateSeriesContinueOnError16707(t *testing.T) {
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.PolicyStatsEnabled = true
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			{Name: "same-name", Action: config.PolicyPermit, Count: true},
		}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "same-name", Action: config.PolicyPermit, Count: true,
			Match: config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"untrust"}}},
	}
	// Zone-pair rule is policy set 0; the global follows it (policySetID
	// has advanced past the one zone pair).
	counters := map[uint32]dataplane.CounterValue{
		policyCounterID(0, 0):             {Packets: 11, Bytes: 1100},
		policyCounterID(1, 0):             {Packets: 22, Bytes: 2200},
		dataplane.DefaultPolicySentinelID: {Packets: 3, Bytes: 300},
	}
	dp := &schedulerCounterAPIDP{Manager: dataplane.New(), counters: counters}
	collector := newCollector(&Server{store: store, dp: dp})
	ts := httptest.NewServer(newMetricsHandler(collector, 5*time.Second))
	defer ts.Close()

	status, body := scrape16707(t, ts)
	if status != http.StatusOK {
		t.Fatalf("Y49-03 scrape status = %d, want 200 (ContinueOnError must salvage the exposition); body:\n%s", status, body)
	}
	// The rest of the exposition survived: health counters present.
	if !strings.Contains(body, "xpf_metrics_invalid_label_values_total") {
		t.Errorf("exposition truncated: health counters missing; body:\n%s", body)
	}
	// Exactly one of the two identical series can survive Gather; the
	// default-policy row is distinct, so at most 2 hit series appear.
	if n := countSeries16707(body, "xpf_policy_hits_total{"); n > 2 {
		t.Errorf("xpf_policy_hits_total series = %d, want <=2 (duplicate dropped, not duplicated)", n)
	}
	if n := collector.gatherErrors.Load(); n != 1 {
		t.Fatalf("gatherErrors = %d after first Y49-03 scrape, want 1 (duplicate counted, not silent)", n)
	}
	// Next scrape certifies the drop in-band.
	status, body = scrape16707(t, ts)
	if status != http.StatusOK {
		t.Fatalf("second Y49-03 scrape status = %d, want 200", status)
	}
	if !strings.Contains(body, "xpf_metrics_gather_errors_total 1") {
		t.Errorf("second scrape does not certify the dropped series (want xpf_metrics_gather_errors_total 1); body:\n%s", body)
	}
	if n := collector.gatherErrors.Load(); n != 2 {
		t.Errorf("gatherErrors = %d after second scrape, want 2 (counted per scrape)", n)
	}
}
