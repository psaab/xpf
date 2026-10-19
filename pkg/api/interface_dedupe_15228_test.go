package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #15228 A44-05: ge-0/0/0 (config) + ge-0/0/0.0 (zone) resolve to same ifindex;
// collectInterfaceCounters must emit one series per direction, not two.
func TestCollectInterfaceCountersDedupesByIfindex15228(t *testing.T) {
	requireLoopback(t)
	// lo + lo.0 both resolve to "lo".
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set interfaces lo unit 0 family inet",
		"set security zones security-zone trust interfaces lo.0",
	}, "\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	cfg := store.ActiveConfig()
	names := allInterfaceNames(cfg)
	t.Logf("allInterfaceNames=%v", names)
	dp := &descriptorCoverageDP{Manager: dataplane.New()}
	c := newCollector(&Server{store: store})
	ch := make(chan prometheus.Metric, 64)
	c.collectInterfaceCounters(ch, dp)
	close(ch)
	counts := map[string]int{}
	for m := range ch {
		var pbm dto.Metric
		if err := m.Write(&pbm); err != nil {
			t.Fatal(err)
		}
		for _, lp := range pbm.Label {
			if lp.GetName() == "iface" {
				counts[lp.GetValue()]++
			}
		}
	}
	t.Logf("label counts=%v", counts)
	total := 0
	for _, v := range counts {
		total += v
	}
	// 2 metrics (packets,bytes) x 2 directions = 4 for ONE interface.
	if total != 4 {
		t.Fatalf("emitted %d iface samples (per-label %v), want 4 for single resolved ifindex", total, counts)
	}
}
