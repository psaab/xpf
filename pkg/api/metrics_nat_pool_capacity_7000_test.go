package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #7000: the `xpf_nat_pool_total_ports` gauge is the DENOMINATOR of pool
// utilisation alerts, so a figure reported for a pool the dataplane refused is
// a monitoring-visible contract break — the alert divides by capacity for a
// pool that can allocate nothing. And a prefix pool under-reported by its
// expansion factor, so utilisation read 256x too high for a healthy /24.
//
// This drives the REAL collector and reads the REAL gauge value, because the
// helper-level test in pkg/config cannot see whether this surface calls it.
func natPoolGauges(t *testing.T, setLines []string, poolIDs map[string]uint8) (map[string]float64, *xpfCollector) {
	t.Helper()
	store := newConfigStore(t, t.TempDir())
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(strings.Join(setLines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := newCollector(&Server{store: store})
	dp := &descriptorCoverageDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{PoolIDs: poolIDs},
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.collectNATPoolMetrics(ch, dp, &dpuserspace.ProcessStatus{})
		close(ch)
	}()
	got := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		if m.Desc() != c.natPoolTotalPorts {
			continue
		}
		for _, l := range pb.GetLabel() {
			if l.GetName() == "pool" {
				got[l.GetValue()] = pb.GetGauge().GetValue()
			}
		}
	}
	return got, c
}

// A healthy prefix pool: the dataplane expands 203.0.113.0/24 to 256 addresses,
// so the gauge must be 256 * 64512. The old derivation counted the member ONCE
// and published 64512 — a utilisation ratio 256x too high.
func TestNATPoolTotalPortsGaugeExpandsPrefixMembers7000(t *testing.T) {
	got, _ := natPoolGauges(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool wide address 203.0.113.0/24",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r1 then source-nat pool wide",
	}, map[string]uint8{"wide": 0})

	const want = float64(256 * 64512)
	if v, ok := got["wide"]; !ok || v != want {
		t.Fatalf("xpf_nat_pool_total_ports{pool=wide} = %v (present=%v), want %v. "+
			"A /24 installs 256 pool addresses; counting the member once under-reports "+
			"capacity by the expansion factor and inflates every utilisation ratio "+
			"computed against this gauge (#7000)", v, ok, want)
	}
}

// A pool the dataplane REFUSES installs no allocator, so its reportable
// capacity is zero. `10.0.0.0/016` is the issue's own measured case: the
// non-canonical mask makes the whole pool `invalid_pool`.
func TestNATPoolTotalPortsGaugeIsZeroForRefusedPool7000(t *testing.T) {
	got, _ := natPoolGauges(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool bad address 10.0.0.0/016",
		"set security nat source pool good address 203.0.113.1/32",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		// `bad` is deliberately UNREFERENCED: the #5877 strict commit gate
		// rejects a malformed pool that a rule references, so a referenced one
		// never reaches this surface. An unreferenced one commits — and the
		// metrics loop walks `SourcePools`, not the rules, so it still publishes
		// a gauge for it. That is exactly how a fabricated denominator escapes
		// to monitoring.
		"set security nat source rule-set rs rule r2 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r2 then source-nat pool good",
	}, map[string]uint8{"bad": 0, "good": 1})

	if v, ok := got["bad"]; !ok || v != 0 {
		t.Fatalf("xpf_nat_pool_total_ports{pool=bad} = %v (present=%v), want 0. "+
			"The malformed mask makes the pool invalid_pool, so NO allocator is "+
			"installed and the dataplane can hand out nothing — any non-zero "+
			"denominator here is confidently wrong (#7000)", v, ok)
	}
	// The healthy sibling in the SAME config must be unaffected. Without this
	// the test would pass on a collector that reported 0 for everything.
	if v, ok := got["good"]; !ok || v != float64(64512) {
		t.Fatalf("xpf_nat_pool_total_ports{pool=good} = %v (present=%v), want 64512 — "+
			"a healthy pool alongside a refused one must still report its real capacity",
			v, ok)
	}
}
