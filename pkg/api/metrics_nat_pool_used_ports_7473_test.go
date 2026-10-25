package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// natPoolUsedPortsSamples collects the pool names that emitted an
// `xpf_nat_pool_used_ports` sample.
//
// It records PRESENCE, not value, because the value cannot distinguish the two
// states: a pool the dataplane never installed reads 0, and 0 is also the
// honest reading for a healthy idle pool. The defect is that the SERIES EXISTS.
// An assertion on the number would be the vacuous version of this test — it
// would pass before and after the fix.
//
// #8606: the source is now the helper's live status rather than the legacy
// `nat_port_counters` map. The fixture below reports BOTH pools in that status
// on purpose: supplying only the healthy one would make the refused-pool
// assertion pass because the pool is ABSENT from the status, not because the
// refusal gate suppressed it — the discriminator this test exists for.
func natPoolUsedPortsSamples(t *testing.T, setLines []string, poolIDs map[string]uint8) map[string]bool {
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
	st := &dpuserspace.ProcessStatus{}
	for name := range poolIDs {
		st.SourceNATPools = append(st.SourceNATPools, dpuserspace.SourceNATPoolStatus{
			PoolName: name, RuleName: "r-" + name, UsedPorts: 7,
		})
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.collectNATPoolMetrics(ch, dp, st)
		close(ch)
	}()
	seen := map[string]bool{}
	for m := range ch {
		if m.Desc() != c.natPoolUsedPorts {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		for _, l := range pb.GetLabel() {
			if l.GetName() == "pool" {
				seen[l.GetValue()] = true
			}
		}
	}
	return seen
}

// #7473: a pool the snapshot builder REFUSED must emit no
// `xpf_nat_pool_used_ports` sample.
//
// #7000 made the capacity gauge honest — `xpf_nat_pool_total_ports` is 0 for a
// refused pool, computed through `SourceNATPoolReportablePorts`. The USAGE
// gauge in the same loop was not gated at all, and it could not be caught by
// noticing a wrong number: `cr.PoolIDs` contains refused pools, because
// `compiler_nat.go` assigns ids without consulting any disarm predicate, so the
// lookup succeeds and `ReadNATPortCounter` returns 0.
//
// A published `used=0` says "measured, and nothing is used". An absent series
// says "not installed". Monitoring cannot tell the first from health — which is
// exactly the argument the #5046 comment in this same function already makes
// for omitting the sample on a counter-READ failure. The refused-pool case
// reaches the same fake zero by a different route.
//
// This surface is the one that must be exactly right: unlike its two CLI twins
// (`show security nat source pool`, and the summary row), a scrape has no
// adjacent NOT INSTALLED line to contradict the number.
//
// FAIL-ON-REVERT: drop the `&& unusable == ""` from the `cr.PoolIDs` lookup in
// `collectNATPoolMetrics` and the `bad` leg reds.
func TestNATPoolUsedPortsIsNotEmittedForRefusedPool7473(t *testing.T) {
	seen := natPoolUsedPortsSamples(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		// `10.0.0.0/016` is #7000's own measured case: the non-canonical mask
		// makes the whole pool `invalid_pool`. Deliberately UNREFERENCED — the
		// #5877 strict gate rejects a malformed pool a rule references, and the
		// metrics loop walks `SourcePools` rather than the rules, which is how
		// it reaches this surface at all.
		"set security nat source pool bad address 10.0.0.0/016",
		"set security nat source pool good address 203.0.113.1/32",
		"set security nat source rule-set rs from zone trust",
		"set security nat source rule-set rs to zone untrust",
		"set security nat source rule-set rs rule r2 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs rule r2 then source-nat pool good",
	}, map[string]uint8{"bad": 0, "good": 1})

	if seen["bad"] {
		t.Errorf("xpf_nat_pool_used_ports{pool=bad} was emitted for a pool the " +
			"dataplane refused. The pool installs no allocator, so the 0 behind " +
			"that sample was never measured — and a scrape has no NOT INSTALLED " +
			"line beside it, so monitoring reads it as a healthy idle pool. The " +
			"#5046 comment in this function already refuses exactly this zero on " +
			"the counter-read-failure path (#7473)")
	}

	// Control. Without it this passes on a collector that emits no used-ports
	// series at all — including one broken so thoroughly that the refused-pool
	// assertion above is vacuously satisfied.
	if !seen["good"] {
		t.Errorf("xpf_nat_pool_used_ports{pool=good} was NOT emitted for a healthy " +
			"pool, so the refused-pool assertion above proves nothing — the fix " +
			"must suppress the refused pool's sample, not every pool's")
	}
}
