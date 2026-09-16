package natpoolalarm

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9896: the tracked-flow cap is the constraint that actually refuses new
// flows (allocator.rs:2036 refuses at live_by_flow.len() >= max_tracked_flows),
// but the alarm divided used ports by the nominal address x port capacity — so
// a pool AT the refusing cap with a low ports ratio never raised.

// poolStatusFlows builds a deduped pool sample carrying the tracked-flow
// counters the snapshot already ships (protocol_counters.go:17,20).
func poolStatusFlows(name string, addr int, low, high uint16, used, live, max uint64) PoolStatus {
	return PoolStatus{
		PoolName: name, AddressCount: addr, PortLow: low, PortHigh: high,
		UsedPorts: used, LiveFlows: live, MaxTrackedFlows: max,
	}
}

// TestFlowCapAtCapRaises_9896 is the synthetic at-cap fixture: nominal capacity
// 5*64512 = 322,560 with only 10,000 ports used (3% — far below raise), but
// live flows AT the 262,144 tracked-flow cap, i.e. the pool is refusing. Must
// raise exactly once.
func TestFlowCapAtCapRaises_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg,
		poolStatusFlows("p1", 5, 1024, 65535, 10_000, 262_144, 262_144)))
	m.evaluate()
	if got := countMatch(rec.snapshot(), raisedTag); got != 1 {
		t.Fatalf("at-cap pool must raise exactly once, got %d raise lines", got)
	}
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].PoolName != "p1" {
		t.Fatalf("expected p1 active, got %+v", alarms)
	}
	if alarms[0].CurrentPct != 100 {
		t.Fatalf("at-cap utilization must report 100%%, got %d", alarms[0].CurrentPct)
	}
}

// TestDualThresholdCrossingSingleSyslog_9896: both legs above raise is still
// ONE transition — exactly one raise line, no double-syslog.
func TestDualThresholdCrossingSingleSyslog_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	// Cap 100 ports: 90 used (90%) AND 95/100 live (95%) — both cross 80.
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 1, 100, 90, 95, 100)))
	m.evaluate()
	if got := countMatch(rec.snapshot(), raisedTag); got != 1 {
		t.Fatalf("dual crossing must emit exactly 1 raise line, got %d", got)
	}
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].CurrentPct != 95 {
		t.Fatalf("expected 95%% (max of legs), got %+v", alarms)
	}
}

// TestFlowLegMissingFallsBackToPorts_9896: MaxTrackedFlows==0 (helper predates
// the counters) makes the flow leg inapplicable — LiveFlows AND
// PersistentLeases must be ignored and the ports ratio alone decides.
func TestFlowLegMissingFallsBackToPorts_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	// Absurd LiveFlows + leases with no cap: must NOT raise (ports 10%).
	s := poolStatusFlows("p1", 1, 1, 100, 10, 1<<60, 0)
	s.PersistentLeases = 1 << 60
	vb.set(coherentView(cfg, s))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 || len(rec.snapshot()) != 0 {
		t.Fatalf("unknown cap must ignore LiveFlows and leases; alarms=%+v lines=%+v",
			m.ActiveAlarms(), rec.snapshot())
	}
	// And the ports leg still raises on its own with no flow data.
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 1, 100, 85, 0, 0)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("ports-only sample must still raise")
	}
}

// TestFlowLegClearsBelowClear_9896: an alarm raised by the flow leg clears when
// live flows drop below clear while ports stay low.
func TestFlowLegClearsBelowClear_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg,
		poolStatusFlows("p1", 5, 1024, 65535, 10_000, 262_144, 262_144)))
	m.evaluate() // raise via flow leg
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("precondition: flow-leg raise")
	}
	rec.reset()
	// Live 50% of cap, ports still 3% — both below clear(70) → clear once.
	vb.set(coherentView(cfg,
		poolStatusFlows("p1", 5, 1024, 65535, 10_000, 131_072, 262_144)))
	m.evaluate()
	if got := countMatch(rec.snapshot(), clearedTag); got != 1 {
		t.Fatalf("expected 1 clear line, got %d", got)
	}
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("alarm should be cleared")
	}
}

// TestFlowLegHysteresisBand_9896: a flow-raised alarm held in the band
// refreshes pct without emitting.
func TestFlowLegHysteresisBand_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg,
		poolStatusFlows("p1", 5, 1024, 65535, 10_000, 262_144, 262_144)))
	m.evaluate() // raise at 100%
	rec.reset()
	// 75% of cap: in [clear, raise) → hold, refresh to 75, no syslog.
	vb.set(coherentView(cfg,
		poolStatusFlows("p1", 5, 1024, 65535, 10_000, 196_608, 262_144)))
	m.evaluate()
	if len(rec.snapshot()) != 0 {
		t.Fatalf("band hold must emit nothing, got %+v", rec.snapshot())
	}
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].CurrentPct != 75 {
		t.Fatalf("expected held alarm at 75%%, got %+v", alarms)
	}
}

// cfgWithAddrOnly mirrors cfgWith for an address-only (`port no-translation`)
// pool: no port range, one address, referenced by one source-NAT rule.
func cfgWithAddrOnly(raise, clear int) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.PoolUtilizationAlarm = &config.PoolUtilizationAlarmConfig{
		RaiseThreshold: raise,
		ClearThreshold: clear,
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p1": {Name: "p1", PortNoTranslation: true, Addresses: []string{"1.1.1.1"}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "rs1", Rules: []*config.NATRule{
			{Name: "r1", Then: config.NATThen{Type: config.NATSource, PoolName: "p1"}},
		}},
	}
	return cfg
}

// TestAddressOnlyFlowLegRaises_9896 (fold): an address-only pool refuses at
// the SAME tracked-flow cap (allocator.rs:3608,4076,4223), so the flow leg is
// evaluated independently of port translation. The sample carries deliberately
// corrupt PORTS fields (the badports shape that HOLDs a port-bearing pool)
// with UsedPorts 0 and live flows at the cap — must still raise at 100%, and
// the pool must NOT be recorded inapplicable (its alarm can fire).
func TestAddressOnlyFlowLegRaises_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWithAddrOnly(80, 70)
	vb.set(coherentView(cfg,
		poolStatusFlows("p1", 0, 100, 1, 0, 262_144, 262_144)))
	m.evaluate()
	if got := countMatch(rec.snapshot(), raisedTag); got != 1 {
		t.Fatalf("address-only at-cap pool must raise exactly once, got %d", got)
	}
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].CurrentPct != 100 {
		t.Fatalf("expected active alarm at 100%%, got %+v", alarms)
	}
	if reason := m.InapplicableReason("p1"); reason != "" {
		t.Fatalf("flow-measurable pool must not be inapplicable, got %q", reason)
	}
}

// TestAddressOnlyNoCapStaysInapplicable_9896 (fold): address-only + no
// flow-cap data (MaxTrackedFlows == 0) has NEITHER leg measurable — the alarm
// cannot fire, so the pool is recorded inapplicable and nothing raises.
func TestAddressOnlyNoCapStaysInapplicable_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWithAddrOnly(80, 70)
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 0, 0, 0, 1<<60, 0)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 || len(rec.snapshot()) != 0 {
		t.Fatalf("unmeasurable pool must not raise; alarms=%+v lines=%+v",
			m.ActiveAlarms(), rec.snapshot())
	}
	if reason := m.InapplicableReason("p1"); reason == "" {
		t.Fatal("unmeasurable address-only pool must be recorded inapplicable")
	}
}

// TestAddressOnlyUnmeasurableUnlatchesSilently_9896 (fold): a flow-raised
// address-only alarm whose leg goes unmeasurable (MaxTrackedFlows flaps to 0)
// must not stay latched — but the drop emits NO clear syslog (utilization did
// not fall below the threshold; the measurement is gone).
func TestAddressOnlyUnmeasurableUnlatchesSilently_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWithAddrOnly(80, 70)
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 0, 0, 0, 262_144, 262_144)))
	m.evaluate() // raise via flow leg
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("precondition: flow-leg raise")
	}
	rec.reset()
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 0, 0, 0, 0, 0)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("unmeasurable pool must not stay latched")
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("unlatch must emit nothing, got %+v", rec.snapshot())
	}
	if reason := m.InapplicableReason("p1"); reason == "" {
		t.Fatal("unmeasurable pool must be recorded inapplicable")
	}
}

// TestAddressOnlyAbsentSampleHolds_9896 (fold): an address-only flow alarm
// with no sample this tick HOLDs — the alarm stays, nothing emits, and the
// (clear) inapplicability record is untouched. Mutation: marking
// inapplicable on the absent path would delete the active alarm via
// markInapplicable's unlatch.
func TestAddressOnlyAbsentSampleHolds_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWithAddrOnly(80, 70)
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 0, 0, 0, 262_144, 262_144)))
	m.evaluate() // raise via flow leg
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("precondition: flow-leg raise")
	}
	rec.reset()
	vb.set(coherentView(cfg)) // same config, no pool sample
	m.evaluate()
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("absent sample must HOLD the flow alarm, not drop it")
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("HOLD must emit nothing, got %+v", rec.snapshot())
	}
	if reason := m.InapplicableReason("p1"); reason != "" {
		t.Fatalf("HOLD must not touch the record, got %q", reason)
	}
}

// TestDeterministicFlowLegRaises_9896 (fold 2): deterministic arms enforce
// the SAME tracked-flow cap (allocate_deterministic_v4/v6 at
// allocator.rs:2930,3088; reserve_address_only_maybe_persistent at :3731 via
// match_rules.rs:678-682), so the flow leg is evaluated independently of
// deterministic classification. The concrete case: one address, a /28 of
// subscribers, 64,512 tracked flows and zero used ports — refusing while the
// ports leg reads 0%. Must raise at 100%, and the pool must NOT be recorded
// inapplicable (its alarm can fire).
func TestDeterministicFlowLegRaises_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, true)
	vb.set(coherentView(cfg,
		poolStatusFlows("p1", 1, 1024, 65535, 0, 64_512, 64_512)))
	m.evaluate()
	if got := countMatch(rec.snapshot(), raisedTag); got != 1 {
		t.Fatalf("deterministic at-cap pool must raise exactly once, got %d", got)
	}
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].CurrentPct != 100 {
		t.Fatalf("expected active alarm at 100%%, got %+v", alarms)
	}
	if reason := m.InapplicableReason("p1"); reason != "" {
		t.Fatalf("flow-measurable pool must not be inapplicable, got %q", reason)
	}
}

// TestDeterministicPortsLegExcluded_9896 (fold 2): the PORTS leg stays
// excluded for deterministic pools — aggregate utilization cannot predict
// per-block exhaustion. 95% ports with a healthy flow leg must NOT raise
// (a PAT pool raises on this sample).
func TestDeterministicPortsLegExcluded_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, true)
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 1, 100, 95, 5, 100)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 || len(rec.snapshot()) != 0 {
		t.Fatalf("ports pressure alone must not raise a deterministic pool; alarms=%+v lines=%+v",
			m.ActiveAlarms(), rec.snapshot())
	}
	if reason := m.InapplicableReason("p1"); reason != "" {
		t.Fatalf("flow-measurable pool must not be inapplicable, got %q", reason)
	}
}

// TestDeterministicHealthyNoRaise_9896 (fold 2): a deterministic pool with a
// healthy flow leg stays silent AND stays measurable (no inapplicable
// record — silence must read as headroom, not as cannot-fire).
func TestDeterministicHealthyNoRaise_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, true)
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 1024, 65535, 0, 1000, 64_512)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 || len(rec.snapshot()) != 0 {
		t.Fatalf("healthy pool must stay silent; alarms=%+v lines=%+v",
			m.ActiveAlarms(), rec.snapshot())
	}
	if reason := m.InapplicableReason("p1"); reason != "" {
		t.Fatalf("healthy pool must not be inapplicable, got %q", reason)
	}
}

// TestDeterministicFlowLegRecovers_9896 (fold 2): a deterministic alarm
// raised by the flow leg clears — with exactly one clear line — when live
// flows drop below the clear threshold.
func TestDeterministicFlowLegRecovers_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, true)
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 1024, 65535, 0, 64_512, 64_512)))
	m.evaluate() // raise via flow leg
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("precondition: flow-leg raise")
	}
	rec.reset()
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 1024, 65535, 0, 1000, 64_512)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("flow leg below clear must clear the alarm")
	}
	if got := countMatch(rec.snapshot(), clearedTag); got != 1 {
		t.Fatalf("recovery must emit exactly one clear, got %d", got)
	}
}

// TestDeterministicNoCapStaysInapplicable_9896 (fold 2): deterministic + no
// flow-cap data (MaxTrackedFlows == 0) has NEITHER leg measurable — the
// alarm cannot fire, so the pool is recorded inapplicable and nothing
// raises. The reason keeps the per-block sentence (pinned by the #9902
// exhaustion cell) and adds the missing-cap cause.
func TestDeterministicNoCapStaysInapplicable_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, true)
	vb.set(coherentView(cfg, poolStatusFlows("p1", 1, 1, 100, 95, 1<<60, 0)))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 || len(rec.snapshot()) != 0 {
		t.Fatalf("unmeasurable pool must not raise; alarms=%+v lines=%+v",
			m.ActiveAlarms(), rec.snapshot())
	}
	if reason := m.InapplicableReason("p1"); reason == "" {
		t.Fatal("unmeasurable deterministic pool must be recorded inapplicable")
	}
}

// TestLeaseLegRaisesAtCap_9896 (fold 2): fresh-lease admission refuses at
// the same cap (allocator.rs:2209,2215,4511,4514), so the flow leg is
// max(live, leases). Idle-lease accumulation at the cap with a healthy live
// leg and a low ports ratio must still raise.
func TestLeaseLegRaisesAtCap_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	s := poolStatusFlows("p1", 5, 1024, 65535, 10_000, 1000, 262_144)
	s.PersistentLeases = 262_144
	vb.set(coherentView(cfg, s))
	m.evaluate()
	if got := countMatch(rec.snapshot(), raisedTag); got != 1 {
		t.Fatalf("lease-at-cap pool must raise exactly once, got %d", got)
	}
	alarms := m.ActiveAlarms()
	if len(alarms) != 1 || alarms[0].CurrentPct != 100 {
		t.Fatalf("expected active alarm at 100%%, got %+v", alarms)
	}
}

// TestLeaseLegBelowLiveDefersToLive_9896 (fold 2): the lease leg joins the
// max — it never LOWERS the utilization. Leases below live leave the live
// percentage in force.
func TestLeaseLegBelowLiveDefersToLive_9896(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	s := poolStatusFlows("p1", 5, 1024, 65535, 10_000, 262_144, 262_144)
	s.PersistentLeases = 1000
	vb.set(coherentView(cfg, s))
	m.evaluate()
	if got := countMatch(rec.snapshot(), raisedTag); got != 1 {
		t.Fatalf("live-at-cap pool must raise exactly once, got %d", got)
	}
	if alarms := m.ActiveAlarms(); len(alarms) != 1 || alarms[0].CurrentPct != 100 {
		t.Fatalf("expected active alarm at 100%%, got %+v", alarms)
	}
}
