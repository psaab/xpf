package natpoolalarm

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const (
	exhaustedRaisedTag  = "NAT_POOL_EXHAUSTION_ALARM_RAISED"
	exhaustedClearedTag = "NAT_POOL_EXHAUSTION_ALARM_CLEARED"
)

// exhPool9902 builds a pool sample whose utilization (10%) can never raise,
// so every assertion below is about the exhaustion pass only.
func exhPool9902(name string, exh, id uint64) PoolStatus {
	return PoolStatus{
		PoolName:        name,
		AddressCount:    1,
		PortLow:         1,
		PortHigh:        100,
		UsedPorts:       10,
		ExhaustionTotal: exh,
		AllocatorID:     id,
	}
}

// setExhView9902 publishes a coherent view with the given freshness token and
// helper incarnation.
func setExhView9902(vb *viewBox, cfg *config.Config, seq, procGen uint64, pools ...PoolStatus) {
	v := coherentView(cfg, pools...)
	v.StatusSequence = seq
	v.ProcGen = procGen
	vb.set(v)
}

func activeExhaustion9902(t *testing.T, m *Monitor) []ActiveExhaustionAlarm {
	t.Helper()
	return m.ActiveExhaustionAlarms()
}

// First sighting establishes the baseline silently — even with a nonzero
// count, there is no history to call it a delta against.
func TestExhaustionFirstSightSilent9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 7))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("first sighting must not raise, got %+v", got)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("first sighting must emit nothing, got %v", rec.snapshot())
	}
}

// Raise on a true delta, silent refresh on further deltas, clear after 3
// fresh clean ticks.
func TestExhaustionRaiseRefreshClear9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 7))
	m.evaluate() // baseline

	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 7))
	m.evaluate() // delta 3 → raise
	if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 3 {
		t.Fatalf("delta must raise with events=3, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedRaisedTag); got != 1 {
		t.Fatalf("raise must emit once, got %d", got)
	}
	rec.reset()

	setExhView9902(vb, cfg, 3, 1, exhPool9902("p1", 10, 7))
	m.evaluate() // delta 2 → refresh, no syslog
	if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 2 {
		t.Fatalf("refresh must update events to 2, got %+v", got)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("refresh must emit nothing, got %v", rec.snapshot())
	}

	// Two clean ticks: still raised, no clear yet.
	setExhView9902(vb, cfg, 4, 1, exhPool9902("p1", 10, 7))
	m.evaluate()
	setExhView9902(vb, cfg, 5, 1, exhPool9902("p1", 10, 7))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 1 {
		t.Fatalf("2 clean ticks must not clear, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedClearedTag); got != 0 {
		t.Fatalf("2 clean ticks must not clear, got %d clears", got)
	}

	// Third clean tick: clear.
	setExhView9902(vb, cfg, 6, 1, exhPool9902("p1", 10, 7))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("3rd clean tick must clear, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedClearedTag); got != 1 {
		t.Fatalf("clear must emit once, got %d", got)
	}
}

// Identity change × {below, equal, above} ⇒ silent rebase in all three
// cells, and the rebase stores the new count (the follow-up delta is
// measured from it, not from the pre-rebase baseline).
func TestExhaustionIdChangeRebases9902(t *testing.T) {
	for _, tc := range []struct {
		name string
		cur  uint64
	}{
		{"below", 0},
		{"equal", 5},
		{"above", 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, rec, vb := newMon()
			cfg := cfgWith(80, 70, false)
			setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
			m.evaluate() // baseline (id=1, count=5)

			setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", tc.cur, 2))
			m.evaluate() // id change ⇒ silent rebase
			if got := activeExhaustion9902(t, m); len(got) != 0 {
				t.Fatalf("id change must not raise, got %+v", got)
			}
			if len(rec.snapshot()) != 0 {
				t.Fatalf("id change must emit nothing, got %v", rec.snapshot())
			}

			// The rebase stored tc.cur: a +3 delta from it raises events=3.
			setExhView9902(vb, cfg, 3, 1, exhPool9902("p1", tc.cur+3, 2))
			m.evaluate()
			if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 3 {
				t.Fatalf("post-rebase delta must raise events=3, got %+v", got)
			}
		})
	}
}

// Helper-incarnation change × {below, equal, above} ⇒ silent rebase,
// same as the id half of the key.
func TestExhaustionProcGenChangeRebases9902(t *testing.T) {
	for _, tc := range []struct {
		name string
		cur  uint64
	}{
		{"below", 0},
		{"equal", 5},
		{"above", 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, rec, vb := newMon()
			cfg := cfgWith(80, 70, false)
			setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
			m.evaluate()

			setExhView9902(vb, cfg, 2, 2, exhPool9902("p1", tc.cur, 1))
			m.evaluate() // procGen change ⇒ silent rebase
			if got := activeExhaustion9902(t, m); len(got) != 0 {
				t.Fatalf("procGen change must not raise, got %+v", got)
			}
			if len(rec.snapshot()) != 0 {
				t.Fatalf("procGen change must emit nothing, got %v", rec.snapshot())
			}

			setExhView9902(vb, cfg, 3, 2, exhPool9902("p1", tc.cur+3, 1))
			m.evaluate()
			if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 3 {
				t.Fatalf("post-rebase delta must raise events=3, got %+v", got)
			}
		})
	}
}

// Same key: below ⇒ defensive rebase, equal ⇒ clean tick, above ⇒ raise.
func TestExhaustionSameKeyCells9902(t *testing.T) {
	t.Run("below-rebases", func(t *testing.T) {
		m, rec, vb := newMon()
		cfg := cfgWith(80, 70, false)
		setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
		m.evaluate()
		setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 2, 1))
		m.evaluate() // cur<prev on the same key ⇒ rebase
		if got := activeExhaustion9902(t, m); len(got) != 0 {
			t.Fatalf("same-key decrease must not raise, got %+v", got)
		}
		if len(rec.snapshot()) != 0 {
			t.Fatalf("same-key decrease must emit nothing, got %v", rec.snapshot())
		}
		// Rebased at 2: +1 raises events=1 (not a 5-based phantom).
		setExhView9902(vb, cfg, 3, 1, exhPool9902("p1", 3, 1))
		m.evaluate()
		if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 1 {
			t.Fatalf("post-rebase delta must raise events=1, got %+v", got)
		}
	})

	t.Run("equal-is-clean", func(t *testing.T) {
		m, rec, vb := newMon()
		cfg := cfgWith(80, 70, false)
		setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
		m.evaluate()
		setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 5, 1))
		m.evaluate() // equal ⇒ clean tick, nothing raised
		if got := activeExhaustion9902(t, m); len(got) != 0 {
			t.Fatalf("clean tick must not raise, got %+v", got)
		}
		if len(rec.snapshot()) != 0 {
			t.Fatalf("clean tick must emit nothing, got %v", rec.snapshot())
		}
	})

	t.Run("above-raises", func(t *testing.T) {
		m, _, vb := newMon()
		cfg := cfgWith(80, 70, false)
		setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
		m.evaluate()
		setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 6, 1))
		m.evaluate() // delta 1 ⇒ raise
		if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 1 {
			t.Fatalf("delta must raise events=1, got %+v", got)
		}
	})
}

// The r3 hysteresis cell: an active alarm with 2 clean ticks accumulated,
// then an id change ⇒ streak reset WITHOUT clear (no false credit — the
// clear still needs 3 fresh ticks after the rebase, and no CLEAR line may
// claim the exhaustion went away when it was the allocator that changed).
func TestExhaustionRebaseNoClearCredit9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 9, 1))
	m.evaluate() // raise
	setExhView9902(vb, cfg, 3, 1, exhPool9902("p1", 9, 1))
	m.evaluate() // clean 1
	setExhView9902(vb, cfg, 4, 1, exhPool9902("p1", 9, 1))
	m.evaluate() // clean 2 (streak 2)
	rec.reset()

	setExhView9902(vb, cfg, 5, 1, exhPool9902("p1", 9, 2))
	m.evaluate() // id change ⇒ streak reset, NO clear
	if got := activeExhaustion9902(t, m); len(got) != 1 {
		t.Fatalf("rebase must not clear the active alarm, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedClearedTag); got != 0 {
		t.Fatalf("rebase must not emit a clear, got %d", got)
	}

	// Two more clean ticks: streak is 2 again, still no clear (the
	// pre-rebase ticks were NOT credited — otherwise this would clear).
	setExhView9902(vb, cfg, 6, 1, exhPool9902("p1", 9, 2))
	m.evaluate()
	setExhView9902(vb, cfg, 7, 1, exhPool9902("p1", 9, 2))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 1 {
		t.Fatalf("2 post-rebase clean ticks must not clear, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedClearedTag); got != 0 {
		t.Fatalf("2 post-rebase clean ticks must not emit a clear, got %d", got)
	}

	// Third fresh tick: clear.
	setExhView9902(vb, cfg, 8, 1, exhPool9902("p1", 9, 2))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("3rd post-rebase clean tick must clear, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedClearedTag); got != 1 {
		t.Fatalf("clear must emit once, got %d", got)
	}
}

// A repeated status sequence means no new sample: the exhaustion pass must
// not advance at all (no raise/refresh, no streak credit).
func TestExhaustionSameSeqHolds9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate() // baseline at seq 1

	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 8, 1))
	m.evaluate() // same seq: skipped even though the count moved
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("same-seq tick must not raise, got %+v", got)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("same-seq tick must emit nothing, got %v", rec.snapshot())
	}

	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate() // fresh seq: the delta evaluates now
	if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 3 {
		t.Fatalf("fresh seq must raise events=3, got %+v", got)
	}

	// Same-seq clean ticks credit nothing toward the clear.
	rec.reset()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 1 {
		t.Fatalf("same-seq ticks must not clear, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedClearedTag); got != 0 {
		t.Fatalf("same-seq ticks must not emit a clear, got %d", got)
	}
}

// Synthetic (seq 0) views are never skipped — every existing monitor test
// builds seq-0 views, and the exhaustion pass must evaluate them.
func TestExhaustionZeroSeqAlwaysEvaluates9902(t *testing.T) {
	m, _, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, exhPool9902("p1", 5, 1)))
	m.evaluate()
	vb.set(coherentView(cfg, exhPool9902("p1", 6, 1)))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 1 {
		t.Fatalf("seq-0 views must evaluate, got %+v", got)
	}
}

// Eligible-but-absent ⇒ HOLD: no state change, no syslog.
func TestExhaustionAbsentHolds9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate() // raise
	rec.reset()

	setExhView9902(vb, cfg, 3, 1) // p1 absent
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 1 {
		t.Fatalf("absent sample must HOLD the alarm, got %+v", got)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("absent sample must emit nothing, got %v", rec.snapshot())
	}
}

// Removal retires the baseline AND clears with syslog; a re-add restarts
// silently (no phantom delta from the pre-removal baseline).
func TestExhaustionRemovalRetiresReaddSilent9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate() // raise
	rec.reset()

	// Unreference the pool: retire + clear.
	unref := cfgWith(80, 70, false)
	unref.Security.NAT.Source = nil
	setExhView9902(vb, unref, 3, 1, exhPool9902("p1", 8, 1))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("removal must clear the alarm, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedClearedTag); got != 1 {
		t.Fatalf("removal must emit one clear, got %d", got)
	}

	// Re-add with a HIGHER count: first-sighting silent, no phantom delta.
	rec.reset()
	setExhView9902(vb, cfg, 4, 1, exhPool9902("p1", 50, 1))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("re-add must restart silently, got %+v", got)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("re-add must emit nothing, got %v", rec.snapshot())
	}
}

// Removal of a never-raised pool drops its baseline-only record too (else
// the map grows unboundedly); the re-add is still silent.
func TestExhaustionBaselineOnlyPruned9902(t *testing.T) {
	m, _, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate() // baseline, never raised

	unref := cfgWith(80, 70, false)
	unref.Security.NAT.Source = nil
	setExhView9902(vb, unref, 2, 1, exhPool9902("p1", 5, 1))
	m.evaluate() // prune

	setExhView9902(vb, cfg, 3, 1, exhPool9902("p1", 50, 1))
	m.evaluate() // re-add: silent (a retained baseline would raise 45)
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("re-added pool must restart silently, got %+v", got)
	}
}

// Deterministic pools are watched for exhaustion (per-block fullness IS an
// allocator event) while staying inapplicable for utilization.
func TestExhaustionDeterministicWatched9902(t *testing.T) {
	m, rec, vb := newMon()
	detCfg := cfgWith(80, 70, true)
	setExhView9902(vb, detCfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate()
	setExhView9902(vb, detCfg, 2, 1, exhPool9902("p1", 9, 1))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 4 {
		t.Fatalf("deterministic pool must raise exhaustion events=4, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedRaisedTag); got != 1 {
		t.Fatalf("deterministic raise must emit once, got %d", got)
	}
	if len(m.ActiveAlarms()) != 0 {
		t.Fatalf("deterministic pool must not raise utilization, got %+v", m.ActiveAlarms())
	}
	if reason := m.InapplicableReason("p1"); !strings.Contains(reason, "cannot predict per-block exhaustion") {
		t.Fatalf("deterministic pool must be marked inapplicable, got %q", reason)
	}
}

// Address-only pools are watched for exhaustion (collision IS an allocator
// event) while staying inapplicable for utilization.
func TestExhaustionAddressOnlyWatched9902(t *testing.T) {
	m, _, vb := newMon()
	cfg := cfgWith(80, 70, false)
	cfg.Security.NAT.SourcePools["p1"].PortNoTranslation = true
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 6, 1))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 1 {
		t.Fatalf("address-only pool must raise exhaustion, got %+v", got)
	}
	if len(m.ActiveAlarms()) != 0 {
		t.Fatalf("address-only pool must not raise utilization, got %+v", m.ActiveAlarms())
	}
	if reason := m.InapplicableReason("p1"); reason == "" {
		t.Fatal("address-only pool must stay marked inapplicable")
	}
}

// Convert-to-deterministic still emits exactly ONE utilization clear (the
// #7361-era contract), and the exhaustion baseline survives the conversion.
func TestExhaustionDetConvertOneClear9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	vb.set(coherentView(cfg, PoolStatus{
		PoolName: "p1", AddressCount: 1, PortLow: 1, PortHigh: 100,
		UsedPorts: 95, ExhaustionTotal: 5, AllocatorID: 1,
	}))
	m.evaluate() // utilization raise + exhaustion baseline
	if len(m.ActiveAlarms()) != 1 {
		t.Fatal("precondition: utilization alarm should be raised")
	}
	rec.reset()

	vb.set(coherentView(cfgWith(80, 70, true), PoolStatus{
		PoolName: "p1", AddressCount: 1, PortLow: 1, PortHigh: 100,
		UsedPorts: 95, ExhaustionTotal: 5, AllocatorID: 1,
	}))
	m.evaluate()
	if len(m.ActiveAlarms()) != 0 {
		t.Fatal("convert-to-deterministic must clear utilization")
	}
	if got := countMatch(rec.snapshot(), clearedTag); got != 1 {
		t.Fatalf("det-convert must emit exactly 1 utilization clear, got %d", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedRaisedTag) + countMatch(rec.snapshot(), exhaustedClearedTag); got != 0 {
		t.Fatalf("det-convert must emit no exhaustion lines, got %d", got)
	}

	// The exhaustion baseline survived: a delta raises on the true delta.
	vb.set(coherentView(cfgWith(80, 70, true), PoolStatus{
		PoolName: "p1", AddressCount: 1, PortLow: 1, PortHigh: 100,
		UsedPorts: 95, ExhaustionTotal: 7, AllocatorID: 1,
	}))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 2 {
		t.Fatalf("post-convert delta must raise events=2, got %+v", got)
	}
}

// A class change that keeps the allocator (same id) neither retires nor
// rebases the exhaustion state.
func TestExhaustionClassChangeKeepsState9902(t *testing.T) {
	m, _, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate()

	addrOnly := cfgWith(80, 70, false)
	addrOnly.Security.NAT.SourcePools["p1"].PortNoTranslation = true
	setExhView9902(vb, addrOnly, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate() // same id across the class change ⇒ true delta
	if got := activeExhaustion9902(t, m); len(got) != 1 || got[0].Events != 3 {
		t.Fatalf("class change must not retire exhaustion state, got %+v", got)
	}
}

// Feature-disabled clears exhaustion alarms with syslog and retires the
// baselines (re-enable restarts silently).
func TestExhaustionDisableClears9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate() // raise
	rec.reset()

	disabled := cfgWith(80, 70, false)
	disabled.Security.NAT.PoolUtilizationAlarm = nil
	setExhView9902(vb, disabled, 3, 1, exhPool9902("p1", 8, 1))
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("disable must clear exhaustion alarms, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedClearedTag); got != 1 {
		t.Fatalf("disable must emit one exhaustion clear, got %d", got)
	}

	rec.reset()
	setExhView9902(vb, cfg, 4, 1, exhPool9902("p1", 50, 1))
	m.evaluate() // re-enable: silent re-baseline
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("re-enable must restart silently, got %+v", got)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("re-enable must emit nothing, got %v", rec.snapshot())
	}
}

// Nil config clears exhaustion alarms with syslog, like utilization.
func TestExhaustionNilConfigClears9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate() // raise
	rec.reset()

	vb.set(View{Config: nil, HelperCoherent: true, Available: true})
	m.evaluate()
	if got := activeExhaustion9902(t, m); len(got) != 0 {
		t.Fatalf("nil config must clear exhaustion alarms, got %+v", got)
	}
	if got := countMatch(rec.snapshot(), exhaustedClearedTag); got != 1 {
		t.Fatalf("nil config must emit one exhaustion clear, got %d", got)
	}
}

// !Available / !HelperCoherent HOLD exhaustion alarms without emission.
func TestExhaustionHoldPaths9902(t *testing.T) {
	for _, tc := range []struct {
		name string
		view func(cfg *config.Config) View
	}{
		{"unavailable", func(cfg *config.Config) View { return View{Available: false} }},
		{"incoherent", func(cfg *config.Config) View {
			return View{Config: cfg, Pools: map[string]PoolStatus{}, Available: true, HelperCoherent: false}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, rec, vb := newMon()
			cfg := cfgWith(80, 70, false)
			setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
			m.evaluate()
			setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
			m.evaluate() // raise
			rec.reset()

			vb.set(tc.view(cfg))
			m.evaluate()
			if got := activeExhaustion9902(t, m); len(got) != 1 {
				t.Fatalf("HOLD path must keep the alarm, got %+v", got)
			}
			if len(rec.snapshot()) != 0 {
				t.Fatalf("HOLD path must emit nothing, got %v", rec.snapshot())
			}
		})
	}
}

// Exhaustion syslog lines carry the raise/clear severities and the RT_NAT
// shape (formatter contract, mirroring utilization).
func TestExhaustionSeverityAndShape9902(t *testing.T) {
	m, rec, vb := newMon()
	cfg := cfgWith(80, 70, false)
	setExhView9902(vb, cfg, 1, 1, exhPool9902("p1", 5, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 2, 1, exhPool9902("p1", 8, 1))
	m.evaluate()
	lines := rec.snapshot()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if lines[0].sev != severityRaise {
		t.Fatalf("raise severity = %d, want %d", lines[0].sev, severityRaise)
	}
	if !strings.HasPrefix(lines[0].msg, "RT_NAT") ||
		!strings.Contains(lines[0].msg, "pool-name=\"p1\"") ||
		!strings.Contains(lines[0].msg, "events=3") {
		t.Fatalf("raise line shape wrong: %q", lines[0].msg)
	}

	rec.reset()
	setExhView9902(vb, cfg, 3, 1, exhPool9902("p1", 8, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 4, 1, exhPool9902("p1", 8, 1))
	m.evaluate()
	setExhView9902(vb, cfg, 5, 1, exhPool9902("p1", 8, 1))
	m.evaluate()
	lines = rec.snapshot()
	if len(lines) != 1 || lines[0].sev != severityClear {
		t.Fatalf("clear severity wrong: %+v", lines)
	}
	if !strings.Contains(lines[0].msg, exhaustedClearedTag) {
		t.Fatalf("clear line shape wrong: %q", lines[0].msg)
	}
}

func TestRenderExhaustionAlarmsDetail9902(t *testing.T) {
	alarms := []ActiveExhaustionAlarm{
		{PoolName: "p1", Events: 3, FirstSeen: time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC)},
		{PoolName: "p2", Events: 12},
	}
	var b strings.Builder
	got := RenderExhaustionAlarms(&b, alarms, 2, true)
	if got != 4 {
		t.Fatalf("count = %d, want 4", got)
	}
	out := b.String()
	if !strings.Contains(out, "Alarm 3:") || !strings.Contains(out, "Alarm 4:") {
		t.Fatalf("numbering wrong:\n%s", out)
	}
	if !strings.Contains(out, "Class: NAT") || !strings.Contains(out, "Severity: Minor") {
		t.Fatalf("class/severity wrong:\n%s", out)
	}
	if !strings.Contains(out, "NAT source pool p1 allocator-reported exhaustion events: 3 (most recent sample)") {
		t.Fatalf("p1 description wrong:\n%s", out)
	}
	if !strings.Contains(out, "First seen: 2026-06-20 01:02:03") {
		t.Fatalf("first-seen line missing:\n%s", out)
	}
	if strings.Count(out, "First seen:") != 1 {
		t.Fatalf("zero FirstSeen must omit the first-seen line:\n%s", out)
	}
}

func TestRenderExhaustionAlarmsSummary9902(t *testing.T) {
	alarms := []ActiveExhaustionAlarm{{PoolName: "p1", Events: 3}}
	var b strings.Builder
	got := RenderExhaustionAlarms(&b, alarms, 0, false)
	if got != 1 {
		t.Fatalf("summary count = %d, want 1", got)
	}
	if b.String() != "" {
		t.Fatalf("summary mode must write no body, got %q", b.String())
	}
}

func TestRenderExhaustionAlarmsEmpty9902(t *testing.T) {
	var b strings.Builder
	got := RenderExhaustionAlarms(&b, nil, 3, true)
	if got != 3 || b.String() != "" {
		t.Fatalf("empty alarms must not change count or write: count=%d out=%q", got, b.String())
	}
}
