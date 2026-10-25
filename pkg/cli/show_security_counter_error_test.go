// #3345: the text `show security screen` / `show security alarms` commands
// must print a warning when a global-counter read fails, rather than printing
// a clean "Total screen drops: 0" / "No security alarms" that hides a degraded
// counter bridge.
//
// FAIL-ON-REVERT: restoring `v, _ := c.dp.ReadGlobalCounter(idx)` (dropping
// the readErr capture + the warning print) makes both commands emit the clean
// zero output with no warning and the want-"warning" assertions go RED.
package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// counterErrCLIDP is a loaded cliRuntime whose global-counter reads fail.
type counterErrCLIDP struct {
	dataplane.DataPlane
}

func (d *counterErrCLIDP) IsLoaded() bool { return true }

func (d *counterErrCLIDP) ReadGlobalCounter(uint32) (uint64, error) {
	return 0, errors.New("counter bridge degraded")
}

// lateCounterErrCLIDP fails ONLY a LATE read (a per-type screen counter that
// is read after the leading screen-drops total / the global-stats loop), while
// returning a non-zero GlobalCtrScreenDrops so the per-type breakdown loop is
// entered. It models the early-warn/late-read ordering bug: an error check
// placed before the late read would pass, printing a stale 0 with no warning.
type lateCounterErrCLIDP struct {
	dataplane.DataPlane
}

func (d *lateCounterErrCLIDP) IsLoaded() bool { return true }

func (d *lateCounterErrCLIDP) ReadGlobalCounter(idx uint32) (uint64, error) {
	switch idx {
	case dataplane.GlobalCtrScreenSynFlood:
		return 0, errors.New("counter bridge degraded (late read)")
	case dataplane.GlobalCtrScreenDrops:
		return 5, nil // non-zero -> the per-type breakdown loop runs
	}
	return 0, nil
}

func (d *lateCounterErrCLIDP) SessionCount() (int, int)          { return 0, 0 }
func (d *lateCounterErrCLIDP) GetMapStats() []dataplane.MapStats { return nil }

// natCounterErrCLIDP fails ReadGlobalCounter and stubs the session iterators
// that showNATSource walks before reading the NAT alloc-fail counter.
type natCounterErrCLIDP struct {
	dataplane.DataPlane
}

func (d *natCounterErrCLIDP) IsLoaded() bool { return true }

func (d *natCounterErrCLIDP) ReadGlobalCounter(uint32) (uint64, error) {
	return 0, errors.New("counter bridge degraded")
}

func (d *natCounterErrCLIDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}

func (d *natCounterErrCLIDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

// screenProfileStore commits a config with a screen profile + zone so that
// showScreen reaches the per-type counter section (it returns early when no
// screen profiles are configured).
func screenProfileStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range []string{
		"set security screen ids-option untrust-screen icmp flood threshold 1000",
		"set security zones security-zone untrust screen untrust-screen",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestShowScreenWarnsOnCounterReadError(t *testing.T) {
	c := &CLI{store: screenProfileStore(t), dp: &counterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showScreen(); err != nil {
			t.Fatalf("showScreen() error = %v", err)
		}
	})

	// The total line may still print its (possibly 0) value, but the trailing
	// warning is what makes a degraded read distinguishable from a true zero.
	if !strings.Contains(out, "warning") {
		t.Fatalf("showScreen output lacks a counter-read warning; got:\n%s", out)
	}
}

func TestShowSecurityAlarmsWarnsOnCounterReadError(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")), dp: &counterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showSecurityAlarms(nil); err != nil {
			t.Fatalf("showSecurityAlarms() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showSecurityAlarms output lacks a counter-read warning; got:\n%s", out)
	}
}

// showStatistics / showFlowStatistics are the canonical operator global-counter
// views (`show security flow statistics`). Both must warn on a degraded read.
func TestShowStatisticsWarnsOnCounterReadError(t *testing.T) {
	c := &CLI{dp: &counterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showStatistics(false); err != nil {
			t.Fatalf("showStatistics() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showStatistics output lacks a counter-read warning; got:\n%s", out)
	}
}

func TestShowFlowStatisticsWarnsOnCounterReadError(t *testing.T) {
	c := &CLI{dp: &counterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showFlowStatistics(); err != nil {
			t.Fatalf("showFlowStatistics() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showFlowStatistics output lacks a counter-read warning; got:\n%s", out)
	}
}

// The following three tests pin the early-warn/late-read ORDERING fix: the
// warning must be checked AFTER all global-counter reads, so a failure on a
// LATE read (per-type screen breakdown) is surfaced rather than printing a
// stale 0 under an earlier passed check. Each FAILS if the readErr check is
// moved before the late read.
func TestShowScreenWarnsOnLateCounterReadError(t *testing.T) {
	c := &CLI{store: screenProfileStore(t), dp: &lateCounterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showScreen(); err != nil {
			t.Fatalf("showScreen() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showScreen lacks a warning on a LATE counter-read failure "+
			"(early-warn/late-read ordering); got:\n%s", out)
	}
}

func TestShowStatisticsDetailWarnsOnLateCounterReadError(t *testing.T) {
	c := &CLI{dp: &lateCounterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showStatistics(true); err != nil {
			t.Fatalf("showStatistics(detail) error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showStatistics(detail) lacks a warning on a LATE counter-read "+
			"failure (early-warn/late-read ordering); got:\n%s", out)
	}
}

func TestShowFlowStatisticsWarnsOnLateCounterReadError(t *testing.T) {
	c := &CLI{dp: &lateCounterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showFlowStatistics(); err != nil {
			t.Fatalf("showFlowStatistics() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showFlowStatistics lacks a warning on a LATE counter-read "+
			"failure (early-warn/late-read ordering); got:\n%s", out)
	}
}

func TestShowChassisClusterFabricStatisticsWarnsOnCounterReadError(t *testing.T) {
	c := &CLI{dp: &counterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showChassisClusterFabricStatistics(); err != nil {
			t.Fatalf("showChassisClusterFabricStatistics() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showChassisClusterFabricStatistics output lacks a counter-read warning; got:\n%s", out)
	}
}

// policyCounterErrCLIDP is a loaded cliRuntime whose per-policy counter reads
// fail.
type policyCounterErrCLIDP struct {
	dataplane.DataPlane
}

func (d *policyCounterErrCLIDP) IsLoaded() bool { return true }

func (d *policyCounterErrCLIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

// #3408: the CLI `show security policies hit-count` table must warn on a
// per-policy counter read failure rather than printing clean-zero counts.
func TestShowPoliciesHitCountWarnsOnCounterReadError(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true) // policy-stats enabled
	c := &CLI{store: store, dp: &policyCounterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showPoliciesHitCount(store.ActiveConfig(), "", ""); err != nil {
			t.Fatalf("showPoliciesHitCount() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showPoliciesHitCount lacks a counter-read warning; got:\n%s", out)
	}
}

// textErrCLIDP fails per-zone / per-policy / filter / flood reads (filter
// config read succeeds so the per-term read is reached) and supplies an apply
// result so zone/flood/filter renderers resolve their IDs.
type textErrCLIDP struct {
	dataplane.DataPlane
	apply *dataplane.ApplyResult
}

func (d *textErrCLIDP) IsLoaded() bool                          { return true }
func (d *textErrCLIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *textErrCLIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}
func (d *textErrCLIDP) ReadZoneCounters(uint32, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}
func (d *textErrCLIDP) ReadFloodCounters(uint32) (dataplane.FloodState, error) {
	return dataplane.FloodState{}, errors.New("counter bridge degraded")
}
func (d *textErrCLIDP) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{RuleStart: 0}, nil
}
func (d *textErrCLIDP) ReadFilterCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("counter bridge degraded")
}

func TestShowPoliciesBriefWarnsOnCounterReadError(t *testing.T) {
	c := &CLI{store: newPolicyHitCountCLIStore(t, true), dp: &textErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies", "brief"}); err != nil {
			t.Fatalf("handleShowSecurity(policies brief) error = %v", err)
		}
	})
	if !strings.Contains(out, "warning") {
		t.Fatalf("policies brief lacks a counter-read warning; got:\n%s", out)
	}
}

func TestShowZonesDisplayWarnsOnCounterReadError(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true) // has trust/untrust zones
	c := &CLI{store: store, dp: &textErrCLIDP{
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1, "untrust": 2}},
	}}

	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(store.ActiveConfig(), false, ""); err != nil {
			t.Fatalf("showZonesDisplay() error = %v", err)
		}
	})
	if !strings.Contains(out, "warning") {
		t.Fatalf("showZonesDisplay lacks a zone counter-read warning; got:\n%s", out)
	}
}

func TestShowFirewallFiltersWarnsOnCounterReadError(t *testing.T) {
	store := newFirewallFilterTestStore(t)
	c := &CLI{store: store, dp: &textErrCLIDP{
		apply: &dataplane.ApplyResult{FilterIDs: map[string]uint32{
			"inet:bandwidth-output": 0, "inet6:bandwidth-output": 100,
		}},
	}}

	out := captureStdout(t, func() {
		if err := c.showFirewallFilters(); err != nil {
			t.Fatalf("showFirewallFilters() error = %v", err)
		}
	})
	if !strings.Contains(out, "warning") {
		t.Fatalf("showFirewallFilters lacks a filter counter-read warning; got:\n%s", out)
	}
}

func TestShowScreenStatisticsAllWarnsOnCounterReadError(t *testing.T) {
	store := screenProfileStore(t) // has untrust zone + screen profile
	c := &CLI{store: store, dp: &textErrCLIDP{
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"untrust": 1}},
	}}

	out := captureStdout(t, func() {
		if err := c.showScreenStatisticsAll(); err != nil {
			t.Fatalf("showScreenStatisticsAll() error = %v", err)
		}
	})
	if !strings.Contains(out, "warning") {
		t.Fatalf("showScreenStatisticsAll lacks a flood counter-read warning; got:\n%s", out)
	}
}

// partialFloodErrCLIDP succeeds the flood-counter read for one zone (ID 1) and
// fails it for another (ID 2), modelling the #3344 partial-failure case.
type partialFloodErrCLIDP struct {
	dataplane.DataPlane
	apply *dataplane.ApplyResult
}

func (d *partialFloodErrCLIDP) IsLoaded() bool                          { return true }
func (d *partialFloodErrCLIDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *partialFloodErrCLIDP) ReadFloodCounters(zoneID uint32) (dataplane.FloodState, error) {
	if zoneID == 2 {
		return dataplane.FloodState{}, errors.New("counter bridge degraded")
	}
	return dataplane.FloodState{SynCount: 7}, nil
}

// #3344: `show security screen-statistics all` must NOT silently drop a zone
// whose flood-counter read fails — it must emit a per-zone error row naming the
// affected zone (the good zone still renders normally).
//
// FAIL-ON-REVERT: restoring the bare `continue` (no per-zone row) removes the
// "Screen statistics for zone 'untrust'" header for the failing zone, so the
// want-header assertion goes RED. The good zone "trust" still renders, and the
// trailing #3408 aggregate warning still prints, so neither alone proves the
// per-zone surfacing.
func TestShowScreenStatisticsAllSurfacesPerZoneReadError(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true) // trust + untrust zones
	c := &CLI{store: store, dp: &partialFloodErrCLIDP{
		apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 1, "untrust": 2}},
	}}

	out := captureStdout(t, func() {
		if err := c.showScreenStatisticsAll(); err != nil {
			t.Fatalf("showScreenStatisticsAll() error = %v", err)
		}
	})

	// Good zone renders normally.
	if !strings.Contains(out, "Screen statistics for zone 'trust':") {
		t.Fatalf("good zone 'trust' missing from output; got:\n%s", out)
	}
	// Failing zone is NOT dropped — it appears with an explicit error row.
	if !strings.Contains(out, "Screen statistics for zone 'untrust':") {
		t.Fatalf("failing zone 'untrust' silently dropped (no per-zone row); got:\n%s", out)
	}
	if !strings.Contains(out, "Error reading flood counters") {
		t.Fatalf("failing zone lacks an inline 'Error reading flood counters' row; got:\n%s", out)
	}
	// The #3408 aggregate degraded flag is retained.
	if !strings.Contains(out, "warning") {
		t.Fatalf("output lacks the trailing aggregate counter-read warning; got:\n%s", out)
	}
}

// showNATSource previously OMITTED the NAT alloc-fail line on a read error
// (acceptable — no stale 0 — but indistinguishable from "no failures"). It now
// emits an explicit warning. FAIL-ON-REVERT: dropping the else branch removes
// the warning line.
func TestShowNATSourceWarnsOnCounterReadError(t *testing.T) {
	c := &CLI{dp: &natCounterErrCLIDP{}}

	out := captureStdout(t, func() {
		if err := c.showNATSource(nil, nil); err != nil {
			t.Fatalf("showNATSource() error = %v", err)
		}
	})

	if !strings.Contains(out, "warning") {
		t.Fatalf("showNATSource output lacks a NAT alloc-fail counter-read warning; got:\n%s", out)
	}
}
