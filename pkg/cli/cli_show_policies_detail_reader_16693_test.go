// #16693: the local `show security policies detail` view must build its
// policy-counter reader ONCE (one ReadAllPolicyCounters snapshot for the
// whole rendering), skip the snapshot entirely when nothing will be read,
// and surface the trailing #8177 stats-disabled note and #3408 read-failure
// warning the gRPC detail renderer prints.
//
// Before the fix, cliPolicyStats constructed NewPolicyCounterReader inside
// the per-policy call — one eager snapshot per policy, even with
// policy-stats off — and both call sites discarded the (statsDisabled,
// readErr) results, so neither trailing line ever appeared on the console.
//
// FAIL-ON-REVERT: restoring the per-policy construction makes
// TestCLIShowPoliciesDetailSingleSnapshot16693 see bulkCalls == P instead of
// 1; restoring it without the anyPolicyNeedsCounterRead gate also makes the
// stats-off cell see a snapshot; dropping the accumulators / trailing prints
// makes the note and warning cells go RED.
package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// countingBulkCLIDP is a loaded cliRuntime whose bulk snapshot counts how
// many times it was taken and whose per-policy fallback records a poison
// call. bulkErr, when set, is returned by every read (bulk failure or
// fallback failure alike) so the #3408 warning path is exercised.
type countingBulkCLIDP struct {
	*dataplane.Manager
	bulk      map[uint32]dataplane.CounterValue
	bulkErr   error
	bulkCalls *int
	perCalls  *int
}

func (d *countingBulkCLIDP) IsLoaded() bool { return true }

func (d *countingBulkCLIDP) ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error) {
	*d.bulkCalls++
	if d.bulkErr != nil {
		return nil, d.bulkErr
	}
	return d.bulk, nil
}

func (d *countingBulkCLIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	*d.perCalls++
	if d.bulkErr != nil {
		return dataplane.CounterValue{}, d.bulkErr
	}
	return dataplane.CounterValue{Packets: 7, Bytes: 700}, nil
}

// fallbackOnlyCLIDP has NO bulk method, so NewPolicyCounterReader must
// return the per-policy fallback unchanged (non-bulk / retired-eBPF shape).
type fallbackOnlyCLIDP struct {
	*dataplane.Manager
	err   error
	calls *int
}

func (d *fallbackOnlyCLIDP) IsLoaded() bool { return true }

func (d *fallbackOnlyCLIDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	*d.calls++
	if d.err != nil {
		return dataplane.CounterValue{}, d.err
	}
	return dataplane.CounterValue{Packets: 7, Bytes: 700}, nil
}

// detailConfig16693 builds a config with n zone-pair policies plus one
// global policy. countIdx marks indices carrying `count` (-1 = none).
func detailConfig16693(statsEnabled bool, n int, countIdx map[int]bool, globalCount bool) *config.Config {
	cfg := &config.Config{}
	cfg.Security.PolicyStatsEnabled = statsEnabled
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"}, "untrust": {Name: "untrust"},
	}
	pols := make([]*config.Policy, 0, n)
	for i := range n {
		pols = append(pols, &config.Policy{
			Name:  fmt.Sprintf("pol-%d", i),
			Count: countIdx[i],
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"junos-http"},
			},
		})
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust", ToZone: "untrust", Policies: pols,
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:  "global-pol",
		Count: globalCount,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"junos-http"},
		},
	}}
	return cfg
}

const statsDisabledNote16693 = "policy count(s) read 0 because policy-stats is disabled"

func TestCLIShowPoliciesDetailSingleSnapshot16693(t *testing.T) {
	const p = 100
	cfg := detailConfig16693(true, p, nil, false)
	bulk := make(map[uint32]dataplane.CounterValue, p+1)
	for i := range p {
		bulk[uint32(i)] = dataplane.CounterValue{Packets: uint64(1000 + i), Bytes: uint64(2000 + i)}
	}
	// Global policies live in the set after the single zone-pair set:
	// PolicyCounterID(1, 0) = 1*MaxRulesPerPolicy (256).
	bulk[256] = dataplane.CounterValue{Packets: 9001, Bytes: 9002}
	bulkCalls, perCalls := 0, 0
	c := &CLI{dp: &countingBulkCLIDP{
		Manager:   dataplane.New(),
		bulk:      bulk,
		bulkCalls: &bulkCalls,
		perCalls:  &perCalls,
	}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	if bulkCalls != 1 {
		t.Fatalf("ReadAllPolicyCounters called %d times for P=%d detail view; want exactly 1", bulkCalls, p)
	}
	if perCalls != 0 {
		t.Fatalf("per-policy ReadPolicyCounters called %d times; want 0 (bulk reader must serve every policy)", perCalls)
	}
	// Values must come from the single snapshot, for zone-pair and global.
	if !strings.Contains(out, "1000 packets, 2000 bytes") {
		t.Errorf("detail missing first policy bulk counters:\n%s", out)
	}
	if !strings.Contains(out, "1099 packets, 2099 bytes") {
		t.Errorf("detail missing last policy bulk counters")
	}
	if !strings.Contains(out, "9001 packets, 9002 bytes") {
		t.Errorf("detail missing global policy bulk counters")
	}
	if strings.Contains(out, statsDisabledNote16693) {
		t.Errorf("stats-enabled detail must not print the stats-disabled note:\n%s", out)
	}
	if strings.Contains(out, "warning: policy counter read failed") {
		t.Errorf("clean detail must not print the read-failure warning:\n%s", out)
	}
}

// Positive control (hit-count): the sibling surface already took exactly
// one snapshot before #16693 and must keep doing so.
func TestCLIShowPoliciesHitCountSingleSnapshot16693Control(t *testing.T) {
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	bulkCalls, perCalls := 0, 0
	c := &CLI{store: store, dp: &countingBulkCLIDP{
		Manager: dataplane.New(),
		bulk: map[uint32]dataplane.CounterValue{
			0:                                 {Packets: 42, Bytes: 4242},
			dataplane.DefaultPolicySentinelID: {Packets: 99, Bytes: 9900},
		},
		bulkCalls: &bulkCalls,
		perCalls:  &perCalls,
	}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesHitCount(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesHitCount: %v", err)
		}
	})
	if bulkCalls != 1 {
		t.Fatalf("hit-count ReadAllPolicyCounters = %d; want 1", bulkCalls)
	}
	if perCalls != 0 {
		t.Fatalf("hit-count per-policy calls = %d; want 0", perCalls)
	}
	if row := rowContaining(out, "allow-web"); !strings.Contains(row, "42") {
		t.Fatalf("hit-count allow-web row = %q; want bulk 42", row)
	}
}

func TestCLIShowPoliciesDetailNoSnapshotWhenStatsOff16693(t *testing.T) {
	cfg := detailConfig16693(false, 5, nil, false)
	bulkCalls, perCalls := 0, 0
	c := &CLI{dp: &countingBulkCLIDP{
		Manager:   dataplane.New(),
		bulk:      map[uint32]dataplane.CounterValue{},
		bulkCalls: &bulkCalls,
		perCalls:  &perCalls,
	}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	if bulkCalls != 0 {
		t.Fatalf("stats-off detail took %d snapshots; want 0 (nothing is read)", bulkCalls)
	}
	if perCalls != 0 {
		t.Fatalf("stats-off detail made %d per-policy reads; want 0", perCalls)
	}
	// 5 zone-pair + 1 global, all unread: the #8177 note counts all six.
	want := "note: 6 policy count(s) read 0 because policy-stats is disabled " +
		"system-wide, not because no traffic matched (enable with " +
		"`set security policy-stats system-wide enable`, or add `count` to an " +
		"individual policy)"
	if !strings.Contains(out, want) {
		t.Fatalf("stats-off detail missing byte-identical #8177 note %q:\n%s", want, out)
	}
	if strings.Contains(out, "Session statistics:") {
		t.Errorf("stats-off detail must not render a Session statistics block:\n%s", out)
	}
}

func TestCLIShowPoliciesDetailCountPolicyReadsWhenStatsOff16693(t *testing.T) {
	// Mixed: stats off, pol-1 carries `count` -> exactly one snapshot, the
	// counted policy renders live stats, and the other five are noted.
	cfg := detailConfig16693(false, 5, map[int]bool{1: true}, false)
	bulkCalls, perCalls := 0, 0
	c := &CLI{dp: &countingBulkCLIDP{
		Manager: dataplane.New(),
		bulk: map[uint32]dataplane.CounterValue{
			1: {Packets: 55, Bytes: 5500},
		},
		bulkCalls: &bulkCalls,
		perCalls:  &perCalls,
	}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	if bulkCalls != 1 {
		t.Fatalf("mixed detail ReadAllPolicyCounters = %d; want 1", bulkCalls)
	}
	if !strings.Contains(out, "55 packets, 5500 bytes") {
		t.Errorf("counted policy live statistics missing:\n%s", out)
	}
	if !strings.Contains(out, "note: 5 policy count(s) read 0") {
		t.Errorf("mixed detail note must count the 5 unread policies (4 zone-pair + global):\n%s", out)
	}
}

func TestCLIShowPoliciesDetailWarnsOnBulkReadFailure16693(t *testing.T) {
	cfg := detailConfig16693(true, 3, nil, false)
	bulkCalls, perCalls := 0, 0
	c := &CLI{dp: &countingBulkCLIDP{
		Manager:   dataplane.New(),
		bulkErr:   errors.New("counter bridge degraded"),
		bulkCalls: &bulkCalls,
		perCalls:  &perCalls,
	}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	if bulkCalls != 1 {
		t.Fatalf("failing detail ReadAllPolicyCounters = %d; want 1", bulkCalls)
	}
	want := "warning: policy counter read failed (session statistics may be incomplete): counter bridge degraded"
	if !strings.Contains(out, want) {
		t.Fatalf("detail missing #3408 warning %q:\n%s", want, out)
	}
	if strings.Contains(out, statsDisabledNote16693) {
		t.Errorf("read-failure detail must not also print the stats-disabled note:\n%s", out)
	}
}

func TestCLIShowPoliciesDetailWarnsOnFallbackReadFailure16693(t *testing.T) {
	// Non-bulk dataplane: the per-policy fallback errors. Reachable only
	// here, because the userspace bulk reader never errors per policy.
	cfg := detailConfig16693(true, 3, nil, false)
	calls := 0
	c := &CLI{dp: &fallbackOnlyCLIDP{
		Manager: dataplane.New(),
		err:     errors.New("counter bridge degraded"),
		calls:   &calls,
	}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	if calls == 0 {
		t.Fatalf("fallback dataplane was never read; the warning cell would pass vacuously")
	}
	want := "warning: policy counter read failed (session statistics may be incomplete): counter bridge degraded"
	if !strings.Contains(out, want) {
		t.Fatalf("fallback detail missing #3408 warning %q:\n%s", want, out)
	}
}

func TestCLIShowPoliciesDetailFallbackValues16693(t *testing.T) {
	// Non-bulk fallback still renders its values through the single
	// prebuilt reader (fallback returned unchanged by NewPolicyCounterReader).
	cfg := detailConfig16693(true, 2, nil, false)
	calls := 0
	c := &CLI{dp: &fallbackOnlyCLIDP{Manager: dataplane.New(), calls: &calls}}
	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})
	if !strings.Contains(out, "7 packets, 700 bytes") {
		t.Errorf("fallback detail missing per-policy counters:\n%s", out)
	}
	// 2 zone-pair + 1 global, each read via the fallback.
	if calls != 3 {
		t.Fatalf("fallback reads = %d; want 3 (one per rendered policy)", calls)
	}
}
