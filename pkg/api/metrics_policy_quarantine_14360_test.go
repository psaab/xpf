package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #14360: collectPolicyCounters ignored zone quarantine. A quarantined
// (scrubbed, unpublished) zone-pair rule returned
// ErrPolicyCounterUnpublished from the bulk reader, so every scrape bumped
// xpf_policy_counters_unpublished_rules — the #7567 publication-failure
// alert gauge — for a routine operator-initiated state, masking genuine
// failures. A mixed-scope global ([quarantined, trust] -> untrust) that
// survives for its live members was labelled with the authored unpruned
// set, and a wholly-quarantined global was likewise counted unpublished.
//
// Mirror REST (security.go pruneQuarantinedScope /
// ScopedGlobalQuarantineDropped) and the runtime scrub
// (scrubPoliciesForQuarantinedZones): skip wholly-quarantined zone-pairs
// and wholly-dropped globals WITHOUT unpublished++, and prune
// quarantined members from the surviving global's scope labels.
//
// FAIL-ON-REVERT: removing the quarantine skips/prune makes the
// unpublished gauge count the scrubbed rules too (see the warmup
// companion test) and the mixed global label "trust z214" instead of
// "trust".

func TestCollectPolicyCountersQuarantine14360(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	// Quarantine fixture: z214 loses the StableZoneID collision to z174.
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"if-trust"}},
		"untrust": {Name: "untrust", Interfaces: []string{"if-untrust"}},
		"z174":    {Name: "z174", Interfaces: []string{"if-survivor"}},
		"z214":    {Name: "z214", Interfaces: []string{"if-quarantined"}},
	}
	if config.ZoneQuarantineExcludedReason("z214", cfg) == "" {
		t.Fatal("fixture does not quarantine z214")
	}
	if config.ZoneQuarantineExcludedReason("trust", cfg) != "" ||
		config.ZoneQuarantineExcludedReason("z174", cfg) != "" {
		t.Fatal("fixture quarantines a survivor/control zone")
	}
	cfg.Security.PolicyStatsEnabled = true
	// Zone-pair sets: [0]=descriptor-coverage trust->untrust allow,
	// [1]=quarantined trust->z214, [2]=ordinary trust->untrust control.
	cfg.Security.Policies = append(cfg.Security.Policies,
		&config.ZonePairPolicies{FromZone: "trust", ToZone: "z214", Policies: []*config.Policy{
			{Name: "quarantined-pair", Action: config.PolicyPermit, Count: true},
		}},
		&config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			{Name: "ordinary-pair", Action: config.PolicyPermit, Count: true},
		}},
	)
	// Globals continue after all zone-pair sets. Replace the coverage g1
	// with the quarantine matrix: mixed survives pruned, dead is wholly
	// quarantined on its from side.
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name: "mixed-global", Action: config.PolicyDeny, Count: true,
			Match: config.PolicyMatch{FromZones: []string{"z214", "trust"}, ToZones: []string{"untrust"}},
		},
		{
			Name: "dead-global", Action: config.PolicyDeny, Count: true,
			Match: config.PolicyMatch{FromZones: []string{"z214"}, ToZones: []string{"untrust"}},
		},
	}

	// Counter IDs: policySetID is the zone-pair set index; globals start
	// after the last set. Seed readable counters for the live rules and
	// deliberately for the scrubbed rules too — the per-policy fallback
	// (schedulerCounterAPIDP has no bulk snapshot, so
	// NewPolicyCounterReader returns it unchanged) returns the seeded
	// value with nil error for every ID, including scrubbed ones. That
	// models the stale-survivor window for labels and proves the skip
	// is by quarantine, not by read failure: if the collector reads a
	// scrubbed rule it would emit a series, so a pass cannot come from
	// an unread zero.
	nSets := uint32(len(cfg.Security.Policies))
	quarantinedPairID := policyCounterID(1, 0)
	ordinaryPairID := policyCounterID(2, 0)
	mixedGlobalID := policyCounterID(nSets, 0)
	deadGlobalID := policyCounterID(nSets, 1)
	dp := &schedulerCounterAPIDP{
		Manager: dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{
			quarantinedPairID: {Packets: 99, Bytes: 9900},
			ordinaryPairID:    {Packets: 11, Bytes: 1100},
			mixedGlobalID:     {Packets: 42, Bytes: 4200},
			deadGlobalID:      {Packets: 77, Bytes: 7700},
			// Default-policy sentinel is read only under statsEnabled;
			// seed it so the control scrape is fully published.
			dataplane.DefaultPolicySentinelID: {Packets: 5, Bytes: 500},
		},
	}

	c := &xpfCollector{srv: &Server{store: store}}
	c.initPolicyDescriptors()
	c.policyHitsTotal = prometheus.NewDesc(
		"xpf_policy_hits_total", "policy hits",
		[]string{"from_zone", "to_zone", "policy_name"}, nil)

	ch := make(chan prometheus.Metric, 64)
	c.collectPolicyCounters(ch, dp)
	close(ch)
	var got []prometheus.Metric
	unpublished := -1.0
	for m := range ch {
		got = append(got, m)
		if descFQName(m.Desc().String()) == "xpf_policy_counters_unpublished_rules" {
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatalf("write gauge: %v", err)
			}
			unpublished = pb.GetGauge().GetValue()
		}
	}

	// Every seeded live rule is published, so nothing may count as
	// unpublished. Pre-fix the scrubbed rules' reads also succeed via
	// this fake (nil error), so the gauge alone is NOT the RED signal
	// here — the label/series assertions below are. The gauge assertion
	// still pins the contract with the unpublished fake in the
	// companion sub-check via warmup DP (below).
	if unpublished != 0 {
		t.Errorf("xpf_policy_counters_unpublished_rules = %v, want 0", unpublished)
	}
	if c.counterReadErrors.Load() != 0 {
		t.Errorf("counterReadErrors = %d, want 0", c.counterReadErrors.Load())
	}

	// Ordinary zone-pair control still emits with authored labels.
	assertCounterClose(t, got, c.policyHitsTotal, map[string]string{
		"from_zone": "trust", "to_zone": "untrust", "policy_name": "ordinary-pair",
	}, 11)
	// Mixed global survives with PRUNED scope: "trust", not "trust z214"
	// (authored order z214,trust; pruned sorted label is "trust").
	assertCounterClose(t, got, c.policyHitsTotal, map[string]string{
		"from_zone": "trust", "to_zone": "untrust", "policy_name": "mixed-global",
	}, 42)

	// No series may carry the quarantined zone or a scrubbed rule name.
	for _, m := range got {
		if m.Desc() != c.policyHitsTotal {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		labels := map[string]string{}
		for _, l := range pb.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["policy_name"] == "quarantined-pair" || labels["policy_name"] == "dead-global" {
			t.Errorf("scrubbed rule emitted a series: %v", labels)
		}
		if labels["from_zone"] == "z214" || labels["to_zone"] == "z214" ||
			labels["from_zone"] == "trust z214" || labels["from_zone"] == "z214 trust" {
			t.Errorf("quarantined zone leaked into labels: %v", labels)
		}
	}
}

// TestCollectPolicyCountersQuarantineUnpublishedGauge14360 pins the
// alert-gauge half with a DP that publishes NOTHING (warmup bulk
// snapshot): live rules count unpublished, scrubbed rules must not.
// Pre-fix gauge = live (coverage pair + ordinary + mixed + default) +
// scrubbed (quarantined-pair + dead-global); post-fix only live count.
func TestCollectPolicyCountersQuarantineUnpublishedGauge14360(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"if-trust"}},
		"untrust": {Name: "untrust", Interfaces: []string{"if-untrust"}},
		"z174":    {Name: "z174", Interfaces: []string{"if-survivor"}},
		"z214":    {Name: "z214", Interfaces: []string{"if-quarantined"}},
	}
	cfg.Security.PolicyStatsEnabled = true
	cfg.Security.Policies = append(cfg.Security.Policies,
		&config.ZonePairPolicies{FromZone: "trust", ToZone: "z214", Policies: []*config.Policy{
			{Name: "quarantined-pair", Action: config.PolicyPermit, Count: true},
		}},
		&config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			{Name: "ordinary-pair", Action: config.PolicyPermit, Count: true},
		}},
	)
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name: "mixed-global", Action: config.PolicyDeny, Count: true,
			Match: config.PolicyMatch{FromZones: []string{"z214", "trust"}, ToZones: []string{"untrust"}},
		},
		{
			Name: "dead-global", Action: config.PolicyDeny, Count: true,
			Match: config.PolicyMatch{FromZones: []string{"z214"}, ToZones: []string{"untrust"}},
		},
	}

	c := newCollector(&Server{store: store})
	dp := &warmupPolicyAPIDP{Manager: dataplane.New()}

	ch := make(chan prometheus.Metric, 64)
	c.collectPolicyCounters(ch, dp)
	close(ch)
	unpublished := -1.0
	hits := 0
	for m := range ch {
		switch descFQName(m.Desc().String()) {
		case "xpf_policy_hits_total":
			hits++
		case "xpf_policy_counters_unpublished_rules":
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatalf("write gauge: %v", err)
			}
			unpublished = pb.GetGauge().GetValue()
		}
	}
	if hits != 0 {
		t.Errorf("hits = %d, want 0 with an empty bulk snapshot", hits)
	}
	// Live counter-eligible rules: coverage zone-pair allow (set 0),
	// ordinary-pair, mixed-global, and the implicit default-policy row
	// = 4. Scrubbed quarantined-pair and dead-global must NOT count.
	if unpublished != 4 {
		t.Errorf("xpf_policy_counters_unpublished_rules = %v, want 4 (live rules only; quarantined-pair + dead-global excluded)", unpublished)
	}
	if c.counterReadErrors.Load() != 0 {
		t.Errorf("counterReadErrors = %d, want 0", c.counterReadErrors.Load())
	}
}
