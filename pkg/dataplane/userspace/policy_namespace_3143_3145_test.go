package userspace

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// multiAppExpansionConfig builds a config whose first policy matches an
// application-set "web-apps" expanding to two applications (junos-http,
// junos-https), followed by a single-application policy "allow-ssh", plus a
// global policy. This is the case the per-policy counter path got wrong before
// the regression was reverted: the helper aggregates the expanded rules under
// one stable RuleID per policy name, and the counter READ callers identify a
// policy by its SLICE index in zpp.Policies, not by the dataplane snapshot's
// span-accumulated PolicyID.
func multiAppExpansionConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"web-apps": {
			Name:         "web-apps",
			Applications: []string{"junos-http", "junos-https"},
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{
			{
				Name:   "allow-web",
				Match:  config.PolicyMatch{Applications: []string{"web-apps"}},
				Action: config.PolicyPermit,
			},
			{
				Name:   "allow-ssh",
				Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
				Action: config.PolicyPermit,
			},
		},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:   "global-allow",
		Match:  config.PolicyMatch{Applications: []string{"web-apps"}},
		Action: config.PolicyPermit,
	}}
	return cfg
}

// callerCounterID mirrors EXACTLY how every production per-policy hit-count
// reader (pkg/api/metrics_counters.go policyCounterID, pkg/api/security.go,
// pkg/cli/cli_show_security*.go, pkg/grpcapi/server_show_*.go) builds the
// numeric handle it passes to ReadPolicyCounters: policySetID*MaxRulesPerPolicy
// plus the policy's raw SLICE index in zpp.Policies. The counter resolver must
// agree with this handle — NOT with the span-accumulated dataplane snapshot
// PolicyID.
func callerCounterID(policySetID uint32, sliceIndex int) uint32 {
	return PolicyCounterID(policySetID, uint32(sliceIndex))
}

// Test_3143_CounterResolutionMatchesSliceIndexCallers verifies that the counter
// resolver decodes the SLICE-INDEX handle the production callers pass, so a
// policy that follows a multi-application policy resolves to its OWN stable rule
// ID. The bug guarded against is a span-accumulated resolver: it would map the
// caller's slice-index handle into the PRECEDING (expanded) policy's span and
// return the preceding policy's name. Restoring that span-accumulated resolver
// makes the allow-ssh assertion below resolve to allow-web → RED.
func Test_3143_CounterResolutionMatchesSliceIndexCallers(t *testing.T) {
	cfg := multiAppExpansionConfig()

	// allow-web is slice index 0, allow-ssh is slice index 1 in policy set 0.
	// The callers therefore read allow-ssh's counter with handle 1 — even
	// though allow-web expands to 2 dataplane rules.
	wantWeb := stablePolicyRuleID("lan", "wan", "allow-web")
	wantSSH := stablePolicyRuleID("lan", "wan", "allow-ssh")
	if got := policyRuleIDForCounter(cfg, callerCounterID(0, 0)); got != wantWeb {
		t.Fatalf("policyRuleIDForCounter(handle 0) = %q, want %q", got, wantWeb)
	}
	if got := policyRuleIDForCounter(cfg, callerCounterID(0, 1)); got != wantSSH {
		t.Fatalf("policyRuleIDForCounter(handle 1) = %q, want %q (allow-ssh, NOT the preceding allow-web)", got, wantSSH)
	}
	// Global policies are policy set index 1 (after the one zone-pair set);
	// global-allow is slice index 0 there.
	wantGlobal := stablePolicyRuleID("junos-global", "junos-global", "global-allow")
	if got := policyRuleIDForCounter(cfg, callerCounterID(1, 0)); got != wantGlobal {
		t.Fatalf("policyRuleIDForCounter(global handle) = %q, want %q", got, wantGlobal)
	}
}

// Test_3143_CounterE2EThroughCallerHandle is the end-to-end test the suite was
// missing: it combines application-set expansion with a counter assertion across
// the full caller → resolver → name-keyed helper store path. The helper reports
// each policy's hit count keyed by its stable RuleID (the expanded rules of
// allow-web aggregate under one "lan->wan/allow-web" counter); a caller reads
// allow-ssh with the slice-index handle and must get allow-ssh's count, not the
// preceding allow-web's.
//
// Fail-on-revert: with a span-accumulated resolver, ReadPolicyCounters(handle 1)
// resolves to allow-web and returns allow-web's 50/5000 instead of allow-ssh's
// 11/1100 → RED.
func Test_3143_CounterE2EThroughCallerHandle(t *testing.T) {
	cfg := multiAppExpansionConfig()
	m := New()
	m.lastSnapshot = &ConfigSnapshot{Config: cfg}
	m.lastStatus = ProcessStatus{
		PolicyRuleCounters: []PolicyRuleCounterStatus{
			{RuleID: stablePolicyRuleID("lan", "wan", "allow-web"), Packets: 50, Bytes: 5000},
			{RuleID: stablePolicyRuleID("lan", "wan", "allow-ssh"), Packets: 11, Bytes: 1100},
		},
	}

	// Iterate exactly as the production counter readers do.
	results := map[string]dataplane.CounterValue{}
	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		for i, pol := range zpp.Policies {
			ctr, err := m.ReadPolicyCounters(callerCounterID(policySetID, i))
			if err != nil {
				t.Fatalf("ReadPolicyCounters(%s): %v", pol.Name, err)
			}
			results[pol.Name] = ctr
		}
		policySetID++
	}

	if got := results["allow-ssh"]; got != (dataplane.CounterValue{Packets: 11, Bytes: 1100}) {
		t.Fatalf("allow-ssh counter = %+v, want packets=11 bytes=1100 (NOT the preceding allow-web's 50/5000)", got)
	}
	if got := results["allow-web"]; got != (dataplane.CounterValue{Packets: 50, Bytes: 5000}) {
		t.Fatalf("allow-web counter = %+v, want packets=50 bytes=5000", got)
	}
}

// TestPolicyCounterResolverCountsNilPolicySetsLikeWalkPolicyRuleSlots pins the
// #3474 contract: a nil zone-pair slot in cfg.Security.Policies consumes a
// policy-set ID. walkPolicyRuleSlots and every production counter caller
// (pkg/api/security.go, pkg/api/metrics_counters.go) advance policySetID for a
// nil element, so the counter resolver MUST advance its set index in lockstep.
//
// Fixture: cfg.Security.Policies = [nil, {lan->wan, ...}]. The real zone-pair
// set therefore lives at policySetID == 1, which is exactly the handle the
// callers compute (callerCounterID(1, 0/1)).
//
// Fail-on-revert: with the resolver's nil branch skipping WITHOUT incrementing
// (the bug), it under-counts the set index by one, never matches currentSet==1,
// falls through to the global branch (empty GlobalPolicies here) and returns ""
// instead of the lan->wan rule IDs — so both assertions go RED.
func TestPolicyCounterResolverCountsNilPolicySetsLikeWalkPolicyRuleSlots(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		nil, // tolerant/HA-sync path can leave a nil zone-pair slot
		{
			FromZone: "lan",
			ToZone:   "wan",
			Policies: []*config.Policy{
				{Name: "allow-web", Action: config.PolicyPermit},
				{Name: "allow-ssh", Action: config.PolicyPermit},
			},
		},
	}

	// The nil slot is policy set 0; the real zone-pair set is policy set 1. The
	// callers read its rules with handles callerCounterID(1, 0) and
	// callerCounterID(1, 1) — the resolver must agree.
	wantWeb := stablePolicyRuleID("lan", "wan", "allow-web")
	wantSSH := stablePolicyRuleID("lan", "wan", "allow-ssh")
	if got := policyRuleIDForCounter(cfg, callerCounterID(1, 0)); got != wantWeb {
		t.Fatalf("policyRuleIDForCounter(set 1, slice 0) = %q, want %q (a preceding nil slot must still consume a policy-set ID)", got, wantWeb)
	}
	if got := policyRuleIDForCounter(cfg, callerCounterID(1, 1)); got != wantSSH {
		t.Fatalf("policyRuleIDForCounter(set 1, slice 1) = %q, want %q", got, wantSSH)
	}

	// The resolver must agree with walkPolicyRuleSlots on which (set, slice)
	// every configured policy maps to. Cross-check that the set index the walker
	// assigns each non-nil policy resolves back to that policy's own rule ID.
	if err := walkPolicyRuleSlots(cfg, func(slot policyRuleSlot) error {
		want := stablePolicyRuleID(slot.FromZone, slot.ToZone, slot.Policy.Name)
		if got := policyRuleIDForCounter(cfg, callerCounterID(slot.PolicySetID, int(slot.SliceIndex))); got != want {
			t.Fatalf("resolver/walker disagree at set %d slice %d: resolver=%q, walker=%q", slot.PolicySetID, slot.SliceIndex, got, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("walkPolicyRuleSlots: %v", err)
	}

	// Control / no-regression: a config with NO leading nil still resolves both
	// rules at policy set 0 exactly as before.
	noNil := &config.Config{}
	noNil.Security.Policies = []*config.ZonePairPolicies{cfg.Security.Policies[1]}
	if got := policyRuleIDForCounter(noNil, callerCounterID(0, 0)); got != wantWeb {
		t.Fatalf("control (no nil): policyRuleIDForCounter(set 0, slice 0) = %q, want %q", got, wantWeb)
	}
	if got := policyRuleIDForCounter(noNil, callerCounterID(0, 1)); got != wantSSH {
		t.Fatalf("control (no nil): policyRuleIDForCounter(set 0, slice 1) = %q, want %q", got, wantSSH)
	}
}

// Test_3145_SnapshotPolicyIDIsSpanAccumulated documents the OTHER namespace: the
// dataplane snapshot's PolicyID is span-accumulated (advances by the app-set
// expansion count), distinct from the slice-index counter handle above. Since
// #16560 sets are contiguous ranges, so the global set starts at 2 (not 256).
func Test_3145_SnapshotPolicyIDIsSpanAccumulated(t *testing.T) {
	cfg := multiAppExpansionConfig()
	snaps, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("buildPolicySnapshots: %v", err)
	}
	ids := map[string]uint32{}
	for _, s := range snaps {
		ids[s.Name] = s.PolicyID
	}
	// allow-web expands to 2 (IDs 0..1 as one policy slot at base 0), so
	// allow-ssh's snapshot PolicyID is 2 (span accumulated), and the global
	// set starts contiguously at 3 (#16560, not the legacy 256 block).
	if ids["allow-web"] != 0 || ids["allow-ssh"] != 2 {
		t.Fatalf("snapshot PolicyID spacing: allow-web=%d allow-ssh=%d, want 0 and 2", ids["allow-web"], ids["allow-ssh"])
	}
	if ids["global-allow"] != 3 {
		t.Fatalf("global snapshot PolicyID = %d, want 3 (contiguous after 2+1 expanded)", ids["global-allow"])
	}
}

// bigAppSet registers an application-set "big-set" with nApps real member
// applications (so ExpandApplicationSet resolves each member) and returns the
// member list. Each member is a distinct tcp application.
func bigAppSet(cfg *config.Config, nApps int) {
	if cfg.Applications.Applications == nil {
		cfg.Applications.Applications = map[string]*config.Application{}
	}
	members := make([]string, 0, nApps)
	for i := 0; i < nApps; i++ {
		name := fmt.Sprintf("app-%d", i)
		cfg.Applications.Applications[name] = &config.Application{
			Name:            name,
			Protocol:        "tcp",
			DestinationPort: fmt.Sprintf("%d", 10000+i),
		}
		members = append(members, name)
	}
	if cfg.Applications.ApplicationSets == nil {
		cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{}
	}
	cfg.Applications.ApplicationSets["big-set"] = &config.ApplicationSet{Name: "big-set", Applications: members}
}

// singleBigPolicyConfig is one zone-pair set with a single policy whose app-set
// expands to nApps terms — so the set's cumulative expansion equals nApps.
func singleBigPolicyConfig(nApps int) *config.Config {
	cfg := &config.Config{}
	bigAppSet(cfg, nApps)
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name:   "big",
			Match:  config.PolicyMatch{Applications: []string{"big-set"}},
			Action: config.PolicyPermit,
		}},
	}}
	return cfg
}

// Test16560_PerSetCapRemoved verifies #16560 on the LIVE userspace
// snapshot path: a single set expanding to 257 or 1000 terms builds, and
// IDs are contiguous (no 256-block spill concept). Only the total bound
// (65536) still rejects. Fail-on-revert: restoring the per-set cap makes
// the 257/1000 builds RED.
func Test16560_PerSetCapRemoved(t *testing.T) {
	for _, n := range []int{256, 257, 1000} {
		snaps, err := buildPolicySnapshots(singleBigPolicyConfig(n))
		if err != nil {
			t.Fatalf("buildPolicySnapshots(%d apps) err = %v, want success (#16560)", n, err)
		}
		if len(snaps) != 1 || snaps[0].PolicyID != 0 {
			t.Fatalf("buildPolicySnapshots(%d) snaps=%+v, want one at ID 0", n, snaps)
		}
	}
	// 257 plain policies in one pair + a second set: contiguous bases.
	cfg := &config.Config{}
	first := make([]*config.Policy, 0, 257)
	for i := 0; i < 257; i++ {
		first = append(first, &config.Policy{
			Name:   fmt.Sprintf("rule-%d", i),
			Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
			Action: config.PolicyPermit,
		})
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "lan", ToZone: "wan", Policies: first},
		{FromZone: "dmz", ToZone: "wan", Policies: []*config.Policy{{
			Name:   "next-set-rule",
			Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
			Action: config.PolicyPermit,
		}}},
	}
	// 257 globals also build contiguously after zone pairs.
	for i := 0; i < 257; i++ {
		cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies, &config.Policy{
			Name:   fmt.Sprintf("g%d", i),
			Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
			Action: config.PolicyPermit,
		})
	}
	snaps, err := buildPolicySnapshots(cfg)
	if err != nil {
		t.Fatalf("buildPolicySnapshots(257+1+257): %v", err)
	}
	seen := map[uint32]string{}
	var nextBase, globalBase uint32
	for _, s := range snaps {
		key := stablePolicyRuleID(s.FromZone, s.ToZone, s.Name)
		if prev, ok := seen[s.PolicyID]; ok && prev != key {
			t.Fatalf("runtime ID %d shared by %q and %q", s.PolicyID, prev, key)
		}
		seen[s.PolicyID] = key
		if s.Name == "next-set-rule" {
			nextBase = s.PolicyID
		}
		if s.Name == "g0" {
			globalBase = s.PolicyID
		}
	}
	if nextBase != 257 {
		t.Fatalf("second set base = %d, want 257 (contiguous)", nextBase)
	}
	if globalBase != 258 {
		t.Fatalf("global base = %d, want 258 (contiguous after zone pairs)", globalBase)
	}
	// Stability across unrelated edit: inserting a policy in the SECOND
	// set must not renumber the first set or globals before it; deleting
	// it restores IDs. IDs are deterministic from config order on both
	// nodes (same walker), so cross-node identity follows.
	idsBefore := PolicyIDsByStableKey(cfg)
	cfg2 := &config.Config{}
	cfg2.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "lan", ToZone: "wan", Policies: first},
		{FromZone: "dmz", ToZone: "wan", Policies: []*config.Policy{
			{Name: "inserted", Match: config.PolicyMatch{Applications: []string{"junos-ssh"}}, Action: config.PolicyPermit},
			{Name: "next-set-rule", Match: config.PolicyMatch{Applications: []string{"junos-ssh"}}, Action: config.PolicyPermit},
		}},
	}
	cfg2.Security.GlobalPolicies = cfg.Security.GlobalPolicies
	idsAfter := PolicyIDsByStableKey(cfg2)
	// Positional IDs: only sets BEFORE the edited set are stable; the
	// edited set's successors and all later sets (globals) shift by the
	// inserted span — that is the documented positional contract, and
	// daemon invalidation sweeps the shifted IDs.
	for k, v := range idsBefore {
		if strings.HasPrefix(k, "lan->wan/") {
			if idsAfter[k] != v {
				t.Fatalf("unrelated edit renumbered earlier set %s: %d -> %d", k, v, idsAfter[k])
			}
		}
		if strings.HasPrefix(k, "junos-global->junos-global/") {
			if idsAfter[k] != v+1 {
				t.Fatalf("global after edited set must shift by inserted span: %s: %d -> %d", k, v, idsAfter[k])
			}
		}
	}
	if idsAfter["dmz->wan/next-set-rule"] != idsBefore["dmz->wan/next-set-rule"]+1 {
		t.Fatalf("inserted policy must shift only its own set successors: before %d after %d", idsBefore["dmz->wan/next-set-rule"], idsAfter["dmz->wan/next-set-rule"])
	}
}
