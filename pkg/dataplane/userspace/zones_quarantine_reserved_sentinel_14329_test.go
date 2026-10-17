package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14329: a poisoned reserved-sentinel zone definition
// (any / junos-host / junos-global with DroppedEnforcementChild) must not
// erase global or wildcard policies via quarantine scrubbing, and the
// dedicated poison paths must govern instead. walkPolicyRuleSlots must
// stay in sync with scrub for scoped globals whose Match side is fully
// quarantined (a real, non-reserved zone).

func sentinel14329Policy(name string) *config.Policy {
	return &config.Policy{
		Name:   name,
		Action: config.PolicyDeny,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
	}
}

func reservedPoisonedCfg14329(reserved string) *config.Config {
	zones := map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"untrust": {Name: "untrust"},
	}
	if reserved != "" {
		zones[reserved] = &config.ZoneConfig{Name: reserved, DroppedEnforcementChild: true}
	}
	return &config.Config{
		Security: config.SecurityConfig{
			Zones: zones,
			Policies: []*config.ZonePairPolicies{
				{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{
					{Name: "wildcard-rule", Action: config.PolicyPermit, Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}}},
				}},
				{FromZone: "trust", ToZone: "junos-host", Policies: []*config.Policy{
					{Name: "host-rule", Action: config.PolicyPermit, Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}}},
				}},
				{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
					{Name: "healthy", Action: config.PolicyPermit, Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}}},
				}},
			},
			GlobalPolicies: []*config.Policy{
				func() *config.Policy { p := sentinel14329Policy("global-deny"); return p }(),
				func() *config.Policy {
					p := sentinel14329Policy("global-permit")
					p.Action = config.PolicyPermit
					return p
				}(),
			},
		},
	}
}

func names14329(rules []PolicyRuleSnapshot) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		out[r.Name] = true
	}
	return out
}

func TestPoisonedReservedSentinelZonesDoNotEraseGlobalOrDefinedAnyPolicies(t *testing.T) {
	for _, reserved := range []string{config.JunosGlobalZoneName, config.ReservedWildcardZoneName, "junos-host"} {
		t.Run(reserved, func(t *testing.T) {
			cfg := reservedPoisonedCfg14329(reserved)

			// walk must not skip zone-pair sets merely because the reserved
			// name is poisoned: dedicated poisons (defined-any, host, global
			// sentinel) handle them, and cap accounting must still see them.
			ids := PolicyIDsByStableKey(cfg)
			// Global rules must be present in ID maps.
			for _, key := range []string{
				"junos-global->junos-global/global-deny",
				"junos-global->junos-global/global-permit",
			} {
				if _, ok := ids[key]; !ok {
					t.Fatalf("reserved %q poisoned: PolicyIDsByStableKey missing %q (got %v)", reserved, key, ids)
				}
			}
			// Wildcard / host zone-pair rules must not be silently erased
			// from the ID namespace merely due to reserved poison.
			// (For `any`, the defined-any poison still records the rule;
			// for junos-host, host rules are legitimate context.)
			if _, ok := ids["any->untrust/wildcard-rule"]; !ok {
				t.Fatalf("reserved %q poisoned: wildcard rule missing from PolicyIDsByStableKey %v", reserved, ids)
			}
			if _, ok := ids["trust->junos-host/host-rule"]; !ok {
				t.Fatalf("reserved %q poisoned: host rule missing from PolicyIDsByStableKey %v", reserved, ids)
			}
			if _, ok := ids["trust->untrust/healthy"]; !ok {
				t.Fatalf("reserved %q poisoned: healthy rule missing %v", reserved, ids)
			}

			// Snapshot: globals must survive quarantine scrub (not Case-1a dropped).
			snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			got := names14329(snap.Policies)
			if !got["global-deny"] || !got["global-permit"] {
				t.Fatalf("reserved %q poisoned: global policies erased from snapshot, got %v policies %v", reserved, got, snap.Policies)
			}
			if !got["healthy"] {
				t.Fatalf("reserved %q poisoned: healthy rule erased, got %v", reserved, got)
			}
			// `any` defined: wildcard zone-pair rule must survive as a
			// poisoned rule (dedicated #12249 path rejects whole snapshot),
			// not be silently scrubbed away.
			if reserved == config.ReservedWildcardZoneName {
				if !got["wildcard-rule"] {
					t.Fatalf("defined poisoned `any`: wildcard rule silently erased instead of poisoned, got %v", got)
				}
				rule := policyNamed12249(snap.Policies, "wildcard-rule")
				if rule == nil || !hasSentinel12249(rule) {
					t.Fatalf("defined poisoned `any`: wildcard rule must carry dedicated poison sentinel, got %+v", rule)
				}
				reasons := PolicyContentRejectionReasons(cfg, nil)
				if len(reasons) == 0 || !strings.Contains(strings.Join(reasons, "\n"), "wildcard-rule") {
					t.Fatalf("defined poisoned `any`: expected dedicated rejection reason for wildcard-rule, got %v", reasons)
				}
			}
			// junos-host context rule must survive (not scrubbed).
			if reserved == "junos-host" {
				if !got["host-rule"] {
					t.Fatalf("poisoned junos-host: host rule silently erased, got %v", got)
				}
			}
			if reserved == config.JunosGlobalZoneName {
				if !got["wildcard-rule"] || !got["host-rule"] {
					t.Fatalf("poisoned junos-global: wildcard/host rules erased, got %v", got)
				}
			}
			// Partial-republish scrub path must agree.
			q := quarantinedZoneNamesForConfig(cfg)
			if _, ok := q[reserved]; ok {
				t.Fatalf("reserved %q must not be in policy quarantine set %v", reserved, q)
			}
		})
	}
}

func TestWalkPolicyRuleSlotsSkipsFullyQuarantinedScopedGlobalPolicies(t *testing.T) {
	colliding := d412CollidingZoneName(t)

	mkGlobal := func(name string, from, to []string) *config.Policy {
		p := sentinel14329Policy(name)
		p.Match.FromZones = from
		p.Match.ToZones = to
		return p
	}

	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
				colliding: {Name: colliding},
			},
			Policies: []*config.ZonePairPolicies{
				{FromZone: "trust", ToZone: "untrust", Policies: d412Rules("survivor", 1)},
			},
			GlobalPolicies: []*config.Policy{
				// Fully quarantined on from side -> scrub drops it.
				mkGlobal("fully-q-from", []string{colliding}, nil),
				// Fully quarantined on to side -> scrub drops it.
				mkGlobal("fully-q-to", nil, []string{colliding}),
				// Partially quarantined -> scrub prunes and keeps it.
				mkGlobal("partial-q", []string{colliding, "trust"}, nil),
				// Unscoped -> keeps.
				mkGlobal("unscoped", nil, nil),
			},
		},
	}

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	got := names14329(snap.Policies)
	if got["fully-q-from"] || got["fully-q-to"] {
		t.Fatalf("fully-quarantined scoped globals must be dropped from snapshot, got %v", got)
	}
	if !got["partial-q"] || !got["unscoped"] {
		t.Fatalf("partial/unscoped globals must survive snapshot, got %v", got)
	}
	// Partial must be pruned to survivor only.
	for _, r := range snap.Policies {
		if r.Name == "partial-q" {
			if len(r.MatchFromZones) != 1 || r.MatchFromZones[0] != "trust" {
				t.Fatalf("partial-q scope not pruned to [trust]: %v", r.MatchFromZones)
			}
		}
	}

	ids := PolicyIDsByStableKey(cfg)
	for _, dropped := range []string{"fully-q-from", "fully-q-to"} {
		key := "junos-global->junos-global/" + dropped
		if _, ok := ids[key]; ok {
			t.Fatalf("fully-quarantined scoped global %q must not consume ID slot / appear in PolicyIDsByStableKey, got %v", dropped, ids)
		}
	}
	for _, kept := range []string{"partial-q", "unscoped"} {
		key := "junos-global->junos-global/" + kept
		if _, ok := ids[key]; !ok {
			t.Fatalf("kept scoped global %q missing from PolicyIDsByStableKey %v", kept, ids)
		}
	}
	if got := PoliciesByStableKey(cfg); len(got) != 3 { // survivor + partial + unscoped
		t.Fatalf("PoliciesByStableKey entries = %d, want 3 (survivor+partial+unscoped), got %v", len(got), got)
	}
	// Survivor global IDs must match snapshot PolicyIDs.
	snapIDs := map[string]uint32{}
	for _, r := range snap.Policies {
		snapIDs[stablePolicyRuleID(r.FromZone, r.ToZone, r.Name)] = r.PolicyID
	}
	for key, want := range snapIDs {
		if gotID, ok := ids[key]; !ok || gotID != want {
			t.Fatalf("PolicyIDsByStableKey[%q] = %d (ok=%v), want snapshot PolicyID %d", key, gotID, ok, want)
		}
	}
	// RuntimePolicyIDs: global set is len(Policies)=1; dropped globals must
	// not appear, kept must appear with matching IDs.
	rt := RuntimePolicyIDs(cfg)
	// survivor is set 0 slice 0; globals are set 1 slices 0..3 in config order.
	if _, ok := rt[[2]uint32{1, 0}]; ok {
		t.Fatalf("RuntimePolicyIDs contains fully-quarantined global slice 0: %v", rt)
	}
	if _, ok := rt[[2]uint32{1, 1}]; ok {
		t.Fatalf("RuntimePolicyIDs contains fully-quarantined global slice 1: %v", rt)
	}
	if _, ok := rt[[2]uint32{1, 2}]; !ok {
		t.Fatalf("RuntimePolicyIDs missing partial-q global slice 2: %v", rt)
	}
	if _, ok := rt[[2]uint32{1, 3}]; !ok {
		t.Fatalf("RuntimePolicyIDs missing unscoped global slice 3: %v", rt)
	}
}
