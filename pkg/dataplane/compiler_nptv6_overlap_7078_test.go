package dataplane

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// nptv6OverlapConfig builds a config with TWO NPTv6 rules, so the cross-rule
// class is reachable at all — nptv6ProbeConfig carries only one and cannot
// express an overlap.
func nptv6OverlapConfig(zoneA, matchA, thenA, zoneB, matchB, thenB string) *config.Config {
	cfg := failLaterPhaseConfig()
	cfg.Security.Policies[0].Policies[0].Match.Applications = []string{"any"}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs-npt-4960", FromZone: zoneA,
			Rules: []*config.StaticNATRule{
				{Name: "r-npt-4960", IsNPTv6: true, Match: matchA, Then: thenA},
			},
		},
		{
			Name: "rs-npt-7078b", FromZone: zoneB,
			Rules: []*config.StaticNATRule{
				{Name: "r-npt-7078b", IsNPTv6: true, Match: matchB, Then: thenB},
			},
		},
	}
	return cfg
}

// TestNPTv6OverlapRejectedBeforeHostMutation_7078 is the residual named in
// compiler_validate_4960.go's header: the pre-pass replicated the helper's
// per-rule PARSE rejections but not its cross-rule OVERLAP rejection, so an
// overlapping pair was accepted, the host was mutated, and the helper then
// rejected the whole snapshot at publish with no rollback.
//
// The measurement in #7078 was `zoneConfigCalls == 1` — compileZones entered.
// assertRejectedByTheNPTv6Row asserts no mutation happened at all, and asserts
// it BEFORE the error-text check for the reason that helper documents: on a
// revert the compile still errors (the tripwire), so a text assertion placed
// first would fire and bury the finding that compileZones ran.
func TestNPTv6OverlapRejectedBeforeHostMutation_7078(t *testing.T) {
	dp := &recordingDP{}
	// The issue's exact repro: same external prefix, one zone.
	cfg := nptv6OverlapConfig(
		"untrust", "2001:db8:9::/48", "fd00:9::/48",
		"untrust", "2001:db8:9::/48", "fd00:aa::/48",
	)

	_, err := CompileConfig(dp, cfg, false)
	assertRejectedByTheNPTv6Row(t, dp, err, "overlaps")
}

// TestNPTv6SplitHorizonStillCompiles_7078 is THE PAIRED CELL, and the one that
// separates this fix from the naive one.
//
// #5176 partitions overlap by zone scope: a packet carries exactly one relevant
// zone, so two DISTINCT non-empty `from zone` scopes are disjoint and the helper
// installs both rules happily. Reusing validateNPTv6Strict's older overlap check
// — whose `seenPrefix` carries no zone — would reject this config, converting a
// working apply into a failed one. That is the over-rejection the #4960 guard's
// three properties exist to prevent, so a fix that closes the residual by
// breaking this is worse than the residual.
//
// The prefixes here are IDENTICAL to the rejected case above. Only the zone
// differs, which is what makes this a discriminating cell rather than a
// restatement.
func TestNPTv6SplitHorizonStillCompiles_7078(t *testing.T) {
	dp := &recordingDP{}
	cfg := nptv6OverlapConfig(
		"untrust", "2001:db8:9::/48", "fd00:9::/48",
		"dmz", "2001:db8:9::/48", "fd00:9::/48",
	)

	_, err := CompileConfig(dp, cfg, false)
	// It must NOT be rejected by the pre-pass. It still stops at the tripwire,
	// which is how this fixture proves the compile got PAST validation.
	if err == nil {
		t.Fatal("precondition: this fixture stops at the recordingDP tripwire, so " +
			"a nil error means the fixture stopped exercising the compile")
	}
	if strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("OVER-REJECTED: two NPTv6 rules with identical prefixes in DISTINCT "+
			"zones are legitimate split-horizon (#5176) and the helper installs both. "+
			"Rejecting them turns a working apply into a failed one — the exact "+
			"over-rejection the #4960 pre-pass must not commit, and what reusing "+
			"validateNPTv6Strict's zone-blind overlap check would have done: %v", err)
	}
	if strings.HasPrefix(err.Error(), "validate nptv6: ") {
		t.Fatalf("the pre-pass's nptv6 row rejected a config the helper accepts: %v", err)
	}
}

// TestNPTv6OverlapPredicateMirrorsTheHelper_7078 pins the shared predicate
// directly, at the shapes where a coarser implementation would diverge from
// `find_overlap`.
func TestNPTv6OverlapPredicateMirrorsTheHelper_7078(t *testing.T) {
	set := func(name, zone, match, then string) *config.StaticNATRuleSet {
		return &config.StaticNATRuleSet{
			Name: name, FromZone: zone,
			Rules: []*config.StaticNATRule{{Name: name + "-r", IsNPTv6: true, Match: match, Then: then}},
		}
	}
	for _, tc := range []struct {
		name     string
		sets     []*config.StaticNATRuleSet
		conflict bool
		why      string
	}{
		{
			"same zone, same external prefix", []*config.StaticNATRuleSet{
				set("a", "untrust", "2001:db8:9::/48", "fd00:9::/48"),
				set("b", "untrust", "2001:db8:9::/48", "fd00:aa::/48"),
			}, true, "the issue's repro",
		},
		{
			"distinct zones, identical prefixes", []*config.StaticNATRuleSet{
				set("a", "untrust", "2001:db8:9::/48", "fd00:9::/48"),
				set("b", "dmz", "2001:db8:9::/48", "fd00:9::/48"),
			}, false, "#5176 split-horizon: a packet carries one zone, so these are disjoint",
		},
		{
			"wildcard zone against a named zone", []*config.StaticNATRuleSet{
				set("a", "", "2001:db8:9::/48", "fd00:9::/48"),
				set("b", "dmz", "2001:db8:9::/48", "fd00:aa::/48"),
			}, true, "an empty scope matches every zone, so zones_conflict is true",
		},
		{
			"/64 beneath a /48", []*config.StaticNATRuleSet{
				set("a", "untrust", "2001:db8:9::/48", "fd00:9::/48"),
				set("b", "untrust", "2001:db8:9:0::/64", "fd00:bb::/64"),
			}, true, "overlap is a COMMON-PREFIX match at the shorter length, not equality",
		},
		{
			"disjoint prefixes, same zone", []*config.StaticNATRuleSet{
				set("a", "untrust", "2001:db8:9::/48", "fd00:9::/48"),
				set("b", "untrust", "2001:db8:aa::/48", "fd00:aa::/48"),
			}, false, "the control: nothing overlaps",
		},
		{
			"internal of one vs external of another", []*config.StaticNATRuleSet{
				set("a", "untrust", "2001:db8:9::/48", "fd00:9::/48"),
				set("b", "untrust", "fd00:9::/48", "2001:db8:cc::/48"),
			}, false, "the seen-sets are INDEPENDENT: outbound matches on the internal " +
				"prefix and inbound on the external, so an internal/external collision " +
				"is not an overlap. A single merged set would wrongly reject this",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Security.NAT.Static = tc.sets
			got := config.NPTv6OverlapConflict(cfg)
			if tc.conflict && got == "" {
				t.Fatalf("want a conflict (%s), got none", tc.why)
			}
			if !tc.conflict && got != "" {
				t.Fatalf("want NO conflict (%s), got %q", tc.why, got)
			}
		})
	}
}

// TestNPTv6OverlapSkipsUnknownLeavesExcludedRules_9877: a marked NPTv6 rule is
// dropped by the snapshot builder, so it can neither report nor trigger an
// overlap — in either seen-set position. RED-on-revert: drop the
// StaticNATRuleExcludedReason consult in NPTv6OverlapConflict and both rows
// report the overlap.
func TestNPTv6OverlapSkipsUnknownLeavesExcludedRules_9877(t *testing.T) {
	marked := func(name, zone, match, then string) *config.StaticNATRuleSet {
		return &config.StaticNATRuleSet{
			Name: name, FromZone: zone,
			Rules: []*config.StaticNATRule{{
				Name: name + "-r", IsNPTv6: true, Match: match, Then: then,
				UnknownMatchLeaves: []string{"soruce-address"},
			}},
		}
	}
	healthy := func(name, zone, match, then string) *config.StaticNATRuleSet {
		return &config.StaticNATRuleSet{
			Name: name, FromZone: zone,
			Rules: []*config.StaticNATRule{{Name: name + "-r", IsNPTv6: true, Match: match, Then: then}},
		}
	}
	for _, tc := range []struct {
		name string
		sets []*config.StaticNATRuleSet
	}{
		{"marked rule first, healthy overlap second", []*config.StaticNATRuleSet{
			marked("a", "untrust", "2001:db8:9::/48", "fd00:9::/48"),
			healthy("b", "untrust", "2001:db8:9::/48", "fd00:aa::/48"),
		}},
		{"healthy rule first, marked overlap second", []*config.StaticNATRuleSet{
			healthy("a", "untrust", "2001:db8:9::/48", "fd00:9::/48"),
			marked("b", "untrust", "2001:db8:9::/48", "fd00:aa::/48"),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Security.NAT.Static = tc.sets
			if got := config.NPTv6OverlapConflict(cfg); got != "" {
				t.Fatalf("want NO conflict (the marked rule never reaches the helper), got %q", got)
			}
		})
	}
}

// TestNPTv6OverlapWithExcludedRuleStillCompiles_9877 is the compile-level twin:
// the pair the issue's repro rejects must reach the tripwire once the
// overlapping rule is marked excluded.
func TestNPTv6OverlapWithExcludedRuleStillCompiles_9877(t *testing.T) {
	dp := &recordingDP{}
	cfg := nptv6OverlapConfig(
		"untrust", "2001:db8:9::/48", "fd00:9::/48",
		"untrust", "2001:db8:9::/48", "fd00:aa::/48",
	)
	cfg.Security.NAT.Static[0].Rules[0].UnknownMatchLeaves = []string{"soruce-address"}

	_, err := CompileConfig(dp, cfg, false)
	if !errors.Is(err, errStopBeforeHostReconcile) {
		t.Fatalf("an overlap involving an EXCLUDED rule was rejected by the "+
			"pre-pass. The marked rule never reaches try_from_snapshots, so "+
			"no overlap the helper could refuse exists — failing the compile "+
			"turns a working tolerant-load config into a failed apply "+
			"(#9877 / #1960).\n  got: %v", err)
	}
}
