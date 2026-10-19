package config

import (
	"strings"
	"testing"
)

// #15266 (B09-01): validateNPTv6Strict rejected same-prefix NPTv6 rules in
// different `from zone` rule-sets that the helper admits. Its seenPrefix
// carried no zone, so a split-horizon pair (distinct non-empty zones) was
// flagged as overlapping, and the lenient warning falsely claimed the helper
// rejects the whole snapshot. The helper (nptv6.rs find_overlap /
// zones_conflict, #5176) and the zone-aware predicate
// (nptv6FindOverlap / zonesConflictNPTv6 in nptv6_overlap.go) agree: two
// distinct non-empty zones are disjoint because a packet carries exactly
// one relevant zone.
//
// The fix makes the overlap leg of validateNPTv6Strict use the same
// zone-aware predicate, so commit and helper share one answer.
//
// FAIL-ON-REVERT: drop the zonesConflictNPTv6 gate in validateNPTv6Strict
// (compare prefixes zone-blindly again) and
// TestNPTv6SplitHorizonDifferentZonesCommits15266 and
// TestNPTv6SplitHorizonLenientNoFalseWarning15266 go RED.

func nptv6SplitHorizon15266(zoneA, ruleA, zoneB, ruleB string) []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
		"set security nat static rule-set rs-a from zone " + zoneA,
		"set security nat static rule-set rs-a rule " + ruleA + " match destination-address 2001:db8:9::/48",
		"set security nat static rule-set rs-a rule " + ruleA + " then static-nat nptv6-prefix fd00:9::/48",
		"set security nat static rule-set rs-b from zone " + zoneB,
		"set security nat static rule-set rs-b rule " + ruleB + " match destination-address 2001:db8:9::/48",
		"set security nat static rule-set rs-b rule " + ruleB + " then static-nat nptv6-prefix fd00:9::/48",
	}
}

// The probe config: identical external AND internal prefixes in two
// rule-sets scoped to DIFFERENT non-empty zones. The helper installs both.
// Strict commit must accept.
func TestNPTv6SplitHorizonDifferentZonesCommits15266(t *testing.T) {
	lines := nptv6SplitHorizon15266("untrust", "r-a", "dmz", "r-b")
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("split-horizon NPTv6 (same prefixes, distinct zones) must COMMIT (#15266/#5176), got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "overlaps rule-set") {
			t.Fatalf("no overlap warning may be emitted for split-horizon, got: %q", w)
		}
	}
}

// Lenient twin: same split-horizon config via CompileConfigLenient must not
// produce the false "helper rejects the whole snapshot" warning for the
// overlap leg.
func TestNPTv6SplitHorizonLenientNoFalseWarning15266(t *testing.T) {
	lines := nptv6SplitHorizon15266("untrust", "r-a", "dmz", "r-b")
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient compile must not brick: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "overlaps rule-set") {
			t.Fatalf("lenient must not falsely claim overlap for split-horizon, got: %q", w)
		}
	}
}

// Same-zone control: identical prefixes in the SAME zone still reject.
func TestNPTv6SameZoneOverlapStillRejects15266(t *testing.T) {
	lines := nptv6SplitHorizon15266("untrust", "r-a", "untrust", "r-b")
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("same-zone overlapping NPTv6 rules must be rejected (#15266 control)")
	}
	if !strings.Contains(err.Error(), "overlaps rule-set") {
		t.Fatalf("error must report the overlap, got: %v", err)
	}
}

// Wildcard-vs-zone control: an unscoped (empty FromZone) rule-set overlaps a
// zoned one — zonesConflictNPTv6 treats "" as conflicting with everything.
func TestNPTv6WildcardVsZoneOverlapStillRejects15266(t *testing.T) {
	lines := []string{
		"set security zones security-zone dmz",
		"set security nat static rule-set rs-a rule r-a match destination-address 2001:db8:9::/48",
		"set security nat static rule-set rs-a rule r-a then static-nat nptv6-prefix fd00:9::/48",
		"set security nat static rule-set rs-b from zone dmz",
		"set security nat static rule-set rs-b rule r-b match destination-address 2001:db8:9::/48",
		"set security nat static rule-set rs-b rule r-b then static-nat nptv6-prefix fd00:9::/48",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("wildcard-vs-zone overlapping NPTv6 rules must be rejected (#15266 control)")
	}
	if !strings.Contains(err.Error(), "overlaps rule-set") {
		t.Fatalf("error must report the overlap, got: %v", err)
	}
}

// Nested-prefix control in the same zone: a /48 and a /64 beneath it still
// reject (overlap is a common-prefix match at the shorter length).
func TestNPTv6NestedPrefixSameZoneStillRejects15266(t *testing.T) {
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule broad match destination-address 2001:db8:1::/48",
		"set security nat static rule-set rs1 rule broad then static-nat nptv6-prefix fd00:1::/48",
		"set security nat static rule-set rs1 rule narrow match destination-address 2001:db8:1:2::/64",
		"set security nat static rule-set rs1 rule narrow then static-nat nptv6-prefix fd00:2::/64",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("nested-prefix same-zone NPTv6 overlap must be rejected (#15266 control)")
	}
	if !strings.Contains(err.Error(), "overlaps rule-set") {
		t.Fatalf("error must report the overlap, got: %v", err)
	}
}
