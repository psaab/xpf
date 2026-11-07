package config

import (
	"strings"
	"testing"
)

// #4339: a static-NAT rule-set with a SINGLE NPTv6 rule and multiple distinct
// from-scopes (`from zone trust; from zone untrust`) must not be rejected as
// overlapping itself. compileNATStatic emits one snapshot per scope; the shared
// overlap engine partitions by from-zone, so two distinct non-empty zones are
// disjoint exactly as they are in the helper. Repeated identical scopes are
// deduplicated separately by collectNATScopes (#16874).
//
// The tests also pin the opposite case: two distinct rules that overlap within a
// common zone remain rejected.
//
// FAIL-ON-REVERT: remove the zonesConflictNPTv6 partition in the shared overlap
// engine and TestNPTv6SingleRuleMultiScopeCommits_4339 goes RED.

// nptv6MultiScopeSet builds a single-rule NPTv6 rule-set with TWO from-scopes.
func nptv6MultiScopeSet(rule, match, prefix string) []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat static rule-set NPTv6-INBOUND from zone trust",
		"set security nat static rule-set NPTv6-INBOUND from zone untrust",
		"set security nat static rule-set NPTv6-INBOUND rule " + rule + " match destination-address " + match,
		"set security nat static rule-set NPTv6-INBOUND rule " + rule + " then static-nat nptv6-prefix " + prefix,
	}
}

func TestNPTv6SingleRuleMultiScopeCommits_4339(t *testing.T) {
	tree := buildTree(t, nptv6MultiScopeSet("map-v6-neutral", "2602:fd41:70::/48", "2001:559:8585::/48"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a single NPTv6 rule bound to two from-scopes must COMMIT — it cannot overlap "+
			"itself (#4339), got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "overlaps rule-set") {
			t.Fatalf("no self-overlap warning may be emitted, got: %q", w)
		}
	}
}

// A GENUINE overlap between two DISTINCT rules must STILL be rejected — the fix
// only skips self-comparison, it does not disable the overlap check.
func TestNPTv6GenuineOverlapStillRejected_4339(t *testing.T) {
	// Two distinct rules whose external (match) prefixes overlap: a /48 and a
	// nested /64 under it. First-match resolution would be order-dependent.
	lines := []string{
		"set security zones security-zone trust",
		"set security nat static rule-set rs1 from zone trust",
		"set security nat static rule-set rs1 rule broad match destination-address 2001:db8:1::/48",
		"set security nat static rule-set rs1 rule broad then static-nat nptv6-prefix fd00:1::/48",
		"set security nat static rule-set rs1 rule narrow match destination-address 2001:db8:1:2::/64",
		"set security nat static rule-set rs1 rule narrow then static-nat nptv6-prefix fd00:2::/64",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("two DISTINCT NPTv6 rules with overlapping external prefixes must be rejected (#2241/#4339)")
	}
	if !strings.Contains(err.Error(), "overlaps rule-set") {
		t.Fatalf("error must report the genuine overlap, got: %v", err)
	}
}

// The genuine-overlap check must still fire when BOTH distinct rules are
// expanded across the same multiple scopes. Shared zones conflict even though
// each logical rule also has another disjoint scope.
func TestNPTv6GenuineOverlapMultiScopeStillRejected_4339(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone trust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule a match destination-address 2001:db8:9::/48",
		"set security nat static rule-set rs1 rule a then static-nat nptv6-prefix fd00:9::/48",
		"set security nat static rule-set rs1 rule b match destination-address 2001:db8:9::/48",
		"set security nat static rule-set rs1 rule b then static-nat nptv6-prefix fd00:8::/48",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("two DISTINCT multi-scope NPTv6 rules sharing an external prefix must be rejected (#4339)")
	}
	if !strings.Contains(err.Error(), "overlaps rule-set") {
		t.Fatalf("error must report the genuine overlap, got: %v", err)
	}
}
