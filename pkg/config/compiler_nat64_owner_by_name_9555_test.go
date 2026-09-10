package config

import (
	"strings"
	"testing"
)

// #9555: a second NAT64 rule-set under the same /96 prefix is SHADOWED by the
// dataplane's first-match selection. Measured before this change on
// `origin/master` at `65541cdd0`:
//   - Go REJECTED two differently-named pools with identical addresses as a
//     #5144 double-mint, although only the first rule-set can ever mint (an
//     over-refusal with a false reason);
//   - Go ACCEPTED two same-prefix rule-sets with DISJOINT pools SILENTLY, while
//     the dataplane never used the second pool.
// The Rust premise both rest on is pinned in `nat64_tests.rs`
// (`nat64_selects_the_first_built_rule_set_for_a_shared_prefix_9555`).

func unreachableWarning9555(cfg *Config, ruleSet string) string {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#9555") && strings.Contains(w, "UNREACHABLE") &&
			strings.Contains(w, "rule-set \""+ruleSet+"\"") {
			return w
		}
	}
	return ""
}

func acceptedWithUnreachable9555(t *testing.T, ruleSet string, cmds ...string) {
	t.Helper()
	cfg, err := CompileConfig(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("#9555: strict commit must ACCEPT a same-prefix duplicate, whose later rule-set is "+
			"shadowed and never mints; got: %v", err)
	}
	if unreachableWarning9555(cfg, ruleSet) == "" {
		t.Fatalf("#9555: strict commit must WARN that rule-set %q is UNREACHABLE; warnings = %v", ruleSet, cfg.Warnings)
	}
}

// FAIL-ON-REVERT, the over-refusal: rejected before #9555 as a double-mint.
func TestNAT64ShadowedSamePrefixIdenticalAddressIsNotADoubleMint9555(t *testing.T) {
	acceptedWithUnreachable9555(t, "B",
		"set security nat source pool P1 address 100.64.0.7/32",
		"set security nat source pool P2 address 100.64.0.7/32",
		"set security nat nat64 rule-set A prefix 64:ff9b::/96",
		"set security nat nat64 rule-set A source-pool P1",
		"set security nat nat64 rule-set B prefix 64:ff9b::/96",
		"set security nat nat64 rule-set B source-pool P2",
	)
}

// FAIL-ON-REVERT, the silent symptom: accepted with NO warning before #9555.
func TestNAT64ShadowedSamePrefixDisjointPoolsWarns9555(t *testing.T) {
	acceptedWithUnreachable9555(t, "B",
		"set security nat source pool P1 address 100.64.0.7/32",
		"set security nat source pool P2 address 100.64.0.8/32",
		"set security nat nat64 rule-set A prefix 64:ff9b::/96",
		"set security nat nat64 rule-set A source-pool P1",
		"set security nat nat64 rule-set B prefix 64:ff9b::/96",
		"set security nat nat64 rule-set B source-pool P2",
	)
}

// The same pool on both: harmless, still accepted (#5144's own cell), now warned.
func TestNAT64ShadowedSamePrefixSamePoolWarns9555(t *testing.T) {
	acceptedWithUnreachable9555(t, "B",
		"set security nat source pool P address 100.64.0.7/32",
		"set security nat nat64 rule-set A prefix 64:ff9b::/96",
		"set security nat nat64 rule-set A source-pool P",
		"set security nat nat64 rule-set B prefix 64:ff9b::/96",
		"set security nat nat64 rule-set B source-pool P",
	)
}

// Equivalent spellings are the same /96 to the dataplane, so still a duplicate.
func TestNAT64ShadowedEquivalentPrefixSpellingWarns9555(t *testing.T) {
	acceptedWithUnreachable9555(t, "B",
		"set security nat source pool P1 address 100.64.0.7/32",
		"set security nat source pool P2 address 100.64.0.8/32",
		"set security nat nat64 rule-set A prefix 64:ff9b::/96",
		"set security nat nat64 rule-set A source-pool P1",
		"set security nat nat64 rule-set B prefix 64:ff9b::/096",
		"set security nat nat64 rule-set B source-pool P2",
	)
}

// UNDER-REFUSAL CONTROL: the reachable rule-set is chosen by CONFIG order, not by
// name. Z comes first and its pool backs a source-NAT rule, a real cross-feature
// collision. A sorts first by name and has a disjoint pool. Choosing by name would
// make A the owner, drop Z as "shadowed", and ACCEPT the collision.
func TestNAT64ReachableRuleSetIsChosenByConfigOrderNotName9555(t *testing.T) {
	cmds := []string{
		"set security nat source pool S address 100.64.0.9/32",
		"set security nat source pool D address 100.64.0.10/32",
		"set security nat nat64 rule-set Z prefix 64:ff9b::/96",
		"set security nat nat64 rule-set Z source-pool S",
		"set security nat nat64 rule-set A prefix 64:ff9b::/96",
		"set security nat nat64 rule-set A source-pool D",
	}
	cmds = append(cmds, srcRule("RS", "r1", "S")...)
	lenient, err := CompileConfigLenient(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient compile must not brick: %v", err)
	}
	var order []string
	for _, rs := range lenient.Security.NAT.NAT64 {
		order = append(order, rs.Name)
	}
	if strings.Join(order, ",") != "Z,A" {
		t.Fatalf("precondition: the compiled NAT64 rule-sets must keep CONFIG order Z,A, got %v; "+
			"if the compiler sorts them, config order and name order coincide and this cell tests nothing", order)
	}
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
}

// CONSERVATIVE CONTROL: an earlier rule-set the dataplane SKIPS (a non-host pool
// member fails `parse_pool_v4`, #3888) shadows nothing. B is reachable, and its
// pool collides with source NAT, so the #5144 finding must still be emitted.
func TestNAT64SkippedEarlierRuleSetDoesNotShadow9555(t *testing.T) {
	cmds := []string{
		"set security nat source pool BAD address 100.65.0.0/24",
		"set security nat source pool OVL address 100.64.0.9/32",
		"set security nat nat64 rule-set A prefix 64:ff9b::/96",
		"set security nat nat64 rule-set A source-pool BAD",
		"set security nat nat64 rule-set B prefix 64:ff9b::/96",
		"set security nat nat64 rule-set B source-pool OVL",
	}
	cmds = append(cmds, srcRule("RS", "r1", "OVL")...)
	cfg, err := CompileConfigLenient(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient compile must not brick: %v", err)
	}
	found5144 := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5144") && strings.Contains(w, "rule-set \"B\"") {
			found5144 = true
		}
	}
	if !found5144 {
		t.Fatalf("#9555 UNDER-REFUSAL: rule-set A is skipped whole by the dataplane (a /24 pool member), so "+
			"rule-set B is reachable and its pool collides with source NAT; the #5144 finding naming B must "+
			"still be emitted. warnings = %v", cfg.Warnings)
	}
	if w := unreachableWarning9555(cfg, "B"); w != "" {
		t.Fatalf("#9555: rule-set B must NOT be reported unreachable -- the rule-set ahead of it is never built; got %q", w)
	}
}
