package config

import (
	"strings"
	"testing"
)

// #4313 — PRODUCTION closed-world subtree flip: `security nat nat64`.
//
// nat64 is an xpf-NATIVE stanza (Junos does NAT64 via source/destination NAT +
// `then static-nat inet`, not this spelling), so its grammar IS exactly what
// xpf models and compiles — there is no external Junos superset to
// false-reject. The container's only child is `rule-set`; a rule-set's only
// children are `prefix` and `source-pool` (both modeled value leaves whose
// value rides on the same statement line). The compiler (compileNAT64) reads
// ONLY prefix + source-pool and the struct (NAT64RuleSet) holds ONLY those
// two, so the subtree is leaf-complete by construction.
//
// Silent-drop here is a real footgun: a typo'd `prefx` left NAT64RuleSet.Prefix
// empty, validateNAT64PrefixStrict skipped the rule (Prefix == "" → continue),
// and NAT64 translation silently did nothing — IPv6-only clients lost IPv4
// reachability with no error. The flip REJECTS the typo at strict commit.
//
// Each rejection test is RED on revert of the closedWorld flag: without it,
// SchemaValidate returns nil (open-world silent-accept) and the test fails.

func cwNAT64Set(bodyLines ...string) []string {
	out := []string{}
	for _, l := range bodyLines {
		out = append(out, "set security nat nat64 "+l)
	}
	return out
}

// TestClosedWorldNAT64_RejectsUnknownKeyword covers both closed levels: a typo
// at the nat64 level (`rulset`) and under a rule-set instance (`prefx`).
func TestClosedWorldNAT64_RejectsUnknownKeyword(t *testing.T) {
	for _, typo := range []string{
		"rulset r1 prefix 64:ff9b::/96",        // nat64-level typo
		"rule-set r1 prefx 64:ff9b::/96",       // rule-set-level typo (prefix)
		"rule-set r1 source-pol p1",            // rule-set-level typo (source-pool)
		"rule-set r1 destination-prefix ::/96", // unmodeled keyword under rule-set
	} {
		tree := buildTree(t, cwNAT64Set(typo))
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatalf("a typo'd NAT64 leaf %q must be rejected at commit, not silently dropped (NAT64 silently inert)", typo)
		}
		bad := strings.Fields(typo)[0]
		if !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "closed-world") {
			t.Fatalf("error must name the typo %q and the closed-world subtree, got: %v", bad, err)
		}
	}
}

// TestClosedWorldNAT64_AcceptsValid proves no false-reject: every modeled NAT64
// leaf still commits clean under closed-world.
func TestClosedWorldNAT64_AcceptsValid(t *testing.T) {
	for _, leaf := range []string{
		"rule-set r1 prefix 64:ff9b::/96",
		"rule-set r1 source-pool p1",
	} {
		tree := buildTree(t, cwNAT64Set(leaf))
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("valid NAT64 leaf %q must commit clean under closed-world, got: %v", leaf, err)
		}
	}
	// a fully-specified rule-set
	full := buildTree(t, cwNAT64Set(
		"rule-set r1 prefix 64:ff9b::/96",
		"rule-set r1 source-pool p1",
	))
	if err := SchemaValidate(full); err != nil {
		t.Fatalf("a fully-specified NAT64 rule-set must commit clean under closed-world, got: %v", err)
	}
}

// TestClosedWorldNAT64_LenientDoesNotBrick documents the #1960 no-brick
// contract: the closed-world reject is a SchemaValidate error, downgraded to a
// warning on the tolerant Store.Load / SyncApply path (CompileConfigLenient).
func TestClosedWorldNAT64_LenientDoesNotBrick(t *testing.T) {
	typoTree := buildTree(t, cwNAT64Set("rule-set r1 prefx 64:ff9b::/96"))
	if err := SchemaValidate(typoTree); err == nil {
		t.Fatal("precondition: strict SchemaValidate must reject the typo")
	}
	if _, err := CompileConfigLenient(typoTree); err != nil {
		t.Fatalf("the lenient load/peer-sync path must not brick on a closed-world typo (#1960); got: %v", err)
	}
}
