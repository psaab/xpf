package config

// #3117: a security-policy `scheduler-name <name>` is compiled
// (compiler_security.go) and strict-validated against the defined
// class-of-service schedulers (compiler_validate_strict_cos.go
// validatePolicySchedulerReferencesStrict), but it was ABSENT from
// setSchema — so the leaf had no structural / `?` completion, violating
// the two-SSOT rule that every compiled + validated leaf lives in the
// schema tree. These tests assert the leaf is now offered by config-mode
// completion for BOTH zone-pair and global policies. Reverting the schema
// addition turns them RED (the leaf would no longer be a known child),
// which is the fail-on-revert guard.

import "testing"

// TestSchema3117_SchedulerName_ZonePairCompletion asserts scheduler-name
// is offered as a child of a zone-pair policy node alongside its
// description/match/then siblings.
func TestSchema3117_SchedulerName_ZonePairCompletion(t *testing.T) {
	results := CompleteSetPathWithValues(
		[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p1"}, nil)
	if !containsCompletionName(results, "scheduler-name") {
		t.Fatalf("expected zone-pair policy completion to offer scheduler-name, got %v", completionNames(results))
	}
	// Sanity: the established sibling leaves are still present (guards
	// against an edit that displaces the policy subtree wholesale).
	if !containsCompletionName(results, "then") || !containsCompletionName(results, "match") {
		t.Fatalf("expected policy subtree siblings (then, match), got %v", completionNames(results))
	}
}

// TestSchema3117_SchedulerName_GlobalCompletion asserts the same for
// global policies.
func TestSchema3117_SchedulerName_GlobalCompletion(t *testing.T) {
	results := CompleteSetPathWithValues(
		[]string{"security", "policies", "global", "policy", "p1"}, nil)
	if !containsCompletionName(results, "scheduler-name") {
		t.Fatalf("expected global policy completion to offer scheduler-name, got %v", completionNames(results))
	}
}

// TestSchema3117_SchedulerName_FlatSchemaAccepts confirms the declared
// leaf validates cleanly via the flat-set typed-leaf gate (no false
// reject), matching how sibling schema leaves are exercised. The strict
// undefined-scheduler reference check remains the SSOT for rejection and
// is not duplicated here.
func TestSchema3117_SchedulerName_FlatSchemaAccepts(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security policies from-zone trust to-zone untrust policy p1 scheduler-name sched1",
		"set security policies global policy g1 scheduler-name sched1",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q) failed: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q) failed: %v", cmd, err)
		}
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("expected scheduler-name leaves to pass schema validation, got: %v", err)
	}
}
