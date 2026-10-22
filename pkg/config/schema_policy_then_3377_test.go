package config

// #3377: the security-policy `then` action subtree compiled permit/deny/
// reject/log/count (compilePolicy's `then` switch in compiler_security.go)
// but setSchema declared only `log` — permit/deny/reject/count lived only
// in a `// permit, deny, reject, count → leaf` comment placeholder. That is
// the compiled-but-not-schema-visible drift the two-SSOT rule (#1319)
// exists to prevent: `set security policies ... then ?` could not complete
// the most basic policy actions. These tests assert the actions are now
// offered by config-mode completion and validate cleanly, for BOTH zone-
// pair and global policies, and a canary pins the schema `then` child set
// to the compiler's switch token set. Reverting the schema addition (back
// to a lone `log` child) turns them RED — the fail-on-revert guard.

import (
	"sort"
	"testing"
)

// compilerPolicyThenTokens is the EXACT set of top-level `then` tokens the
// security-policy compiler enforces — the cases in compilePolicy's `then`
// switch (compiler_security.go: permit, deny, reject, log, count). The
// schema `then` children MUST equal this set for both policy scopes; the
// canary below fails if a compiled action drifts out of the schema (or a
// schema-only action drifts in with no compiler support).
var compilerPolicyThenTokens = []string{"count", "deny", "log", "permit", "reject"}

func policyThenSchemaNode(t *testing.T, scope string) *schemaNode {
	t.Helper()
	policies := schemaSecurity.children["policies"]
	if policies == nil {
		t.Fatal("schemaSecurity missing policies child")
	}
	var policy *schemaNode
	switch scope {
	case "zone-pair":
		policy = policies.children["from-zone"].children["policy"]
	case "global":
		policy = policies.children["global"].children["policy"]
	default:
		t.Fatalf("unknown scope %q", scope)
	}
	if policy == nil {
		t.Fatalf("%s scope missing policy node", scope)
	}
	then := policy.children["then"]
	if then == nil {
		t.Fatalf("%s scope missing then node", scope)
	}
	return then
}

func sortedSchemaKeys(m map[string]*schemaNode) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestSchema3377_ThenActions_ZonePairCompletion asserts the zone-pair
// policy `then ?` offers permit/deny/reject/count (and still log).
func TestSchema3377_ThenActions_ZonePairCompletion(t *testing.T) {
	results := CompleteSetPathWithValues(
		[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p1", "then"}, nil)
	for _, want := range []string{"permit", "deny", "reject", "log", "count"} {
		if !containsCompletionName(results, want) {
			t.Fatalf("expected zone-pair then completion to offer %q, got %v", want, completionNames(results))
		}
	}
}

// TestSchema3377_ThenActions_GlobalCompletion asserts the same for global
// policies.
func TestSchema3377_ThenActions_GlobalCompletion(t *testing.T) {
	results := CompleteSetPathWithValues(
		[]string{"security", "policies", "global", "policy", "g1", "then"}, nil)
	for _, want := range []string{"permit", "deny", "reject", "log", "count"} {
		if !containsCompletionName(results, want) {
			t.Fatalf("expected global then completion to offer %q, got %v", want, completionNames(results))
		}
	}
}

// TestSchema3377_ThenSubOptionCompletion asserts the modifier sub-options
// complete: `then deny ?` => log/count, `then log ?` =>
// session-init/session-close.
func TestSchema3377_ThenSubOptionCompletion(t *testing.T) {
	deny := CompleteSetPathWithValues(
		[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p1", "then", "deny"}, nil)
	for _, want := range []string{"log", "count"} {
		if !containsCompletionName(deny, want) {
			t.Fatalf("expected then deny completion to offer %q, got %v", want, completionNames(deny))
		}
	}
	logc := CompleteSetPathWithValues(
		[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p1", "then", "log"}, nil)
	for _, want := range []string{"session-init", "session-close"} {
		if !containsCompletionName(logc, want) {
			t.Fatalf("expected then log completion to offer %q, got %v", want, completionNames(logc))
		}
	}
}

// TestSchema3377_ThenActions_FlatSchemaAccepts confirms the declared
// action leaves validate cleanly via the flat-set schema gate (no false
// reject). The strict reject-at-commit gates for UNSUPPORTED then-permit/
// then-reject/then-deny children (#3114/#3115/#3141) remain the SSOT for
// rejection and are exercised by their own tests, not duplicated here.
func TestSchema3377_ThenActions_FlatSchemaAccepts(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security policies from-zone trust to-zone untrust policy permit-pol match source-address any",
		"set security policies from-zone trust to-zone untrust policy permit-pol then permit",
		"set security policies from-zone trust to-zone untrust policy deny-pol match source-address any",
		"set security policies from-zone trust to-zone untrust policy deny-pol then deny",
		"set security policies from-zone trust to-zone untrust policy deny-log-pol match source-address any",
		"set security policies from-zone trust to-zone untrust policy deny-log-pol then deny log session-init",
		"set security policies from-zone trust to-zone untrust policy reject-pol match source-address any",
		"set security policies from-zone trust to-zone untrust policy reject-pol then reject",
		"set security policies from-zone trust to-zone untrust policy count-pol match source-address any",
		"set security policies from-zone trust to-zone untrust policy count-pol then permit",
		"set security policies from-zone trust to-zone untrust policy count-pol then count",
		"set security policies global policy g-permit then permit",
		"set security policies global policy g-deny then deny count",
		"set security policies global policy g-reject then reject",
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
		t.Fatalf("expected then permit/deny/reject/count leaves to pass schema validation, got: %v", err)
	}
}

// TestSchema3377_ThenSchemaMatchesCompiler is the drift canary: the schema
// `then` child set MUST equal the compiler's `then` switch token set
// (compilerPolicyThenTokens) for BOTH zone-pair and global scopes. If a
// future action is added to compilePolicy's switch but not the schema (or
// vice-versa), this fails — closing the compiled-but-not-schema-visible
// drift class #3377 found.
func TestSchema3377_ThenSchemaMatchesCompiler(t *testing.T) {
	for _, scope := range []string{"zone-pair", "global"} {
		then := policyThenSchemaNode(t, scope)
		got := sortedSchemaKeys(then.children)
		if len(got) != len(compilerPolicyThenTokens) {
			t.Fatalf("%s then children %v != compiler token set %v", scope, got, compilerPolicyThenTokens)
		}
		for i, want := range compilerPolicyThenTokens {
			if got[i] != want {
				t.Fatalf("%s then children %v != compiler token set %v", scope, got, compilerPolicyThenTokens)
			}
		}
	}
}
