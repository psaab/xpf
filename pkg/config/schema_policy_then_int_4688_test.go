package config

import (
	"strings"
	"testing"
)

// #4688: the policy-statement `then local-preference | metric | metric-type`
// leaves are typed integers gated at the Go commit boundary. Before the fix
// they had no validator, so:
//
//   - `then local-preference abc` committed silently — the compiler's
//     strconv.Atoi failed under an err==nil gate with no else, HasLocalPreference
//     stayed false, and the FRR clause was never emitted (fail-open, no warning).
//   - `then local-preference 42949672960` parsed as int64 in the compiler,
//     rendered, then FRR (u32) rejected it at frr-reload and aborted the WHOLE
//     reload (fable-167 R-1 class).
//
// FAIL-ON-REVERT: dropping the `valueType: ValueInteger, validator:
// ValidateInteger(...)` on these three leaves makes the untyped leaves accept
// any token again, so the reject assertions below fire RED.
func TestPolicyStatementThenInteger_SchemaGate(t *testing.T) {
	set := func(leaf, val string) string {
		return "set policy-options policy-statement p1 term t1 then " + leaf + " " + val
	}
	reject := func(leaf, val string) {
		t.Helper()
		tree := flatTreeFromSets(t, set(leaf, val))
		if err := SchemaValidate(tree); err == nil {
			t.Fatalf("then %s %q: expected SchemaValidate to reject, got nil", leaf, val)
		}
	}
	accept := func(leaf, val string) {
		t.Helper()
		tree := flatTreeFromSets(t, set(leaf, val))
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("then %s %q: expected SchemaValidate to accept, got %v", leaf, val, err)
		}
	}

	// Non-numeric and u32-overflow reject on local-preference / metric.
	for _, leaf := range []string{"local-preference", "metric"} {
		reject(leaf, "abc")
		reject(leaf, "-1")
		reject(leaf, "4294967296") // maxWireU32 + 1 (FRR-reload-abort class)
		accept(leaf, "0")
		accept(leaf, "42")
		accept(leaf, "4294967295") // maxWireU32
	}

	// metric-type is the OSPF external route type: only 1 or 2.
	reject("metric-type", "abc")
	reject("metric-type", "0")
	reject("metric-type", "3")
	accept("metric-type", "1")
	accept("metric-type", "2")
}

// #4688: the reject error names the offending value so the operator sees which
// value was out of range instead of a silent drop / opaque FRR-reload abort.
func TestPolicyStatementThenLocalPreference_ErrorMentionsValue(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set policy-options policy-statement p1 term t1 then local-preference 42949672960")
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("expected an out-of-range local-preference to be rejected at commit")
	}
	if !strings.Contains(err.Error(), "42949672960") {
		t.Fatalf("error %q must name the out-of-range value 42949672960", err.Error())
	}
}
