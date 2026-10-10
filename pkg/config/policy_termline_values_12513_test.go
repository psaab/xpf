package config

import (
	"reflect"
	"strings"
	"testing"
)

// thenFields12513 is the compiled `then` state of one policy term, compared
// whole so a row also proves every field it does not name stayed unset.
type thenFields12513 struct {
	Action             string
	LocalPreference    int
	HasLocalPreference bool
	Metric             int
	HasMetric          bool
	MetricType         int
	Origin             string
	CommunityOp        string
	Community          string
	CommunityAdd       string
	CommunityDelete    []string
	LoadBalance        string
	NextPolicy         bool
}

func thenFieldsOf12513(term *PolicyTerm) thenFields12513 {
	return thenFields12513{
		Action:             term.Action,
		LocalPreference:    term.LocalPreference,
		HasLocalPreference: term.HasLocalPreference,
		Metric:             term.Metric,
		HasMetric:          term.HasMetric,
		MetricType:         term.MetricType,
		Origin:             term.Origin,
		CommunityOp:        term.CommunityOp,
		Community:          term.Community,
		CommunityAdd:       term.CommunityAdd,
		CommunityDelete:    term.CommunityDelete,
		LoadBalance:        term.LoadBalance,
		NextPolicy:         term.NextPolicy,
	}
}

// communityLists12513 defines the community-list names the delete rows use.
const communityLists12513 = "community L1 members 65001:1; community L2 members 65001:2; "

func compileTerm12513(t *testing.T, text string) *PolicyTerm {
	t.Helper()
	tree, parseErrors := NewParser(text).Parse()
	if len(parseErrors) > 0 {
		t.Fatalf("parse %q: %v", text, parseErrors)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected %q: %v", text, err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 1 {
		t.Fatalf("%q: want policy P with one term, got %+v", text, ps)
	}
	return ps.Terms[0]
}

// FAIL-ON-REVERT (#12513): term-LINE `term t then <action> <value>;` for the
// six value-carrying actions beyond next-hop/prepend must land in the typed
// fields, exactly as the block spelling does. Before the fix the generic
// `then` branch stored the keyword in PolicyTerm.Action and dropped the
// value. Only the term-line spelling misrouted: compact `term t { then
// <action> <value>; }` is normalized to the block form. Reverting the
// dispatch fails every value row (Action=<keyword>, typed field unset); the
// block-parity check fails with it.
func TestPolicyTermLineValuesRetained12513(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		want         thenFields12513
	}{
		{"local-preference", "local-preference 200", thenFields12513{LocalPreference: 200, HasLocalPreference: true}},
		{"local-preference zero", "local-preference 0", thenFields12513{HasLocalPreference: true}},
		{"local-preference u32 max", "local-preference 4294967295", thenFields12513{LocalPreference: 4294967295, HasLocalPreference: true}},
		{"metric", "metric 10", thenFields12513{Metric: 10, HasMetric: true}},
		{"metric zero", "metric 0", thenFields12513{HasMetric: true}},
		{"metric u32 max", "metric 4294967295", thenFields12513{Metric: 4294967295, HasMetric: true}},
		{"metric-type 1", "metric-type 1", thenFields12513{MetricType: 1}},
		{"metric-type 2", "metric-type 2", thenFields12513{MetricType: 2}},
		{"origin igp", "origin igp", thenFields12513{Origin: "igp"}},
		{"origin egp", "origin egp", thenFields12513{Origin: "egp"}},
		{"origin incomplete", "origin incomplete", thenFields12513{Origin: "incomplete"}},
		{"community add", "community add 65001:100", thenFields12513{CommunityOp: "add", CommunityAdd: "65001:100"}},
		{"community set", "community set 65001:100", thenFields12513{CommunityOp: "set", Community: "65001:100"}},
		{"community bare replace", "community 65001:100", thenFields12513{Community: "65001:100"}},
		{"community none", "community none", thenFields12513{CommunityOp: "none"}},
		{"community delete", "community delete L1", thenFields12513{CommunityOp: "delete", CommunityDelete: []string{"L1"}}},
		{"community add list", "community add [ 65001:1 65001:2 ]", thenFields12513{CommunityOp: "add", CommunityAdd: "65001:1 65001:2"}},
		{"community set list", "community set [ 65001:1 65001:2 ]", thenFields12513{CommunityOp: "set", Community: "65001:1 65001:2"}},
		{"community bare list", "community [ 65001:1 65001:2 ]", thenFields12513{Community: "65001:1 65001:2"}},
		{"community delete list", "community delete [ L1 L2 ]", thenFields12513{CommunityOp: "delete", CommunityDelete: []string{"L1", "L2"}}},
		{"load-balance per-packet", "load-balance per-packet", thenFields12513{LoadBalance: "per-packet"}},
		{"load-balance consistent-hash", "load-balance consistent-hash", thenFields12513{LoadBalance: "consistent-hash"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			termLine := compileTerm12513(t, "policy-options { "+communityLists12513+
				"policy-statement P { term t then "+tc.action+"; } }")
			if got := thenFieldsOf12513(termLine); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("term-line `then %s` compiled to\n %+v\nwant\n %+v", tc.action, got, tc.want)
			}
			block := compileTerm12513(t, "policy-options { "+communityLists12513+
				"policy-statement P { term t { then { "+tc.action+"; } } } }")
			if got, want := thenFieldsOf12513(termLine), thenFieldsOf12513(block); !reflect.DeepEqual(got, want) {
				t.Fatalf("term-line `then %s` diverged from the block spelling:\n term-line %+v\n block     %+v", tc.action, got, want)
			}
		})
	}
}

// TestPolicyTermLineControlsAndChains12513 pins the edges of the dispatch.
// accept and reject stay terminal actions, an unknown word keeps the generic
// `then` branch (its validation is #12517's), chains keep every action, and
// a bracketed community list ends where the chain resumes. RED-on-mutation:
// dispatching every token after `then` turns the unknown row's Action into
// "" and lets `then foo next policy` commit.
func TestPolicyTermLineControlsAndChains12513(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       thenFields12513
	}{
		{"accept control", "term t then accept;", thenFields12513{Action: "accept"}},
		{"reject control", "term t then reject;", thenFields12513{Action: "reject"}},
		{"unknown word keeps the generic branch", "term t then foo;", thenFields12513{Action: "foo"}},
		{
			"community then local-preference then accept",
			"term t then community add 65001:100 local-preference 200 accept;",
			thenFields12513{Action: "accept", LocalPreference: 200, HasLocalPreference: true, CommunityOp: "add", CommunityAdd: "65001:100"},
		},
		{
			"every value action chained",
			"term t then local-preference 200 metric 10 metric-type 2 origin igp community add 65001:100 load-balance per-packet accept;",
			thenFields12513{
				Action: "accept", LocalPreference: 200, HasLocalPreference: true, Metric: 10, HasMetric: true,
				MetricType: 2, Origin: "igp", CommunityOp: "add", CommunityAdd: "65001:100", LoadBalance: "per-packet",
			},
		},
		{
			"bracketed community list then a chained action",
			"term t then community add [ 65001:1 65001:2 ] local-preference 200 reject;",
			thenFields12513{Action: "reject", LocalPreference: 200, HasLocalPreference: true, CommunityOp: "add", CommunityAdd: "65001:1 65001:2"},
		},
		{
			"compact accept tail reads the whole community list",
			"term t { then accept community delete [ L1 L2 ]; }",
			thenFields12513{Action: "accept", CommunityOp: "delete", CommunityDelete: []string{"L1", "L2"}},
		},
		{
			"value action then next policy",
			"term t then local-preference 200 next policy;",
			thenFields12513{LocalPreference: 200, HasLocalPreference: true, NextPolicy: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			term := compileTerm12513(t, "policy-options { "+communityLists12513+"policy-statement P { "+tc.text+" } }")
			if got := thenFieldsOf12513(term); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("%s compiled to\n %+v\nwant\n %+v", tc.text, got, tc.want)
			}
		})
	}

	tree, parseErrors := NewParser("policy-options { policy-statement P { term t then foo next policy; } }").Parse()
	if len(parseErrors) > 0 {
		t.Fatalf("parse: %v", parseErrors)
	}
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "conflicts with terminal action `then foo`") {
		t.Fatalf("`then foo next policy` must stay the strict #11780 conflict with `then foo`, got %v", err)
	}
}

// TestPolicyTermLineDispatchCoversSchemaValueLeaves12513 keeps the term-line
// dispatch in step with the schema: every value-carrying term `then` leaf
// must reach its operand reader rather than term.Action. next, next-hop, and
// as-path-prepend have their own #11780/#12070 dispatch.
func TestPolicyTermLineDispatchCoversSchemaValueLeaves12513(t *testing.T) {
	examples := map[string]string{"community": "add 65001:100", "load-balance": "per-packet"}
	thenSchema := policyTermThenSchema8939()
	if thenSchema == nil || len(thenSchema.children) == 0 {
		t.Fatal("term-level then schema did not resolve")
	}
	covered := 0
	for leaf, node := range thenSchema.children {
		if node == nil || node.args == 0 || leaf == "next" || leaf == "next-hop" || leaf == "as-path-prepend" {
			continue
		}
		example, ok := examples[leaf]
		if !ok && len(node.valueExamples) > 0 {
			example, ok = node.valueExamples[0], true
		}
		if !ok {
			t.Fatalf("term then leaf %q has no example value; add one to this test", leaf)
		}
		term := compileTerm12513(t, "policy-options { policy-statement P { term t then "+leaf+" "+example+"; } }")
		if term.Action != "" {
			t.Errorf("term-line `then %s %s` stored Action=%q instead of reaching its operand reader", leaf, example, term.Action)
		}
		covered++
	}
	if covered != 6 {
		t.Fatalf("checked %d value leaves, want the 6 #12513 actions", covered)
	}
}

// TestPolicyThenInvalidOperandsRejected12513 is the compiled-gate half of
// #12513: packed `then` tails bypass the schema walk, so out-of-range,
// non-integer, missing, and keyword operands must fail strict compilation
// naming the policy, term, leaf, and value, and downgrade to a warning on the
// tolerant path. RED before the fold: every term-line row compiled clean, and
// the `then accept` rows compiled clean even before #12513.
func TestPolicyThenInvalidOperandsRejected12513(t *testing.T) {
	if !lenientCompileOpts().lenientPolicyThenOperands {
		t.Fatal("lenientPolicyThenOperands is not registered in lenientCompileOpts")
	}
	spellings := []struct{ name, format string }{
		{"term-line", "term t then %s;"},
		{"term-line after accept", "term t then accept %s;"},
		{"compact after accept", "term t { then accept %s; }"},
	}
	for _, tc := range []struct {
		action, leaf, value string
		termLineOnly        bool // the operand is only refused in the dispatched slot
	}{
		{action: "local-preference 4294967296", leaf: "local-preference", value: "4294967296"},
		{action: "local-preference -1", leaf: "local-preference", value: "-1"},
		{action: "local-preference abc", leaf: "local-preference", value: "abc"},
		{action: "local-preference accept", leaf: "local-preference", value: "accept"},
		{action: "local-preference", leaf: "local-preference", value: ""},
		{action: "metric 4294967296", leaf: "metric", value: "4294967296"},
		{action: "metric -1", leaf: "metric", value: "-1"},
		{action: "metric reject", leaf: "metric", value: "reject"},
		{action: "metric-type 3", leaf: "metric-type", value: "3"},
		{action: "metric-type 0", leaf: "metric-type", value: "0"},
		{action: "metric-type abc", leaf: "metric-type", value: "abc"},
		{action: "origin bogus", leaf: "origin", value: "bogus"},
		{action: "origin accept", leaf: "origin", value: "accept"},
		{action: "origin reject", leaf: "origin", value: "reject"},
		{action: "load-balance", leaf: "load-balance", value: ""},
		{action: "load-balance reject", leaf: "load-balance", value: "reject", termLineOnly: true},
		{action: "community", leaf: "community", value: ""},
		{action: "community add", leaf: "community", value: ""},
		{action: "community add [ 65001:1 reject ]", leaf: "community", value: "reject"},
	} {
		for _, sp := range spellings {
			if tc.termLineOnly && sp.name != "term-line" {
				continue
			}
			text := "policy-options { policy-statement P { " + strings.Replace(sp.format, "%s", tc.action, 1) + " } }"
			t.Run(sp.name+"/"+tc.action, func(t *testing.T) {
				assertPolicyThenOperandRejected12513(t, text, tc.leaf, tc.value)
			})
		}
	}
	// The typed-field half also covers the child spelling for callers that
	// compile without the schema walk.
	for _, tc := range []struct{ action, leaf, value string }{
		{"local-preference 4294967296", "local-preference", "4294967296"},
		{"metric -1", "metric", "-1"},
		{"metric-type 3", "metric-type", "3"},
		{"origin bogus", "origin", "bogus"},
	} {
		text := "policy-options { policy-statement P { term t { then { " + tc.action + "; } } } }"
		t.Run("block/"+tc.action, func(t *testing.T) {
			assertPolicyThenOperandRejected12513(t, text, tc.leaf, tc.value)
		})
	}
}

func assertPolicyThenOperandRejected12513(t *testing.T, text, leaf, value string) {
	t.Helper()
	tree, parseErrors := NewParser(text).Parse()
	if len(parseErrors) > 0 {
		t.Fatalf("parse %q: %v", text, parseErrors)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict CompileConfig accepted %q", text)
	}
	for _, want := range []string{`policy-statement "P"`, `term "t"`, "then " + leaf + ":", `invalid value "` + value + `"`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%q: error %q does not contain %q", text, err.Error(), want)
		}
	}
	lenient, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected %q: %v", text, err)
	}
	for _, warning := range lenient.Warnings {
		if strings.Contains(warning, "policy then operand (downgraded to warning on tolerant path)") &&
			strings.Contains(warning, "then "+leaf+":") {
			return
		}
	}
	t.Fatalf("%q: tolerant warnings %q lack the downgraded then %s operand", text, lenient.Warnings, leaf)
}
