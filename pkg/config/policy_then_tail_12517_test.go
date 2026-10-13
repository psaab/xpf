package config_test

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

type policyThenTailCase12517 struct {
	name   string
	action string
	tail   string
}

func policyThenTailCases12517() []policyThenTailCase12517 {
	return []policyThenTailCase12517{
		{name: "local-preference", action: "local-preference 200", tail: "foo"},
		{name: "metric", action: "metric 10", tail: "foo"},
		{name: "metric-type", action: "metric-type 1", tail: "foo"},
		{name: "origin", action: "origin igp", tail: "egp"},
		{name: "community-none", action: "community none", tail: "foo"},
		{name: "community-add", action: "community add [ 65001:100 ]", tail: "foo"},
		{name: "community-set", action: "community set [ 65001:100 ]", tail: "foo"},
		{name: "community-value", action: "community [ 65001:100 ]", tail: "foo"},
		{name: "load-balance", action: "load-balance per-packet", tail: "foo"},
		{name: "accept", action: "accept", tail: "foo"},
		{name: "reject", action: "reject", tail: "foo"},
		{name: "from-protocol", action: "metric 10", tail: "protocol static"},
		{name: "from-prefix-list", action: "metric 10", tail: "prefix-list PL1"},
		{name: "from-route-filter", action: "metric 10", tail: "route-filter 10.0.0.0/8 exact"},
		{name: "from-family", action: "metric 10", tail: "family inet"},
		{name: "from-neighbor", action: "metric 10", tail: "neighbor 192.0.2.1"},
		{name: "from-interface", action: "metric 10", tail: "interface ge-0/0/0"},
		{name: "from-instance", action: "metric 10", tail: "instance master"},
		{name: "from-rib", action: "metric 10", tail: "rib inet.0"},
		{name: "from-as-path", action: "metric 10", tail: "as-path AP1"},
	}
}

func policyThenTailExpr12517(tc policyThenTailCase12517) string {
	return tc.action + " " + tc.tail
}

func policyThenTailSpellings12517(tc policyThenTailCase12517) []struct {
	name, text string
} {
	expr := policyThenTailExpr12517(tc)
	return []struct{ name, text string }{
		{
			name: "compact",
			text: "policy-options { policy-statement P { term t { then " + expr + "; } } }",
		},
		{
			name: "term-line",
			text: "policy-options { policy-statement P { term t then " + expr + "; } }",
		},
		{
			name: "braced",
			text: "policy-options { policy-statement P { term t { then { " + expr + "; } } } }",
		},
		{
			name: "set-path",
			text: "set policy-options policy-statement P term t then " + expr,
		},
	}
}

// policyTree12517 parses hierarchical text, or one or more `set` lines through
// the store's grouped set parser, which keeps `[ ... ]` provenance.
func policyTree12517(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	if strings.HasPrefix(text, "set ") {
		tree := &config.ConfigTree{}
		for _, line := range strings.Split(text, "\n") {
			_, path, quoted, grouped, closed, err := config.ParseSetVerbGroupedClosed(line)
			if err != nil {
				t.Fatalf("ParseSetVerbGroupedClosed(%q): %v", line, err)
			}
			if err := tree.SetPathQuotedGrouped(path, quoted, grouped, closed); err != nil {
				t.Fatalf("SetPathQuotedGrouped(%q): %v", line, err)
			}
		}
		return tree
	}
	tree, parseErrs := config.NewParser(text).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse %q: %v", text, parseErrs)
	}
	return tree
}

func policyThenTailStore12517(t *testing.T) *configstore.Store {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	return store
}

// FAIL-ON-REVERT (#12517): the compiler must retain evidence of every unknown
// then-tail token. All parser spellings feed the same strict gate and tolerant
// warning; from-words must not silently become unvalidated matches.
func TestPolicyThenTailRejectedAcrossSpellings12517(t *testing.T) {
	for _, tc := range policyThenTailCases12517() {
		for _, spelling := range policyThenTailSpellings12517(tc) {
			t.Run(tc.name+"/"+spelling.name, func(t *testing.T) {
				tree := policyTree12517(t, spelling.text)
				t.Run("CompileConfig", func(t *testing.T) {
					if _, err := config.CompileConfig(tree); err == nil {
						t.Errorf("CompileConfig accepted unknown then-tail %q in %q", tc.tail, spelling.text)
					}
				})
				t.Run("CompileConfigLenient", func(t *testing.T) {
					cfg, err := config.CompileConfigLenient(tree)
					if err != nil {
						t.Fatalf("CompileConfigLenient rejected persisted then-tail: %v", err)
					}
					foundWarning := false
					for _, warning := range cfg.Warnings {
						if strings.Contains(warning, "policy then operand (downgraded to warning on tolerant path)") &&
							strings.Contains(warning, strings.Fields(tc.tail)[0]) {
							foundWarning = true
							break
						}
					}
					if !foundWarning {
						t.Errorf("lenient compile omitted then-tail warning for %q: %v", tc.tail, cfg.Warnings)
					}
				})
			})
		}
	}
}

// CheckText, LoadOverride/LoadMerge + CommitCheck, and Commit are separate
// strict entry points; tolerant ingress is covered independently below.
func TestPolicyThenTailStrictStoreChannels12517(t *testing.T) {
	for _, tc := range policyThenTailCases12517() {
		setText := "set policy-options policy-statement P term t then " + policyThenTailExpr12517(tc)
		t.Run(tc.name, func(t *testing.T) {
			t.Run("CheckText", func(t *testing.T) {
				if _, err := configstore.CheckText(setText, 0); err == nil {
					t.Errorf("CheckText accepted %q", setText)
				}
			})
			for _, load := range []struct {
				name string
				fn   func(*configstore.Store, string) error
			}{
				{name: "LoadOverride", fn: (*configstore.Store).LoadOverride},
				{name: "LoadMerge", fn: (*configstore.Store).LoadMerge},
			} {
				t.Run(load.name, func(t *testing.T) {
					store := policyThenTailStore12517(t)
					if err := load.fn(store, setText); err != nil {
						t.Fatalf("%s rejected input before commit validation: %v", load.name, err)
					}
					if _, err := store.CommitCheck(); err == nil {
						t.Errorf("%s + CommitCheck accepted %q", load.name, setText)
					}
					if _, err := store.Commit(); err == nil {
						t.Errorf("%s + Commit accepted %q", load.name, setText)
					}
				})
			}
		})
	}
}

func TestPolicyThenTailTolerantSyncWarns12517(t *testing.T) {
	for _, tc := range policyThenTailCases12517() {
		syncText := policyThenTailSpellings12517(tc)[1].text
		t.Run(tc.name, func(t *testing.T) {
			store, err := configstore.New(filepath.Join(t.TempDir(), "config"))
			if err != nil {
				t.Fatalf("configstore.New: %v", err)
			}
			cfg, err := store.SyncApply(syncText, nil)
			if err != nil {
				t.Fatalf("SyncApply rejected persisted then-tail: %v", err)
			}
			foundWarning := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "policy then operand (downgraded to warning on tolerant path)") &&
					strings.Contains(warning, strings.Fields(tc.tail)[0]) {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("SyncApply omitted then-tail warning for %q: %v", tc.tail, cfg.Warnings)
			}
		})
	}
}

func TestQuotedThenNextHopRejectRemainsDeny12517(t *testing.T) {
	cases := []struct {
		name, text string
	}{
		{
			name: "term-line quoted then",
			text: `policy-options { policy-statement P { term t from protocol static then accept as-path-prepend 65001 "then" next-hop reject; term u then accept; } }`,
		},
		{
			name: "compact quoted then",
			text: `policy-options { policy-statement P { term t then accept as-path-prepend 65001 "then" next-hop reject; term u then accept; } }`,
		},
		{
			name: "term-line bracketed then",
			text: `policy-options { policy-statement P { term t from protocol static then accept as-path-prepend [ 65001 "then" ] next-hop reject; term u then accept; } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := policyTree12517(t, tc.text)
			t.Run("CompileConfig", func(t *testing.T) {
				if _, err := config.CompileConfig(tree); err == nil ||
					!strings.Contains(err.Error(), `unsupported next-hop "reject"`) {
					t.Errorf("strict compile error = %v, want unsupported next-hop reject", err)
				}
			})
			t.Run("CheckText", func(t *testing.T) {
				if _, err := configstore.CheckText(tc.text, 0); err == nil {
					t.Errorf("CheckText accepted quoted-then next-hop reject in %q", tc.text)
				}
			})
			for _, load := range []struct {
				name string
				fn   func(*configstore.Store, string) error
			}{
				{name: "LoadOverride", fn: (*configstore.Store).LoadOverride},
				{name: "LoadMerge", fn: (*configstore.Store).LoadMerge},
			} {
				t.Run(load.name, func(t *testing.T) {
					store := policyThenTailStore12517(t)
					if err := load.fn(store, tc.text); err != nil {
						t.Fatalf("%s rejected input before commit validation: %v", load.name, err)
					}
					if _, err := store.CommitCheck(); err == nil {
						t.Errorf("%s + CommitCheck accepted quoted-then next-hop reject", load.name)
					}
					if _, err := store.Commit(); err == nil {
						t.Errorf("%s + Commit accepted quoted-then next-hop reject", load.name)
					}
				})
			}
			t.Run("CompileConfigLenient", func(t *testing.T) {
				cfg, err := config.CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("lenient compile rejected persisted R7-F2 config: %v", err)
				}
				term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
				if term.Action != "reject" {
					t.Errorf("R7-F2 tolerant action = %q, want reject", term.Action)
				}
			})
			t.Run("SyncApply", func(t *testing.T) {
				store, err := configstore.New(filepath.Join(t.TempDir(), "sync"))
				if err != nil {
					t.Fatalf("configstore.New for SyncApply: %v", err)
				}
				cfg, err := store.SyncApply(tc.text, nil)
				if err != nil {
					t.Fatalf("SyncApply rejected persisted R7-F2 config: %v", err)
				}
				term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
				if term.Action != "reject" {
					t.Errorf("SyncApply R7-F2 action = %q, want reject", term.Action)
				}
			})
		})
	}
}
func TestValidThenActionBoundaries12517(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		wantDelete int
	}{
		{
			name:       "compact chaining and multi-list community delete",
			text:       `policy-options { community C1 members 65000:1; community C2 members 65000:2; policy-statement P { term t from protocol static then local-preference 200 metric 10 community delete [ C1 C2 ] accept; } }`,
			wantDelete: 2,
		},
		{
			name: "braced action chain",
			text: `policy-options { policy-statement P { term t { then { local-preference 200; metric 10; accept; } } } }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.CompileConfig(policyTree12517(t, tc.text))
			if err != nil {
				t.Fatalf("valid action chain rejected: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if term.Action != "accept" || term.LocalPreference != 200 ||
				!term.HasLocalPreference || term.Metric != 10 || !term.HasMetric {
				t.Fatalf("action chain fields = Action:%q LocalPreference:%d/%v Metric:%d/%v",
					term.Action, term.LocalPreference, term.HasLocalPreference,
					term.Metric, term.HasMetric)
			}
			if len(term.CommunityDelete) != tc.wantDelete {
				t.Fatalf("community delete names = %v, want %d", term.CommunityDelete, tc.wantDelete)
			}
		})
	}
}

// FAIL-ON-REVERT (#12517 B5): the from-match words #12517 adds for then-tail
// detection must not join the #12513 operand-keyword map. A community defined
// with one of those names stays a valid term-line or compact `then community`
// value: strict commit accepts it and the operation keeps its resolved value.
// RED when the five words are merged into policyTermFromMatchInlineKeywords12070:
// every term-line row fails with `"<name>" is a policy keyword`.
func TestThenCommunityNamedLikeFromWordStillCompiles12517(t *testing.T) {
	for _, tc := range []struct {
		name, text, op, value string
		deleteNames           []string
	}{
		{name: "term-line add neighbor", text: "community neighbor members 65001:7; policy-statement P { term t then community add neighbor accept; }", op: "add", value: "65001:7"},
		{name: "term-line set rib", text: "community rib members 65001:7; policy-statement P { term t then community set rib accept; }", op: "set", value: "65001:7"},
		{name: "term-line delete instance", text: "community instance members 65001:7; policy-statement P { term t then community delete instance accept; }", op: "delete", deleteNames: []string{"instance"}},
		{name: "term-line bare family", text: "community family members 65001:7; policy-statement P { term t then community family accept; }", op: "", value: "65001:7"},
		{name: "term-line add interface", text: "community interface members 65001:7; policy-statement P { term t then community add interface accept; }", op: "add", value: "65001:7"},
		{name: "compact accept add neighbor", text: "community neighbor members 65001:7; policy-statement P { term t { then accept community add neighbor; } }", op: "add", value: "65001:7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.CompileConfig(policyTree12517(t, "policy-options { "+tc.text+" }"))
			if err != nil {
				t.Fatalf("strict compile rejected a community named like a from-match word: %v", err)
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if term.Action != "accept" || term.CommunityOp != tc.op {
				t.Fatalf("Action=%q CommunityOp=%q, want accept/%q", term.Action, term.CommunityOp, tc.op)
			}
			got := term.Community
			if tc.op == "add" {
				got = term.CommunityAdd
			}
			if tc.op != "delete" && got != tc.value {
				t.Fatalf("community %s value = %q, want resolved %q", tc.op, got, tc.value)
			}
			if tc.op == "delete" && strings.Join(term.CommunityDelete, " ") != strings.Join(tc.deleteNames, " ") {
				t.Fatalf("community delete names = %v, want %v", term.CommunityDelete, tc.deleteNames)
			}
		})
	}
}

// FAIL-ON-REVERT (#12517 B2): an unknown statement in a braced or set-path
// `then` block is the #10707 open-world case, not a #12517 tail. Strict
// compile stays compatible and reports it through the #10707 warning only.
// RED when the child reader records unknown statement keywords as tails:
// every row fails strict compile with the #12517 diagnostic.
func TestOpenWorldThenStatementStaysWarnOnly12517(t *testing.T) {
	for _, tc := range []struct {
		name, text, word string
	}{
		{name: "braced misspelled accept", text: "policy-options { policy-statement P { term t { from { protocol bgp; } then { accept; acccept; } } } }", word: "acccept"},
		{name: "braced unknown first statement", text: "policy-options { policy-statement P { term t { then { foo; accept; } } } }", word: "foo"},
		{name: "set-path unknown statement", text: "set policy-options policy-statement P term t then foo", word: "foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.CompileConfig(policyTree12517(t, tc.text))
			if err != nil {
				t.Fatalf("open-world then statement %q rejected at strict compile: %v", tc.word, err)
			}
			openWorld := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "policy then operand") {
					t.Fatalf("open-world then statement produced a #12517 warning: %q", warning)
				}
				if strings.Contains(warning, "#10707") && strings.Contains(warning, strconv.Quote(tc.word)) {
					openWorld = true
				}
			}
			if !openWorld {
				t.Fatalf("strict compile omitted the #10707 warning for %q: %v", tc.word, cfg.Warnings)
			}
		})
	}
}

// FAIL-ON-REVERT (#12517 B2): a bare `route-filter` marker after `then accept`
// is evidence for both the #11779 from-match gate and the #12517 tail gate.
// The tail gate runs later so the specific #11779 diagnostic reaches the
// operator. RED when the tail check runs before #11779 (for example inside
// validatePolicyThenOperandsStrict): strict compile reports the tail instead.
func TestBareRouteFilterAfterThenKeepsFromDiagnostic12517(t *testing.T) {
	for _, text := range []string{
		"policy-options { policy-statement P { term T then accept route-filter; } }",
		"policy-options { policy-statement P { term T from protocol static then accept route-filter; } }",
	} {
		t.Run(text, func(t *testing.T) {
			_, err := config.CompileConfig(policyTree12517(t, text))
			if err == nil || !strings.Contains(err.Error(), "supported `from` clauses") {
				t.Fatalf("strict compile error = %v, want the #11779 supported-from diagnostic", err)
			}
		})
	}
}

type policyThenLoad12517 struct {
	name string
	fn   func(*configstore.Store, string) error
}

// policyThenLoads12517 are the candidate-loading store channels. A set-path
// text also goes through SetFromInput, the operator CLI/gRPC/REST `set` path.
func policyThenLoads12517(text string) []policyThenLoad12517 {
	loads := []policyThenLoad12517{
		{name: "LoadOverride", fn: (*configstore.Store).LoadOverride},
		{name: "LoadMerge", fn: (*configstore.Store).LoadMerge},
	}
	if strings.HasPrefix(text, "set ") {
		loads = append(loads, policyThenLoad12517{name: "SetFromInput", fn: func(s *configstore.Store, text string) error {
			for _, line := range strings.Split(text, "\n") {
				if err := s.SetFromInput(strings.TrimPrefix(line, "set ")); err != nil {
					return err
				}
			}
			return nil
		}})
	}
	return loads
}

// policyThenCommitCheck12517 loads text into a fresh candidate and returns
// the CommitCheck result; a load error fails the test before commit checks.
func policyThenCommitCheck12517(t *testing.T, load policyThenLoad12517, text string) (*config.Config, error) {
	t.Helper()
	store := policyThenTailStore12517(t)
	if err := load.fn(store, text); err != nil {
		t.Fatalf("%s rejected input before commit validation: %v", load.name, err)
	}
	return store.CommitCheck()
}

// FAIL-ON-REVERT (#12517 B1): a `[ ... ]` community list after a chained
// action is one value. expandFlatRun dropped bracket provenance from the
// statements it cut out of a run, so d042225ed's child reader counted the
// second member as an unknown modifier and strict commit rejected configs
// that master commits. RED with the list extent ignored (one value token
// regardless of brackets): every row fails with `unknown modifier "65001:2"`.
func TestChainedBracketedCommunityListCommits12517(t *testing.T) {
	for _, list := range []struct{ name, clause, op string }{
		{name: "add", clause: "community add [ 65001:1 65001:2 ]", op: "add"},
		{name: "set", clause: "community set [ 65001:1 65001:2 ]", op: "set"},
		{name: "bare", clause: "community [ 65001:1 65001:2 ]", op: ""},
	} {
		chain := "local-preference 200 metric 10 " + list.clause + " accept"
		for _, spelling := range []struct {
			name, text string
			chained    bool
		}{
			{name: "compact chain", text: "policy-options { policy-statement P { term t { then " + chain + "; } } }", chained: true},
			{name: "term-line chain", text: "policy-options { policy-statement P { term t then " + chain + "; } }", chained: true},
			{name: "braced chain", text: "policy-options { policy-statement P { term t { then { " + chain + "; } } } }", chained: true},
			{name: "braced accept first", text: "policy-options { policy-statement P { term t { then { accept " + list.clause + "; } } } }"},
			{name: "set-path chain", text: "set policy-options policy-statement P term t then " + chain, chained: true},
		} {
			check := func(t *testing.T, cfg *config.Config) {
				t.Helper()
				term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
				value := term.Community
				if list.op == "add" {
					value = term.CommunityAdd
				}
				if term.Action != "accept" || term.CommunityOp != list.op || value != "65001:1 65001:2" {
					t.Fatalf("Action=%q CommunityOp=%q value=%q, want accept/%q/%q",
						term.Action, term.CommunityOp, value, list.op, "65001:1 65001:2")
				}
				if spelling.chained && (term.LocalPreference != 200 || term.Metric != 10) {
					t.Fatalf("chain lost its actions: LocalPreference=%d Metric=%d", term.LocalPreference, term.Metric)
				}
			}
			t.Run(list.name+"/"+spelling.name, func(t *testing.T) {
				t.Run("CompileConfig", func(t *testing.T) {
					cfg, err := config.CompileConfig(policyTree12517(t, spelling.text))
					if err != nil {
						t.Fatalf("strict compile rejected a valid bracketed list: %v", err)
					}
					check(t, cfg)
				})
				t.Run("CheckText", func(t *testing.T) {
					cfg, err := configstore.CheckText(spelling.text, 0)
					if err != nil {
						t.Fatalf("CheckText rejected a valid bracketed list: %v", err)
					}
					check(t, cfg)
				})
				for _, load := range policyThenLoads12517(spelling.text) {
					t.Run(load.name, func(t *testing.T) {
						cfg, err := policyThenCommitCheck12517(t, load, spelling.text)
						if err != nil {
							t.Fatalf("%s + CommitCheck rejected a valid bracketed list: %v", load.name, err)
						}
						check(t, cfg)
					})
				}
			})
		}
	}
}

// FAIL-ON-REVERT (#12517 B3): a token after the closing bracket of a
// `then community` list is a tail in every spelling, chained or not.
// RED with bracketed lists exempted from the tail check (d042225ed counted
// every token once any key was bracketed): every child-path row accepts the
// trailing value. RED with bracket provenance left off expandFlatRun's
// segments: the chained child-path rows accept it.
func TestTokenAfterBracketedCommunityListRejected12517(t *testing.T) {
	const defs = "community L1 members 65001:1; community L2 members 65001:2; community L3 members 65001:3; "
	const setDefs = "set policy-options community L1 members 65001:1\n" +
		"set policy-options community L2 members 65001:2\n" +
		"set policy-options community L3 members 65001:3\n"
	for _, list := range []struct{ name, clause, extra string }{
		{name: "add", clause: "community add [ 65001:1 65001:2 ] 65001:3", extra: "65001:3"},
		{name: "set", clause: "community set [ 65001:1 65001:2 ] 65001:3", extra: "65001:3"},
		{name: "bare", clause: "community [ 65001:1 65001:2 ] 65001:3", extra: "65001:3"},
		{name: "delete", clause: "community delete [ L1 L2 ] L3", extra: "L3"},
	} {
		want := `policy-options policy-statement "P" term "t" then community: unknown modifier "` + list.extra + `"`
		// The list ends the chain: with a sibling after the stray value, a
		// set-path replay folds both onto the community leaf and the older
		// #8437 fused-statement walk rejects it first, with its own message.
		chain := "local-preference 200 " + list.clause
		for _, spelling := range []struct{ name, text string }{
			{name: "compact", text: "policy-options { " + defs + "policy-statement P { term t { then " + list.clause + "; } } }"},
			{name: "term-line", text: "policy-options { " + defs + "policy-statement P { term t then " + list.clause + "; } }"},
			{name: "braced", text: "policy-options { " + defs + "policy-statement P { term t { then { " + list.clause + "; } } } }"},
			{name: "set-path", text: setDefs + "set policy-options policy-statement P term t then " + list.clause},
			{name: "compact chain", text: "policy-options { " + defs + "policy-statement P { term t { then " + chain + "; } } }"},
			{name: "term-line chain", text: "policy-options { " + defs + "policy-statement P { term t then " + chain + "; } }"},
			{name: "braced chain", text: "policy-options { " + defs + "policy-statement P { term t { then { " + chain + "; } } } }"},
			{name: "set-path chain", text: setDefs + "set policy-options policy-statement P term t then " + chain},
		} {
			t.Run(list.name+"/"+spelling.name, func(t *testing.T) {
				tree := policyTree12517(t, spelling.text)
				t.Run("CompileConfig", func(t *testing.T) {
					if _, err := config.CompileConfig(tree); err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("strict compile error = %v, want %q", err, want)
					}
				})
				t.Run("CompileConfigLenient", func(t *testing.T) {
					cfg, err := config.CompileConfigLenient(tree)
					if err != nil {
						t.Fatalf("tolerant compile rejected a persisted config: %v", err)
					}
					if !hasPolicyThenTailWarning12517(cfg.Warnings, want) {
						t.Fatalf("tolerant compile omitted %q: %v", want, cfg.Warnings)
					}
				})
				t.Run("CheckText", func(t *testing.T) {
					if _, err := configstore.CheckText(spelling.text, 0); err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("CheckText error = %v, want %q", err, want)
					}
				})
				for _, load := range policyThenLoads12517(spelling.text) {
					t.Run(load.name, func(t *testing.T) {
						if _, err := policyThenCommitCheck12517(t, load, spelling.text); err == nil || !strings.Contains(err.Error(), want) {
							t.Fatalf("%s + CommitCheck error = %v, want %q", load.name, err, want)
						}
					})
				}
			})
		}
	}
}

// hasPolicyThenTailWarning12517 reports the tolerant downgrade of want.
func hasPolicyThenTailWarning12517(warnings []string, want string) bool {
	for _, warning := range warnings {
		if strings.HasPrefix(warning, "policy then operand (downgraded to warning on tolerant path): ") &&
			strings.Contains(warning, want) {
			return true
		}
	}
	return false
}

// FAIL-ON-REVERT (#12517): `show configuration | display set` (FormatSet)
// prints a leaf's `[ ... ]` list without brackets, so the replayed community
// statement carries no bracket provenance. Such a value run stays one value
// and the replay commits, as on master. RED with an unbracketed child-path
// value limited to one token (d042225ed's counter): every add, set, and bare
// row fails with `unknown modifier "65001:2"`.
func TestDisplaySetCommunityListReplays12517(t *testing.T) {
	for _, text := range []string{
		"policy-options { policy-statement P { term t { then { community add [ 65001:1 65001:2 ]; accept; } } } }",
		"policy-options { policy-statement P { term t { then community set [ 65001:1 65001:2 ]; } } }",
		"policy-options { policy-statement P { term t then community [ 65001:1 65001:2 ] accept; } }",
		"policy-options { community L1 members 65001:1; community L2 members 65001:2; policy-statement P { term t { then { community delete [ L1 L2 ]; accept; } } } }",
	} {
		t.Run(text, func(t *testing.T) {
			display := strings.TrimSpace(policyTree12517(t, text).FormatSet())
			if strings.Contains(display, "[") {
				t.Fatalf("display set kept the brackets; this cell needs the bracket-free replay:\n%s", display)
			}
			if _, err := configstore.CheckText(display, 0); err != nil {
				t.Fatalf("CheckText rejected display-set output: %v\n%s", err, display)
			}
			load := policyThenLoads12517(display)
			if _, err := policyThenCommitCheck12517(t, load[len(load)-1], display); err != nil {
				t.Fatalf("%s replay of display-set output failed CommitCheck: %v\n%s", load[len(load)-1].name, err, display)
			}
		})
	}
}

// FAIL-ON-REVERT (#12517 B4): the packed compact and term-line spellings have
// no statement boundary, so an unknown word after `then` lands in Action and
// its operands fall through to the main switch, and a token after `next
// policy` was dropped. Both are rejected at strict commit and warn on the
// tolerant path, like the braced and set-path `next` tail the schema walk
// rejects. RED with the generic-branch and `next` tail records removed:
// every row commits (`then foo accept` renders a plain permit).
//
// A LoadMerge replay of an unknown packed word is different input: set-path
// lines give the word its own statement, which #10707 keeps open-world, so
// it commits with the #10707 warning rather than silently.
func TestPackedUnknownThenWordRejected12517(t *testing.T) {
	for _, tc := range []struct {
		name, expr, want, openWorld string
	}{
		{name: "unknown word", expr: "foo", want: `then: unknown action "foo"`, openWorld: "foo"},
		{name: "unknown word then accept", expr: "foo accept", want: `then: unknown action "foo"`, openWorld: "foo"},
		{name: "match word in action slot", expr: "protocol static", want: `then: "protocol" is a from-match keyword, not a then action`, openWorld: "protocol"},
		{name: "dropped match word in action slot", expr: "neighbor 192.0.2.1 accept", want: `then: "neighbor" is a from-match keyword, not a then action`, openWorld: "neighbor"},
		{name: "next policy tail", expr: "next policy foo", want: `then next: unknown modifier "foo"`},
		{name: "chained next policy tail", expr: "local-preference 200 next policy foo", want: `then next: unknown modifier "foo"`},
	} {
		for _, spelling := range []struct{ name, text string }{
			{name: "compact", text: "policy-options { policy-statement P { term t { then " + tc.expr + "; } } }"},
			{name: "term-line", text: "policy-options { policy-statement P { term t then " + tc.expr + "; } }"},
		} {
			t.Run(tc.name+"/"+spelling.name, func(t *testing.T) {
				tree := policyTree12517(t, spelling.text)
				t.Run("CompileConfig", func(t *testing.T) {
					if _, err := config.CompileConfig(tree); err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("strict compile error = %v, want %q", err, tc.want)
					}
				})
				t.Run("CompileConfigLenient", func(t *testing.T) {
					cfg, err := config.CompileConfigLenient(tree)
					if err != nil {
						t.Fatalf("tolerant compile rejected a persisted config: %v", err)
					}
					if !hasPolicyThenTailWarning12517(cfg.Warnings, tc.want) {
						t.Fatalf("tolerant compile omitted %q: %v", tc.want, cfg.Warnings)
					}
				})
				t.Run("CheckText", func(t *testing.T) {
					if _, err := configstore.CheckText(spelling.text, 0); err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("CheckText error = %v, want %q", err, tc.want)
					}
				})
				t.Run("LoadOverride", func(t *testing.T) {
					load := policyThenLoads12517(spelling.text)[0]
					if _, err := policyThenCommitCheck12517(t, load, spelling.text); err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("LoadOverride + CommitCheck error = %v, want %q", err, tc.want)
					}
				})
				t.Run("LoadMerge", func(t *testing.T) {
					load := policyThenLoads12517(spelling.text)[1]
					cfg, err := policyThenCommitCheck12517(t, load, spelling.text)
					if tc.openWorld == "" {
						if err == nil || !strings.Contains(err.Error(), tc.want) {
							t.Fatalf("LoadMerge + CommitCheck error = %v, want %q", err, tc.want)
						}
						return
					}
					if err != nil {
						t.Fatalf("LoadMerge replay of an open-world statement rejected: %v", err)
					}
					for _, warning := range cfg.Warnings {
						if strings.Contains(warning, "#10707") && strings.Contains(warning, strconv.Quote(tc.openWorld)) {
							return
						}
					}
					t.Fatalf("LoadMerge replay omitted the #10707 warning for %q: %v", tc.openWorld, cfg.Warnings)
				})
			})
		}
	}
}
