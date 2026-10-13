package config_test

import (
	"path/filepath"
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
		{name: "community-add", action: "community add 65001:100", tail: "foo"},
		{name: "community-set", action: "community set 65001:100", tail: "foo"},
		{name: "community-value", action: "community 65001:100", tail: "foo"},
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

func policyTree12517(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	if strings.HasPrefix(text, "set ") {
		path, err := config.ParseSetCommand(text)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", text, err)
		}
		tree := &config.ConfigTree{}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", text, err)
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
