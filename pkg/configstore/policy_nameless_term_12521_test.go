package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestCommitCheckRejectsNamelessPolicyTerm12521(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		first string
	}{
		{name: "then-accept", body: "then accept;", first: "then"},
		{name: "then-reject", body: "then reject;", first: "then"},
		{name: "brace-then-reject", body: "then { reject; }", first: "then"},
		{name: "from-and-then", body: "from { protocol bgp; } then { accept; }", first: "from"},
		{name: "packed-local-preference", body: "then local-preference 200 accept;", first: "then"},
		{name: "multi-key-block", body: "then accept { }", first: "then"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer s.ExitConfigure()
			input := `policy-options {
    policy-statement P {
        term { ` + tc.body + ` }
    }
}`
			if err := s.LoadOverride(input); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := s.CommitCheck(); err == nil {
				t.Fatal("CommitCheck accepted a nameless routing-policy term")
			} else {
				for _, want := range []string{
					"policy-statement \"P\"", "nameless",
					"starting with " + `"` + tc.first + `"`, "#12521",
				} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("CommitCheck error = %q, want diagnostic containing %q", err, want)
					}
				}
			}
		})
	}
}

func TestLoadMergeRejectsNamelessPolicyTermsBeforeFlatten12521(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		first string
	}{
		{name: "brace-then-reject", body: "then { reject; }", first: "then"},
		{name: "from-and-then", body: "from { protocol bgp; } then { accept; }", first: "from"},
		{name: "packed-local-preference", body: "then local-preference 200 accept;", first: "then"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer s.ExitConfigure()
			input := `policy-options {
    policy-statement P {
        term { ` + tc.body + ` }
    }
}`
			before := s.ShowCandidateSet()
			err := s.LoadMerge(input)
			if err == nil {
				t.Fatal("LoadMerge accepted a nameless policy term before flattening")
			}
			for _, want := range []string{"#12521", "policy-statement \"P\"", "starting with " + `"` + tc.first + `"`} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("LoadMerge error = %q, want diagnostic containing %q", err, want)
				}
			}
			if got := s.ShowCandidateSet(); got != before {
				t.Fatalf("failed LoadMerge changed the candidate:\nbefore:\n%s\nafter:\n%s", before, got)
			}
		})
	}
}

func TestLoadMergeAcceptsNamedPolicyTerms12521(t *testing.T) {
	cases := []struct {
		name      string
		candidate string
		input     string
	}{
		{name: "N1-named-then-block", input: `policy-options { policy-statement P { term then { then reject; } } }`},
		{name: "N2-named-from-block", input: `policy-options { policy-statement P { term from { from protocol bgp; then accept; } } }`},
		{name: "N3-quoted-then", input: `policy-options { policy-statement P { term "then" { then reject; } } }`},
		{name: "N4-named-empty-leaf", input: `policy-options { policy-statement P { term T; } }`},
		{name: "N5-named-empty-block", input: `policy-options { policy-statement P { term T { } } }`},
		{name: "N6-packed-named-then", input: `policy-options { policy-statement P { term then then reject; } }`},
		{name: "N7-packed-named-term", input: `policy-options policy-statement P term T;`},
		{name: "N8-candidate-applied-group", candidate: `apply-groups G;`, input: `groups { G { policy-options { policy-statement P { term T; } } } }`},
		{name: "N9-named-then-empty-term", input: `policy-options { policy-statement P { term A { then accept; } term B; } }`},
		{name: "N10-named-term", input: `policy-options { policy-statement P { term T { then reject; } } }`},
		{name: "N11-named-to-term", input: `policy-options { policy-statement P { term to { then accept; } } }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer s.ExitConfigure()
			if tc.candidate != "" {
				if err := s.LoadOverride(tc.candidate); err != nil {
					t.Fatalf("LoadOverride candidate: %v", err)
				}
			}
			if err := s.LoadMerge(tc.input); err != nil {
				t.Fatalf("LoadMerge rejected named term: %v", err)
			}
			if _, err := s.CommitCheck(); err != nil {
				t.Fatalf("CommitCheck rejected named term: %v", err)
			}
		})
	}
}

func TestLoadMergeAcceptsNamedPolicyTermsShowRoundTrip12521(t *testing.T) {
	const setText = `set policy-options policy-statement P term A then accept
set policy-options policy-statement P term B`
	source := newTestStore(t)
	if err := source.EnterConfigure(); err != nil {
		t.Fatalf("source EnterConfigure: %v", err)
	}
	defer source.ExitConfigure()
	if err := source.LoadMerge(setText); err != nil {
		t.Fatalf("seed set candidate: %v", err)
	}
	shown := source.ShowCandidate()
	if !strings.Contains(shown, "term B;") {
		t.Fatalf("hierarchical show omitted named leaf term B:\n%s", shown)
	}

	destination := newTestStore(t)
	if err := destination.EnterConfigure(); err != nil {
		t.Fatalf("destination EnterConfigure: %v", err)
	}
	defer destination.ExitConfigure()
	if err := destination.LoadMerge(shown); err != nil {
		t.Fatalf("LoadMerge rejected ShowCandidate output: %v\n%s", err, shown)
	}
	if _, err := destination.CommitCheck(); err != nil {
		t.Fatalf("CommitCheck rejected ShowCandidate output: %v", err)
	}
}

func TestLoadMergeRejectsPackedNamelessPolicyTermPaths12521(t *testing.T) {
	bodies := []struct {
		name  string
		body  string
		first string
	}{
		{name: "then-accept", body: "then accept;", first: "then"},
		{name: "then-reject", body: "then reject;", first: "then"},
		{name: "brace-then-reject", body: "then { reject; }", first: "then"},
		{name: "brace-then-accept", body: "then { accept; }", first: "then"},
		{name: "from-and-then", body: "from { protocol bgp; } then { accept; }", first: "from"},
		{name: "packed-multi-key", body: "then local-preference 200 accept;", first: "then"},
		{name: "multi-key-block-mutation-killer", body: "then accept { }", first: "then"},
		{name: "multi-key-compact-block-mutation-killer", body: "T from protocol bgp { }", first: "T"},
		{name: "multi-key-from", body: "from protocol bgp;", first: "from"},
		{name: "empty-term", body: "", first: ""},
		{name: "leaf-body-token", body: "foo;", first: "foo"},
	}
	paths := []struct {
		name      string
		input     func(string) string
		candidate string
	}{
		{
			name: "S1-packed-policy-statement-name",
			input: func(body string) string {
				return `policy-options policy-statement P { term { ` + body + ` } }`
			},
		},
		{
			name: "S2-packed-term-head",
			input: func(body string) string {
				return `policy-options { policy-statement P term { ` + body + ` } }`
			},
		},
		{
			name: "S3-packed-group-head-candidate-applied",
			input: func(body string) string {
				return `groups G { policy-options { policy-statement P { term { ` + body + ` } } } }`
			},
			candidate: `apply-groups G;`,
		},
		{
			name: "X1-packed-policy-options-term",
			input: func(body string) string {
				return `policy-options policy-statement P term { ` + body + ` }`
			},
		},
		{
			name: "X2-packed-group-policy-options-term",
			input: func(body string) string {
				return `groups G policy-options policy-statement P term { ` + body + ` }`
			},
			candidate: `apply-groups G;`,
		},
		{
			name: "X3-packed-group-policy-statement",
			input: func(body string) string {
				return `groups { G policy-options { policy-statement P { term { ` + body + ` } } } }`
			},
			candidate: `apply-groups G;`,
		},
		{
			name: "X4-packed-group-policy-options-body",
			input: func(body string) string {
				return `groups G { policy-options policy-statement P { term { ` + body + ` } } }`
			},
			candidate: `apply-groups G;`,
		},
		{
			name: "X5-packed-term-with-inline-apply-groups",
			input: func(body string) string {
				return `groups G { policy-options { policy-statement P term { ` + body + ` } } } apply-groups G;`
			},
		},
		{
			name: "X6-packed-policy-statement-name",
			input: func(body string) string {
				return `policy-options { policy-statement { P term { ` + body + ` } } }`
			},
		},
		{
			name: "X7-packed-group-node-policy-options",
			input: func(body string) string {
				return `groups node0 { policy-options policy-statement P { term { ` + body + ` } } }`
			},
			candidate: `apply-groups node0;`,
		},
		{
			name: "X8-packed-inactive-policy-options",
			input: func(body string) string {
				return `inactive: policy-options policy-statement P { term { ` + body + ` } }`
			},
		},
	}
	for _, path := range paths {
		for _, body := range bodies {
			t.Run(path.name+"/"+body.name, func(t *testing.T) {
				s := newTestStore(t)
				if err := s.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				defer s.ExitConfigure()
				if path.candidate != "" {
					if err := s.LoadOverride(path.candidate); err != nil {
						t.Fatalf("LoadOverride candidate: %v", err)
					}
				}
				before := s.ShowCandidateSet()
				err := s.LoadMerge(path.input(body.body))
				if err == nil {
					t.Fatal("LoadMerge accepted a packed nameless policy term")
				}
				for _, want := range []string{
					"#12521",
					"policy-statement \"P\"",
					"starting with " + `"` + body.first + `"`,
				} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("LoadMerge error = %q, want diagnostic containing %q", err, want)
					}
				}
				if got := s.ShowCandidateSet(); got != before {
					t.Fatalf("failed LoadMerge changed the candidate:\nbefore:\n%s\nafter:\n%s", before, got)
				}
			})
		}
	}
}

func TestLoadMergeRejectsCanonicalNamelessPolicyTermPaths12521(t *testing.T) {
	bodies := []struct {
		name  string
		body  string
		first string
	}{
		{name: "then-accept", body: "then accept;", first: "then"},
		{name: "then-reject", body: "then reject;", first: "then"},
		{name: "brace-then-reject", body: "then { reject; }", first: "then"},
		{name: "brace-then-accept", body: "then { accept; }", first: "then"},
		{name: "from-and-then", body: "from { protocol bgp; } then { accept; }", first: "from"},
		{name: "packed-multi-key", body: "then local-preference 200 accept;", first: "then"},
		{name: "multi-key-block-mutation-killer", body: "then accept { }", first: "then"},
		{name: "multi-key-compact-block-mutation-killer", body: "T from protocol bgp { }", first: "T"},
		{name: "multi-key-from", body: "from protocol bgp;", first: "from"},
		{name: "empty-term", body: "", first: ""},
		{name: "leaf-body-token", body: "foo;", first: "foo"},
	}
	policy := func(body string) string {
		return `policy-options { policy-statement P { term { ` + body + ` } } }`
	}
	paths := []struct {
		name      string
		candidate string
		input     func(string) string
	}{
		{name: "policy-options-root", input: policy},
		{
			name: "policy-statement-container",
			input: func(body string) string {
				return `policy-options { policy-statement { P { term { ` + body + ` } } } }`
			},
		},
		{
			name: "repeated-policy-options-roots",
			input: func(body string) string {
				return `policy-options { policy-statement Q { term T { then accept; } } } ` + policy(body)
			},
		},
		{
			name: "inactive-policy-options-root",
			input: func(body string) string {
				return `inactive: ` + policy(body)
			},
		},
		{
			name: "inactive-term",
			input: func(body string) string {
				return `policy-options { policy-statement P { inactive: term { ` + body + ` } } }`
			},
		},
		{
			name: "group-body",
			input: func(body string) string {
				return `groups { G { ` + policy(body) + ` } }`
			},
		},
		{
			name: "inactive-group-body",
			input: func(body string) string {
				return `inactive: groups { G { ` + policy(body) + ` } }`
			},
		},
		{
			name: "inactive-policy-options-in-group",
			input: func(body string) string {
				return `groups { G { inactive: ` + policy(body) + ` } }`
			},
		},
		{
			name: "group-policy-statement-container",
			input: func(body string) string {
				return `groups { G { policy-options { policy-statement { P { term { ` + body + ` } } } } } }`
			},
		},
		{
			name:      "candidate-applied-group",
			candidate: `apply-groups G;`,
			input: func(body string) string {
				return `groups { G { ` + policy(body) + ` } }`
			},
		},
	}
	for _, path := range paths {
		for _, body := range bodies {
			t.Run(path.name+"/"+body.name, func(t *testing.T) {
				s := newTestStore(t)
				if err := s.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				defer s.ExitConfigure()
				if path.candidate != "" {
					if err := s.LoadOverride(path.candidate); err != nil {
						t.Fatalf("LoadOverride candidate: %v", err)
					}
				}
				before := s.ShowCandidateSet()
				err := s.LoadMerge(path.input(body.body))
				if err == nil {
					t.Fatal("LoadMerge accepted a canonical nameless policy term")
				}
				for _, want := range []string{
					"#12521",
					"policy-statement \"P\"",
					"starting with " + `"` + body.first + `"`,
				} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("LoadMerge error = %q, want diagnostic containing %q", err, want)
					}
				}
				if got := s.ShowCandidateSet(); got != before {
					t.Fatalf("failed LoadMerge changed the candidate:\nbefore:\n%s\nafter:\n%s", before, got)
				}
			})
		}
	}
}

func TestLoadMergeRejectsNamelessTermFromAppliedGroup12521(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer s.ExitConfigure()
	input := `groups {
    G {
        policy-options {
            policy-statement P {
                term { then { reject; } }
            }
        }
    }
}
apply-groups G;`
	err := s.LoadMerge(input)
	if err == nil || !strings.Contains(err.Error(), "#12521") {
		t.Fatalf("LoadMerge applied-group error = %v, want #12521 rejection", err)
	}
}

func TestStoreLoadNeutralizesPersistedNamelessPolicyTerm12521(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	input := `policy-options {
    policy-statement EXPORT-STATIC {
        term { from { protocol static; } then accept; }
    }
}`
	tree, errs := config.NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse persisted input: %v", errs)
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("WriteActiveMarker: %v", err)
	}
	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load: %v", err)
	}
	cfg := booted.ActiveConfig()
	if cfg == nil {
		t.Fatal("Store.Load left ActiveConfig nil")
	}
	ps := cfg.PolicyOptions.PolicyStatements["EXPORT-STATIC"]
	if ps == nil || len(ps.Terms) != 1 {
		t.Fatalf("loaded terms = %#v, want one neutral placeholder", ps)
	}
	term := ps.Terms[0]
	if term.Action != "" || len(term.FromProtocols) != 0 {
		t.Fatalf("loaded term = %#v, want actionless/unmatched placeholder", term)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "#12521") {
		t.Fatalf("Store.Load warnings = %q, want #12521", cfg.Warnings)
	}
}

func TestLoadMergeKeepsGroupReferencesDeferred12521(t *testing.T) {
	cluster, err := os.ReadFile(filepath.Join("..", "..", "docs", "ha-cluster.conf"))
	if err != nil {
		t.Fatalf("read shipped HA config: %v", err)
	}
	userspaceCluster, err := os.ReadFile(filepath.Join("..", "..", "docs", "ha-cluster-userspace.conf"))
	if err != nil {
		t.Fatalf("read shipped userspace HA config: %v", err)
	}
	cases := []struct {
		name      string
		candidate string
		input     string
	}{
		{
			name:      "group-defined-in-candidate",
			candidate: `groups { G { system { host-name candidate; } } }`,
			input:     `apply-groups G;`,
		},
		{
			name:  "shipped-ha-node-variable",
			input: string(cluster),
		},
		{
			name:  "shipped-userspace-ha-node-variable",
			input: string(userspaceCluster),
		},
		{
			name:  "inactive-group-reference",
			input: `inactive: apply-groups G;`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer s.ExitConfigure()
			if tc.candidate != "" {
				if err := s.LoadOverride(tc.candidate); err != nil {
					t.Fatalf("LoadOverride candidate: %v", err)
				}
			}
			if err := s.LoadMerge(tc.input); err != nil {
				t.Fatalf("LoadMerge rejected valid deferred group reference: %v", err)
			}
		})
	}
}

func TestLoadMergeRejectsNamelessPolicyInCandidateAppliedGroup12521(t *testing.T) {
	for _, group := range []string{"G", "node0"} {
		t.Run(group, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer s.ExitConfigure()
			if err := s.LoadOverride(`apply-groups ` + group + `;`); err != nil {
				t.Fatalf("LoadOverride candidate: %v", err)
			}
			input := `groups { ` + group + ` {
    policy-options {
        policy-statement P { term { then { reject; } } }
    }
} }`
			before := s.ShowCandidateSet()
			err := s.LoadMerge(input)
			if err == nil || !strings.Contains(err.Error(), "#12521") {
				t.Fatalf("LoadMerge candidate-applied-group error = %v, want #12521", err)
			}
			if got := s.ShowCandidateSet(); got != before {
				t.Fatalf("rejected LoadMerge changed candidate:\nbefore:\n%s\nafter:\n%s", before, got)
			}
		})
	}
}

func TestLoadMergeScansInactiveNamelessPolicyInGroup12521(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer s.ExitConfigure()
	input := `inactive: groups {
    G {
        policy-options {
            policy-statement P { term { then reject; } }
        }
    }
}`
	err := s.LoadMerge(input)
	if err == nil || !strings.Contains(err.Error(), "#12521") {
		t.Fatalf("LoadMerge inactive-group error = %v, want fail-safe #12521 rejection", err)
	}
}
