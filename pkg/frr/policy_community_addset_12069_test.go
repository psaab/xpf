package frr

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12069 RED-before: `then community add CUST` with
// `community CUST members 65000:100` must render
// `set community 65000:100 additive` — never `set community CUST`,
// which bgpd rejects at exec (Malformed communities attribute).
func TestPolicyCommunityAddRendersResolvedLiteral12069(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set policy-options community CUST members 65000:100",
		"set policy-options policy-statement P term t_add from protocol bgp",
		"set policy-options policy-statement P term t_add then community add CUST",
		"set policy-options policy-statement P term t_end then accept",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := New().generatePolicyOptions(&cfg.PolicyOptions)
	if !strings.Contains(got, " set community 65000:100 additive\n") {
		t.Errorf("missing resolved `set community 65000:100 additive` in:\n%s", got)
	}
	if strings.Contains(got, " set community CUST") {
		t.Errorf("rendered the community NAME verbatim (bgpd rejects this line at exec):\n%s", got)
	}
}

func TestPolicyCommunityAddRendersResolvedMembers12069(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t1", CommunityOp: "add", CommunityAdd: "65000:100 no-export", Action: "accept"},
			}},
		},
	}
	got := New().generatePolicyOptions(po)
	if !strings.Contains(got, " set community 65000:100 no-export additive\n") {
		t.Fatalf("did not render every literal member in order:\n%s", got)
	}
}

// #12069 render belt: leniently-loaded add/set/bare operands that are neither
// literals nor defined names must be omitted (fail-closed), while sibling
// clauses still render and the omission is warned.
func TestPolicyCommunityAddUnresolvableOmitted12069(t *testing.T) {
	for _, tc := range []struct {
		name, op, warning string
	}{
		{"add", "add", "omitting an unresolvable then community add value"},
		{"set", "set", "omitting an unresolvable then community replacement value"},
		{"bare", "", "omitting an unresolvable then community replacement value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			term := &config.PolicyTerm{
				Name: "t1", CommunityOp: tc.op,
				LocalPreference: 200, HasLocalPreference: true, Action: "accept",
			}
			if tc.op == "add" {
				term.CommunityAdd = "NOPE"
			} else {
				term.Community = "NOPE"
			}
			po := &config.PolicyOptionsConfig{
				PolicyStatements: map[string]*config.PolicyStatement{
					"P": {Name: "P", Terms: []*config.PolicyTerm{term}},
				},
			}
			var logs strings.Builder
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(previous)
			got := New().generatePolicyOptions(po)
			if strings.Contains(got, "set community NOPE") {
				t.Fatalf("rendered unresolvable operand verbatim:\n%s", got)
			}
			if !strings.Contains(got, " set local-preference 200\n") {
				t.Errorf("sibling set clause lost when the community clause was omitted:\n%s", got)
			}
			if !strings.Contains(logs.String(), tc.warning) {
				t.Errorf("missing render warning for unresolvable operand: %s", logs.String())
			}
		})
	}
}

// #12069 Astra-R2 fail-open regression: compile the literal-shaped-name /
// invalid-definition matrix through tolerant rendering. The strict compile
// must reject the authored operand, and the renderer must omit it with a
// warning rather than treating its spelling as the failed definition.
func TestPolicyCommunityLiteralShapedFailedResolutionOmitted12069(t *testing.T) {
	for _, name := range []string{"65000:1", "no-export"} {
		for _, definition := range []string{"empty", "regex", "mixed"} {
			for _, op := range []string{"add", "set", "bare"} {
				t.Run(name+"/"+definition+"/"+op, func(t *testing.T) {
					community := `set policy-options community "` + name + `"`
					definitionCommands := []string{}
					switch definition {
					case "empty":
						definitionCommands = []string{community}
					case "regex":
						definitionCommands = []string{community + ` members "65000:*"`}
					case "mixed":
						definitionCommands = []string{
							community + " members no-export",
							community + ` members "65000:*"`,
						}
					}
					clause := "then community " + name
					switch op {
					case "add":
						clause = "then community add " + name
					case "set":
						clause = "then community set " + name
					}
					commands := append(definitionCommands,
						"set policy-options policy-statement P term t1 from protocol bgp",
						"set policy-options policy-statement P term t1 "+clause,
						"set policy-options policy-statement P term t1 then accept",
					)
					buildTree := func() *config.ConfigTree {
						t.Helper()
						tree := &config.ConfigTree{}
						for _, command := range commands {
							path, err := config.ParseSetCommand(command)
							if err != nil {
								t.Fatalf("ParseSetCommand(%q): %v", command, err)
							}
							if err := tree.SetPath(path); err != nil {
								t.Fatalf("SetPath(%q): %v", command, err)
							}
						}
						return tree
					}
					if _, err := config.CompileConfig(buildTree()); err == nil {
						t.Fatalf("strict compile accepted %q with %s definition via %q",
							name, definition, clause)
					} else if !strings.Contains(err.Error(), `uses "`+name+`"`) {
						t.Fatalf("strict error %q does not name authored operand %q", err, name)
					}

					cfg, err := config.CompileConfigLenient(buildTree())
					if err != nil {
						t.Fatalf("tolerant compile failed for %q with %s definition: %v", name, definition, err)
					}
					var logs strings.Builder
					previous := slog.Default()
					slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
					t.Cleanup(func() { slog.SetDefault(previous) })
					got := New().generatePolicyOptions(&cfg.PolicyOptions)
					if strings.Contains(got, " set community ") {
						t.Fatalf("tolerant renderer emitted failed operand %q:\n%s", name, got)
					}
					if !strings.Contains(logs.String(), "omitting an unresolvable then community") ||
						!strings.Contains(logs.String(), name) {
						t.Fatalf("tolerant renderer did not warn with authored operand %q: %s", name, logs.String())
					}
					if strings.Contains(logs.String(), "xpf-invalid-community-resolution") {
						t.Fatalf("tolerant warning exposed internal poison marker: %s", logs.String())
					}
				})
			}
		}
	}
}

func TestPolicyCommunityDirectLiteralStillRenders12069(t *testing.T) {
	for _, value := range []string{"65000:1", "no-export"} {
		for _, op := range []string{"add", "set", "bare"} {
			t.Run(value+"/"+op, func(t *testing.T) {
				clause := "then community " + value
				if op == "add" {
					clause = "then community add " + value
				} else if op == "set" {
					clause = "then community set " + value
				}
				tree := &config.ConfigTree{}
				for _, command := range []string{
					"set policy-options policy-statement P term t1 from protocol bgp",
					"set policy-options policy-statement P term t1 " + clause,
					"set policy-options policy-statement P term t1 then accept",
				} {
					path, err := config.ParseSetCommand(command)
					if err != nil {
						t.Fatalf("ParseSetCommand(%q): %v", command, err)
					}
					if err := tree.SetPath(path); err != nil {
						t.Fatalf("SetPath(%q): %v", command, err)
					}
				}
				cfg, err := config.CompileConfig(tree)
				if err != nil {
					t.Fatalf("strict compile rejected direct literal %q: %v", value, err)
				}
				got := New().generatePolicyOptions(&cfg.PolicyOptions)
				want := " set community " + value
				if op == "add" {
					want += " additive"
				}
				if !strings.Contains(got, want+"\n") {
					t.Fatalf("direct literal %q was not rendered through %s:\n%s", value, op, got)
				}
			})
		}
	}
}
