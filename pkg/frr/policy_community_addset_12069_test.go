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

func TestPolicyCommunityAddRendersAllDefinedMembers12069(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			"CUST": {Name: "CUST", Members: []string{"65000:100", "no-export"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t1", CommunityOp: "add", CommunityAdd: "CUST", Action: "accept"},
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
