package config

import (
	"strings"
	"testing"
)

// #12821: contradictory action tokens WITHIN one default-policy node
// (bracket list, flat key plus block body, nested block child) were read
// as only the first token, silently compiling to permit-all.
func TestContradictoryDefaultPolicyWithinNode12821(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		first  string
		second string
	}{
		{
			name:   "bracket permit then deny",
			first:  "permit-all",
			second: "deny-all",
			text: `security { policies {
				default-policy [ permit-all deny-all ];
			} }`,
		},
		{
			name:   "bracket deny then permit",
			first:  "deny-all",
			second: "permit-all",
			text: `security { policies {
				default-policy [ deny-all permit-all ];
			} }`,
		},
		{
			name:   "bracket permit then reject",
			first:  "permit-all",
			second: "reject-all",
			text: `security { policies {
				default-policy [ permit-all reject-all ];
			} }`,
		},
		{
			name:   "flat key with contradictory block body",
			first:  "permit-all",
			second: "deny-all",
			text: `security { policies {
				default-policy permit-all { deny-all; }
			} }`,
		},
		{
			name:   "flat deny key with permit block body",
			first:  "deny-all",
			second: "permit-all",
			text: `security { policies {
				default-policy deny-all { permit-all; }
			} }`,
		},
		{
			name:   "block child carrying nested contradictory child",
			first:  "permit-all",
			second: "deny-all",
			text: `security { policies {
				default-policy { permit-all { deny-all; } }
			} }`,
		},
		{
			name:   "block child with packed contradictory tail",
			first:  "permit-all",
			second: "deny-all",
			text: `security { policies {
				default-policy { permit-all deny-all; }
			} }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := SchemaValidate(defaultPolicyTree11821(t, tc.text), nil); err == nil {
				t.Errorf("SchemaValidate accepted contradictory default-policy within one node")
			}
			_, err := CompileConfig(defaultPolicyTree11821(t, tc.text))
			if err == nil {
				t.Fatalf("strict compile accepted contradictory default-policy within one node")
			}
			for _, want := range []string{"security policies default-policy", tc.first, tc.second, "#12821"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("strict error %q does not name %q", err, want)
				}
			}
			cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Security.DefaultPolicy != PolicyDeny {
				t.Fatalf("lenient contradictory default-policy compiled as %v, want deny-all", cfg.Security.DefaultPolicy)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "security policies default-policy") &&
					strings.Contains(w, tc.first) && strings.Contains(w, tc.second) &&
					strings.Contains(w, "#12821") {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient compile omitted #12821 warning: %v", cfg.Warnings)
			}
		})
	}
}

func TestSingleDefaultPolicyWithinNodeControls12821(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		want   PolicyAction
		schema bool
	}{
		{"flat permit", `security { policies { default-policy permit-all; } }`, PolicyPermit, true},
		{"flat deny", `security { policies { default-policy deny-all; } }`, PolicyDeny, true},
		{"flat reject", `security { policies { default-policy reject-all; } }`, PolicyReject, true},
		{"block permit", `security { policies { default-policy { permit-all; } } }`, PolicyPermit, true},
		{"block deny", `security { policies { default-policy { deny-all; } } }`, PolicyDeny, true},
		{"no default-policy", `security { policies { } }`, PolicyDeny, true},
		{"bracket permit", `security { policies { default-policy [ permit-all ]; } }`, PolicyPermit, true},
		{"bracket deny", `security { policies { default-policy [ deny-all ]; } }`, PolicyDeny, true},
		{"same action packed twice", `security { policies { default-policy permit-all permit-all; } }`, PolicyPermit, false},
		{"same action in nested children", `security { policies { default-policy { permit-all { permit-all; } } } }`, PolicyPermit, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.schema {
				if err := SchemaValidate(defaultPolicyTree11821(t, tc.text), nil); err != nil {
					t.Fatalf("SchemaValidate rejected control: %v", err)
				}
			}
			cfg, err := CompileConfig(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("strict compile rejected control: %v", err)
			}
			if cfg.Security.DefaultPolicy != tc.want {
				t.Fatalf("control compiled as %v, want %v", cfg.Security.DefaultPolicy, tc.want)
			}
		})
	}
}
