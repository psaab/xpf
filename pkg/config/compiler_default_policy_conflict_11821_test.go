package config

import (
	"strings"
	"testing"
)

func defaultPolicyTree11821(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse default-policy config: %v", errs)
	}
	return tree
}

func TestConflictingDefaultPolicyStanzasRejectedAndFailClosed11821(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		first  string
		second string
	}{
		{
			name:   "one policies block permit then deny",
			first:  "permit-all",
			second: "deny-all",
			text: `security { policies {
				default-policy { permit-all; }
				default-policy { deny-all; }
			} }`,
		},
		{
			name:   "one policies block deny then permit",
			first:  "deny-all",
			second: "permit-all",
			text: `security { policies {
				default-policy { deny-all; }
				default-policy { permit-all; }
			} }`,
		},
		{
			name:   "repeated policies blocks in one security root",
			first:  "permit-all",
			second: "deny-all",
			text: `security {
				policies { default-policy { permit-all; } }
				policies { default-policy { deny-all; } }
			}`,
		},
		{
			name:   "repeated security roots permit then deny",
			first:  "permit-all",
			second: "deny-all",
			text: `security { policies { default-policy { permit-all; } } }
			security { policies { default-policy { deny-all; } } }`,
		},
		{
			name:   "repeated security roots deny then permit",
			first:  "deny-all",
			second: "permit-all",
			text: `security { policies { default-policy { deny-all; } } }
			security { policies { default-policy { permit-all; } } }`,
		},
		{
			name:   "repeated security roots reject then permit",
			first:  "reject-all",
			second: "permit-all",
			text: `security { policies { default-policy { reject-all; } } }
			security { policies { default-policy { permit-all; } } }`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(defaultPolicyTree11821(t, tc.text))
			if err == nil {
				t.Fatal("strict compile accepted conflicting default-policy stanzas")
			}
			for _, want := range []string{"security policies default-policy", tc.first, tc.second, "#11821"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("strict error %q does not name %q", err, want)
				}
			}

			cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Security.DefaultPolicy != PolicyDeny {
				t.Fatalf("lenient conflicting default-policy compiled as %v, want deny-all", cfg.Security.DefaultPolicy)
			}
			foundWarning := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "security policies default-policy") &&
					strings.Contains(warning, tc.first) &&
					strings.Contains(warning, tc.second) &&
					strings.Contains(warning, "#11821") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("lenient compile omitted named conflict warning: %v", cfg.Warnings)
			}
		})
	}
}

func TestIdenticalDefaultPolicyStanzasRemainAccepted11821(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "same policies block",
			text: `security { policies {
				default-policy { permit-all; }
				default-policy { permit-all; }
			} }`,
		},
		{
			name: "repeated security roots",
			text: `security { policies { default-policy { permit-all; } } }
			security { policies { default-policy { permit-all; } } }`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("strict compile rejected identical stanzas: %v", err)
			}
			if cfg.Security.DefaultPolicy != PolicyPermit {
				t.Fatalf("identical permit-all stanzas compiled as %v, want permit-all", cfg.Security.DefaultPolicy)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#11821") {
					t.Fatalf("identical actions produced conflict warning: %q", warning)
				}
			}
		})
	}
}
