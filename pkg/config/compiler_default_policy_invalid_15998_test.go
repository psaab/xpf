package config

import (
	"strings"
	"testing"
)

// #15998: an invalid second default-policy value retained an earlier
// permit-all on tolerant load — the switch had no default arm and the
// conflict censuses count only valid spellings.

func TestInvalidSecondDefaultPolicyFailsClosed15998(t *testing.T) {
	cases := []struct{ name, text string }{
		{"duplicate roots permit then typo", "security { policies { default-policy { permit-all; } } }\nsecurity { policies { default-policy { permit-al; } } }"},
		{"same block permit then typo", "security { policies { default-policy { permit-all; } default-policy { bogus; } } }"},
		{"typo then permit still denied tolerant", "security { policies { default-policy { bogus; } default-policy { permit-all; } } }"},
		{"flat permit then flat typo", "security { policies { default-policy permit-all; default-policy permit-al; } }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if cfg.Security.DefaultPolicy != PolicyDeny {
				t.Fatalf("lenient invalid default-policy compiled as %v, want deny-all", cfg.Security.DefaultPolicy)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#15998") {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing #15998 warning: %v", cfg.Warnings)
			}
			if _, err := CompileConfig(defaultPolicyTree11821(t, tc.text)); err == nil {
				t.Fatal("strict compile accepted invalid default-policy value")
			}
		})
	}
}

func TestSingleInvalidDefaultPolicyAloneIsDeny15998(t *testing.T) {
	cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, "security { policies { default-policy { bogus; } } }"))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if cfg.Security.DefaultPolicy != PolicyDeny {
		t.Fatalf("single invalid = %v, want deny", cfg.Security.DefaultPolicy)
	}
}

func TestValidDefaultPoliciesUnaffected15998(t *testing.T) {
	for _, tc := range []struct {
		text string
		want PolicyAction
	}{
		{"security { policies { default-policy { permit-all; } } }", PolicyPermit},
		{"security { policies { default-policy { deny-all; } } }", PolicyDeny},
		{"security { policies { default-policy { reject-all; } } }", PolicyReject},
		{"security { policies { default-policy { permit-all; } default-policy { permit-all; } } }", PolicyPermit},
	} {
		cfg, err := CompileConfigLenient(defaultPolicyTree11821(t, tc.text))
		if err != nil {
			t.Fatalf("lenient %q: %v", tc.text, err)
		}
		if cfg.Security.DefaultPolicy != tc.want {
			t.Fatalf("%q = %v want %v", tc.text, cfg.Security.DefaultPolicy, tc.want)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#15998") {
				t.Fatalf("valid config got #15998 warning: %q", w)
			}
		}
	}
}
