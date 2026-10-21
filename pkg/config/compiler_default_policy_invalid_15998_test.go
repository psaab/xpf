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

// #15998 fold: an invalid token anywhere in ONE stanza — bracket list,
// packed tail, nested child — must also fail closed, not only an invalid
// *selected* action in a separate stanza. The selected action stays
// permit-all in every case below.
func TestInvalidTrailingTokenInOneStanzaFailsClosed15998(t *testing.T) {
	cases := []struct{ name, text, invalid string }{
		{"bracket list permit then typo", "security { policies { default-policy [ permit-all permit-al ]; } }", "permit-al"},
		{"packed block permit then typo", "security { policies { default-policy { permit-all permit-al; } } }", "permit-al"},
		{"flat key with typo block body", "security { policies { default-policy permit-all { permit-al; } } }", "permit-al"},
		{"nested child typo", "security { policies { default-policy { permit-all { permit-al; } } } }", "permit-al"},
		{"bracket deny then typo still invalid", "security { policies { default-policy [ deny-all bogus ]; } }", "bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(defaultPolicyTree11821(t, tc.text))
			if err == nil {
				t.Fatal("strict compile accepted invalid trailing default-policy token")
			}
			if !strings.Contains(err.Error(), tc.invalid) || !strings.Contains(err.Error(), "#15998") {
				t.Fatalf("strict error %q does not name %q / #15998", err, tc.invalid)
			}
			for _, compile := range []struct {
				name string
				fn   func(*ConfigTree) (*Config, error)
			}{
				{"lenient", CompileConfigLenient},
				{"node lenient", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
			} {
				cfg, err := compile.fn(defaultPolicyTree11821(t, tc.text))
				if err != nil {
					t.Fatalf("%s compile: %v", compile.name, err)
				}
				if cfg.Security.DefaultPolicy != PolicyDeny {
					t.Fatalf("%s: invalid trailing token compiled as %v, want deny-all", compile.name, cfg.Security.DefaultPolicy)
				}
				found := false
				for _, w := range cfg.Warnings {
					if strings.Contains(w, "#15998") && strings.Contains(w, tc.invalid) {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s: missing #15998 warning naming %q: %v", compile.name, tc.invalid, cfg.Warnings)
				}
			}
		})
	}
}

// #15998 fold 2: a quoted-empty or missing value is INVALID, never skipped.
// Skipping tok=="" left the selected permit-all standing on tolerant load.
func TestEmptyDefaultPolicyTokenFailsClosed15998(t *testing.T) {
	cases := []struct{ name, text string }{
		{"single-stanza bracket empty", `security { policies { default-policy [ permit-all "" ]; } }`},
		{"duplicate empty stanza", "security { policies { default-policy { permit-all; } default-policy \"\"; } }"},
		{"missing-value stanza", "security { policies { default-policy { permit-all; } default-policy; } }"},
		{"flat missing value beside permit", "security { policies { default-policy permit-all; default-policy; } }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(defaultPolicyTree11821(t, tc.text)); err == nil {
				t.Fatal("strict compile accepted empty/missing default-policy value")
			} else if !strings.Contains(err.Error(), "#15998") {
				t.Fatalf("strict error %q does not name #15998", err)
			}
			for _, compile := range []struct {
				name string
				fn   func(*ConfigTree) (*Config, error)
			}{
				{"lenient", CompileConfigLenient},
				{"node lenient", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
			} {
				cfg, err := compile.fn(defaultPolicyTree11821(t, tc.text))
				if err != nil {
					t.Fatalf("%s compile: %v", compile.name, err)
				}
				if cfg.Security.DefaultPolicy != PolicyDeny {
					t.Fatalf("%s: empty token compiled as %v, want deny-all", compile.name, cfg.Security.DefaultPolicy)
				}
				found := false
				for _, w := range cfg.Warnings {
					if strings.Contains(w, "#15998") {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s: missing #15998 warning: %v", compile.name, cfg.Warnings)
				}
			}
		})
	}
}

// #15998 fold 3: a NESTED child also named `default-policy` is an authored
// invalid token — the census must exempt only the stanza root's identity.
func TestNestedDefaultPolicyChildFailsClosed15998(t *testing.T) {
	cases := []struct{ name, text string }{
		{"nested default-policy child", "security { policies { default-policy { permit-all { default-policy; } } } }"},
		{"nested default-policy with typo value", "security { policies { default-policy { permit-all { default-policy bogus; } } } }"},
		{"deep nested default-policy", "security { policies { default-policy { permit-all { x { default-policy; } } } } }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(defaultPolicyTree11821(t, tc.text)); err == nil {
				t.Fatal("strict compile accepted nested default-policy child")
			} else if !strings.Contains(err.Error(), "#15998") {
				t.Fatalf("strict error %q does not name #15998", err)
			}
			for _, compile := range []struct {
				name string
				fn   func(*ConfigTree) (*Config, error)
			}{
				{"lenient", CompileConfigLenient},
				{"node lenient", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
			} {
				cfg, err := compile.fn(defaultPolicyTree11821(t, tc.text))
				if err != nil {
					t.Fatalf("%s compile: %v", compile.name, err)
				}
				if cfg.Security.DefaultPolicy != PolicyDeny {
					t.Fatalf("%s: nested child compiled as %v, want deny-all", compile.name, cfg.Security.DefaultPolicy)
				}
				found := false
				for _, w := range cfg.Warnings {
					if strings.Contains(w, "#15998") && strings.Contains(w, "default-policy") {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s: missing #15998 warning naming default-policy: %v", compile.name, cfg.Warnings)
				}
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
