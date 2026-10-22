package config

import "testing"

// compileDefaultPolicyFromSet compiles a config from flat set commands using
// the same ParseSetCommand + SetPath loop the CLI uses (NewParser merges
// newline-separated set lines into one node and must not be used for set
// syntax — see CLAUDE.md "Testing flat set syntax").
func compileDefaultPolicyFromSet(t *testing.T, cmds []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// TestDefaultPolicyFailsClosed is the #3065 fail-on-revert guard: a config
// with a zone-pair policy but NO `security policies default-policy` stanza
// must compile to a DENY no-match default (Junos default-security-policy
// parity), NOT the PolicyPermit zero value. If someone reverts the
// DefaultPolicy=PolicyDeny initializer in compiler.go, the zero value
// (PolicyPermit, iota==0) silently reintroduces the fail-OPEN and this test
// goes RED.
func TestDefaultPolicyFailsClosed(t *testing.T) {
	cfg := compileDefaultPolicyFromSet(t, []string{
		"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces eth1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone untrust interfaces eth1",
		"set security policies from-zone trust to-zone untrust policy allow-web match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow-web match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow-web match application any",
		"set security policies from-zone trust to-zone untrust policy allow-web then permit",
	})
	if cfg.Security.DefaultPolicy != PolicyDeny {
		t.Fatalf("implicit no-match default = %d, want PolicyDeny (%d) — fail-OPEN regression (#3065)",
			cfg.Security.DefaultPolicy, PolicyDeny)
	}
}

// TestDefaultPolicyExplicitOverrides confirms each explicit default-policy
// value maps to the right PolicyAction, including reject-all (which used to
// fall through the compilePolicies switch and be silently ignored).
func TestDefaultPolicyExplicitOverrides(t *testing.T) {
	cases := []struct {
		value string
		want  PolicyAction
	}{
		{"permit-all", PolicyPermit},
		{"deny-all", PolicyDeny},
		{"reject-all", PolicyReject},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			cfg := compileDefaultPolicyFromSet(t, []string{
				"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
				"set interfaces eth1 unit 0 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces eth0",
				"set security zones security-zone untrust interfaces eth1",
				"set security policies default-policy " + tc.value,
			})
			if cfg.Security.DefaultPolicy != tc.want {
				t.Fatalf("default-policy %s = %d, want %d", tc.value, cfg.Security.DefaultPolicy, tc.want)
			}
		})
	}
}

// TestDefaultPolicySchemaValidation confirms the new default-policy leaf is
// known to the config-mode schema (commit-check) — a valid value passes and
// a bogus value is rejected. Before #3065 the leaf was absent and the
// schema walker silently accepted any (mis)spelling.
func TestDefaultPolicySchemaValidation(t *testing.T) {
	build := func(value string) *ConfigTree {
		tree := &ConfigTree{}
		for _, cmd := range []string{
			"set security zones security-zone trust interfaces eth0",
			"set security policies default-policy " + value,
		} {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return tree
	}
	for _, ok := range []string{"permit-all", "deny-all", "reject-all"} {
		if err := SchemaValidate(build(ok)); err != nil {
			t.Errorf("SchemaValidate rejected valid default-policy %q: %v", ok, err)
		}
	}
	if err := SchemaValidate(build("allow-everything")); err == nil {
		t.Errorf("SchemaValidate accepted bogus default-policy value")
	}
}
