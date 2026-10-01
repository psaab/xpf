package config

import (
	"strings"
	"testing"
)

func hierarchicalPolicyCountAlarmTree11342(t *testing.T) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(`
security {
    zones { security-zone trust; security-zone untrust; }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; count { alarm { per-minute-threshold 100; } } }
            }
        }
    }
}
`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse hierarchical policy: %v", errs)
	}
	return tree
}

func flatPolicyCountAlarmTree11342(t *testing.T) *ConfigTree {
	t.Helper()
	return buildPolicyThenTree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
		"set security policies from-zone trust to-zone untrust policy p1 then count alarm per-minute-threshold 100",
	)
}

func TestPolicyThenCountAlarmRejectsStrictAndWarnsLenient11342(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree func(*testing.T) *ConfigTree
	}{
		{name: "flat-set", tree: flatPolicyCountAlarmTree11342},
		{name: "hierarchical", tree: hierarchicalPolicyCountAlarmTree11342},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree(t)

			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("CompileConfig accepted inert then-count alarm; want strict rejection (#11342)")
			} else {
				for _, want := range []string{"then count alarm", "#11342"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("CompileConfig error = %q, want %q", err, want)
					}
				}
			}

			if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), "alarm") {
				t.Fatalf("SchemaValidate error = %v, want strict closed-world alarm rejection", err)
			}

			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected persisted inert alarm: %v", err)
			}
			warnings := strings.Join(cfg.Warnings, "\n")
			for _, want := range []string{"then count alarm", "#11342"} {
				if !strings.Contains(warnings, want) {
					t.Fatalf("CompileConfigLenient warnings = %q, want %q", warnings, want)
				}
			}
			if len(cfg.Security.Policies) == 0 || len(cfg.Security.Policies[0].Policies) == 0 || !cfg.Security.Policies[0].Policies[0].Count {
				t.Fatalf("tolerant compile did not preserve count action: %+v", cfg.Security.Policies)
			}
		})
	}
}

func TestPolicyThenCountWithoutAlarmRemainsSupported11342(t *testing.T) {
	tree := buildPolicyThenTree(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
		"set security policies from-zone trust to-zone untrust policy p1 then count",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected supported then-count action: %v", err)
	}
	if len(cfg.Security.Policies) == 0 || len(cfg.Security.Policies[0].Policies) == 0 || !cfg.Security.Policies[0].Policies[0].Count {
		t.Fatalf("CompileConfig did not preserve supported count action: %+v", cfg.Security.Policies)
	}
}
