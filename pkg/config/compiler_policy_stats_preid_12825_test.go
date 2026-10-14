package config

import (
	"strings"
	"testing"
)

func tree12825(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

// Duplicate pre-id-default-policy blocks must merge log bits (#12825).
func TestDuplicatePreIDDefaultPolicyMerges12825(t *testing.T) {
	cases := []struct{ name, text string }{
		{"two blocks same security root", `security {
			pre-id-default-policy { then { log { session-init; } } }
			pre-id-default-policy { then { log { session-close; } } }
		}`},
		{"two security roots", `security { pre-id-default-policy { then { log { session-init; } } } }
		security { pre-id-default-policy { then { log { session-close; } } } }`},
		{"second block without log does not clear first", `security {
			pre-id-default-policy { then { log { session-init; } } }
			pre-id-default-policy { then { } }
		}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tree12825(t, tc.text))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			p := cfg.Security.PreIDDefaultPolicy
			if p == nil {
				t.Fatal("PreIDDefaultPolicy nil")
			}
			if !p.LogSessionInit {
				t.Errorf("LogSessionInit dropped: %+v", p)
			}
			if tc.name != "second block without log does not clear first" && !p.LogSessionClose {
				t.Errorf("LogSessionClose dropped: %+v", p)
			}
		})
	}
	// Single block control
	cfg, err := CompileConfig(tree12825(t, `security { pre-id-default-policy { then { log { session-init; } } } }`))
	if err != nil || cfg.Security.PreIDDefaultPolicy == nil || !cfg.Security.PreIDDefaultPolicy.LogSessionInit || cfg.Security.PreIDDefaultPolicy.LogSessionClose {
		t.Fatalf("single control: cfg=%+v err=%v", cfg.Security.PreIDDefaultPolicy, err)
	}
	// Absent control stays nil
	cfg, err = CompileConfig(tree12825(t, `security { }`))
	if err != nil || cfg.Security.PreIDDefaultPolicy != nil {
		t.Fatalf("absent control: %+v err=%v", cfg.Security.PreIDDefaultPolicy, err)
	}
	// Flat-set spelling equivalence (duplicate set lines)
	tree := &ConfigTree{}
	for _, line := range []string{
		"set security pre-id-default-policy then log session-init",
		"set security pre-id-default-policy then log session-close",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err = CompileConfig(tree)
	if err != nil || cfg.Security.PreIDDefaultPolicy == nil || !cfg.Security.PreIDDefaultPolicy.LogSessionInit || !cfg.Security.PreIDDefaultPolicy.LogSessionClose {
		t.Fatalf("flat duplicate: %+v err=%v", cfg.Security.PreIDDefaultPolicy, err)
	}
}

// policy-stats: invalid values rejected strict / warned+off lenient; conflicting duplicates handled; valid controls pass.
func TestPolicyStatsSystemWide12825(t *testing.T) {
	// Invalid value cases.
	for _, val := range []string{"enabledd", "banana"} {
		text := `security { policy-stats { system-wide ` + val + `; } }`
		if err := SchemaValidate(tree12825(t, text), nil); err == nil {
			t.Errorf("%q: SchemaValidate accepted", val)
		} else if !strings.Contains(err.Error(), "system-wide") {
			t.Errorf("%q: schema error must name system-wide: %v", val, err)
		}
		if _, err := CompileConfig(tree12825(t, text)); err == nil {
			t.Errorf("%q: strict CompileConfig accepted", val)
		} else if !strings.Contains(err.Error(), "system-wide") {
			t.Errorf("%q: strict error must name system-wide: %v", val, err)
		}
		cfg, err := CompileConfigLenient(tree12825(t, text))
		if err != nil {
			t.Errorf("%q: lenient must boot: %v", val, err)
		} else {
			if cfg.Security.PolicyStatsEnabled {
				t.Errorf("%q: lenient must be fail-closed off", val)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "system-wide") && strings.Contains(w, val) && strings.Contains(w, "#12825") {
					found = true
				}
			}
			if !found {
				t.Errorf("%q: lenient warning missing #12825: %v", val, cfg.Warnings)
			}
		}
	}
	// duplicate leaves within one block, conflicting
	for _, text := range []string{
		`security { policy-stats { system-wide enable; system-wide disable; } }`,
		`security { policy-stats { system-wide enable; } policy-stats { system-wide disable; } }`,
		`security { policy-stats { system-wide disable; } policy-stats { system-wide enable; } }`,
		`security { policy-stats { system-wide enable; } } security { policy-stats { system-wide disable; } }`,
		`security { policy-stats { system-wide disable; } } security { policy-stats { system-wide enable; } }`,
	} {
		if _, err := CompileConfig(tree12825(t, text)); err == nil {
			t.Errorf("conflict strict accepted: %s", text)
		} else if !strings.Contains(err.Error(), "#12825") {
			t.Errorf("conflict strict error missing #12825: %v", err)
		}
		cfg, err := CompileConfigLenient(tree12825(t, text))
		if err != nil {
			t.Errorf("conflict lenient: %v", err)
		} else if cfg.Security.PolicyStatsEnabled {
			t.Errorf("conflict lenient must be off: %s", text)
		}
	}
	// controls
	controls := []struct {
		text string
		want bool
	}{
		{`security { policy-stats { system-wide enable; } }`, true},
		{`security { policy-stats { system-wide enabled; } }`, true},
		{`security { policy-stats { system-wide disable; } }`, false},
		{`security { policy-stats { system-wide disabled; } }`, false},
		{`security { }`, false},
		{`security { policy-stats { system-wide enable; system-wide enable; } }`, true},
		{`security { policy-stats { system-wide enable; } policy-stats { system-wide enable; } }`, true},
	}
	for _, tc := range controls {
		if err := SchemaValidate(tree12825(t, tc.text), nil); err != nil {
			t.Errorf("control schema rejected %q: %v", tc.text, err)
		}
		cfg, err := CompileConfig(tree12825(t, tc.text))
		if err != nil {
			t.Errorf("control strict rejected %q: %v", tc.text, err)
		} else if cfg.Security.PolicyStatsEnabled != tc.want {
			t.Errorf("control %q got %v want %v", tc.text, cfg.Security.PolicyStatsEnabled, tc.want)
		}
		cfg, err = CompileConfigLenient(tree12825(t, tc.text))
		if err != nil || cfg.Security.PolicyStatsEnabled != tc.want {
			t.Errorf("lenient control %q got %+v err=%v", tc.text, cfg, err)
		}
	}
	// flat spellings
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"set security policy-stats system-wide enable", true},
		{"set security policy-stats system-wide disable", false},
	} {
		tree := &ConfigTree{}
		path, err := ParseSetCommand(tc.line)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
		if err := SchemaValidate(tree, nil); err != nil {
			t.Errorf("flat schema %q: %v", tc.line, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg.Security.PolicyStatsEnabled != tc.want {
			t.Errorf("flat %q got err=%v cfg=%+v", tc.line, err, cfg)
		}
	}
	// flat invalid
	tree := &ConfigTree{}
	path, _ := ParseSetCommand("set security policy-stats system-wide enabledd")
	_ = tree.SetPath(path)
	if err := SchemaValidate(tree, nil); err == nil {
		t.Errorf("flat enabledd SchemaValidate accepted")
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Errorf("flat enabledd strict compile accepted")
	}
	// Value-less leaves are invalid too.
	text := `security { policy-stats { system-wide; } }`
	if err := SchemaValidate(tree12825(t, text), nil); err == nil {
		t.Errorf("value-less SchemaValidate accepted")
	}
	if _, err := CompileConfig(tree12825(t, text)); err == nil {
		t.Errorf("value-less strict accepted")
	}
	cfg, err := CompileConfigLenient(tree12825(t, text))
	if err != nil || cfg.Security.PolicyStatsEnabled {
		t.Errorf("value-less lenient: cfg=%+v err=%v", cfg, err)
	}
}
