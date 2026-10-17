package config

import (
	"strings"
	"testing"
)

func parseLLDP14616(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", text, errs)
	}
	return tree
}

func compiledLLDP14616(t *testing.T, text string) *LLDPConfig {
	t.Helper()
	cfg, err := CompileConfig(parseLLDP14616(t, text))
	if err != nil {
		t.Fatalf("CompileConfig %q: %v", text, err)
	}
	if cfg.Protocols.LLDP == nil {
		t.Fatalf("CompileConfig %q: LLDP is nil", text)
	}
	return cfg.Protocols.LLDP
}

// #14616: `protocols lldp interface X disable;` (one-line spelling)
// compiled to Disable:false, and any trailing token was silently ignored.
func TestLLDPInterfacePackedDisable14616(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"hierarchical packed", `protocols { lldp { interface ge-0/0/0 disable; } }`},
		{"hierarchical packed under protocols brace", `protocols lldp { interface ge-0/0/0 disable; }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := SchemaValidate(parseLLDP14616(t, tc.text), nil); err != nil {
				t.Fatalf("SchemaValidate rejected packed disable: %v", err)
			}
			lldp := compiledLLDP14616(t, tc.text)
			if len(lldp.Interfaces) != 1 {
				t.Fatalf("interfaces = %+v, want one", lldp.Interfaces)
			}
			if lldp.Interfaces[0].Name != "ge-0/0/0" || !lldp.Interfaces[0].Disable {
				t.Fatalf("interface = %+v, want {ge-0/0/0 true}", lldp.Interfaces[0])
			}
		})
	}

	t.Run("controls still pass", func(t *testing.T) {
		block := compiledLLDP14616(t, `protocols { lldp { interface ge-0/0/0 { disable; } } }`)
		if len(block.Interfaces) != 1 || !block.Interfaces[0].Disable {
			t.Fatalf("block control = %+v, want disabled", block.Interfaces)
		}
		plain := compiledLLDP14616(t, `protocols { lldp { interface ge-0/0/0; } }`)
		if len(plain.Interfaces) != 1 || plain.Interfaces[0].Disable {
			t.Fatalf("plain control = %+v, want enabled", plain.Interfaces)
		}
		// Flat set spelling already worked via SetPath nesting.
		tree := &ConfigTree{}
		path, err := ParseSetCommand("set protocols lldp interface ge-0/0/0 disable")
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("flat CompileConfig: %v", err)
		}
		if len(cfg.Protocols.LLDP.Interfaces) != 1 || !cfg.Protocols.LLDP.Interfaces[0].Disable {
			t.Fatalf("flat control = %+v, want disabled", cfg.Protocols.LLDP.Interfaces)
		}
	})

	for _, tc := range []struct {
		name string
		text string
		want string
	}{
		{"hierarchical junk instead of disable", `protocols { lldp { interface ge-0/0/0 frobnicate; } }`, "frobnicate"},
		{"hierarchical junk after disable", `protocols { lldp { interface ge-0/0/0 disable frobnicate; } }`, "frobnicate"},
		{"hierarchical junk after name with extra", `protocols { lldp { interface ge-0/0/0 disable disable; } }`, "disable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseLLDP14616(t, tc.text)
			err := SchemaValidate(tree, nil)
			if err == nil {
				t.Fatalf("SchemaValidate accepted %q, want rejection naming %q", tc.text, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SchemaValidate error = %v, want naming %q", err, tc.want)
			}
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted %q, want rejection", tc.text)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error = %v, want naming %q", err, tc.want)
			}
		})
	}

	t.Run("flat junk rejected", func(t *testing.T) {
		tree := &ConfigTree{}
		path, err := ParseSetCommand("set protocols lldp interface ge-0/0/0 frobnicate")
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
		if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), "frobnicate") {
			t.Fatalf("SchemaValidate = %v, want rejection naming frobnicate", err)
		}
	})

	t.Run("lenient compiles packed forms without bricking", func(t *testing.T) {
		for _, text := range []string{
			`protocols { lldp { interface ge-0/0/0 disable; } }`,
			`protocols { lldp { interface ge-0/0/0 frobnicate; } }`,
		} {
			cfg, err := CompileConfigLenient(parseLLDP14616(t, text))
			if err != nil {
				t.Fatalf("lenient %q: %v", text, err)
			}
			if cfg.Protocols.LLDP == nil || len(cfg.Protocols.LLDP.Interfaces) != 1 {
				t.Fatalf("lenient %q LLDP = %+v", text, cfg.Protocols.LLDP)
			}
		}
		// Lenient packed disable should still take effect (not just not brick).
		cfg, err := CompileConfigLenient(parseLLDP14616(t, `protocols { lldp { interface ge-0/0/0 disable; } }`))
		if err != nil {
			t.Fatalf("lenient disable: %v", err)
		}
		if !cfg.Protocols.LLDP.Interfaces[0].Disable {
			t.Fatalf("lenient packed disable = %+v, want disabled", cfg.Protocols.LLDP.Interfaces[0])
		}
	})
}
