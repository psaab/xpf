package config

import (
	"strings"
	"testing"
)

func interfaceDuplexTree11824(t *testing.T, value string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set interfaces ge-0/0/0 duplex " + value)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	return tree
}

func TestInterfaceDuplexEnumAcceptsCanonicalModes11824(t *testing.T) {
	for _, mode := range []string{"full", "half", "auto"} {
		t.Run(mode, func(t *testing.T) {
			tree := interfaceDuplexTree11824(t, mode)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected valid duplex %q: %v", mode, err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected valid duplex %q: %v", mode, err)
			}
			if got := cfg.Interfaces.Interfaces["ge-0/0/0"].Duplex; got != mode {
				t.Fatalf("compiled duplex = %q, want %q", got, mode)
			}
		})
	}
}

func TestInterfaceDuplexInvalidValuesStrictRejectLenientWarn11824(t *testing.T) {
	for _, value := range []string{"garbage", "Full", "FULL"} {
		t.Run(value, func(t *testing.T) {
			tree := interfaceDuplexTree11824(t, value)
			if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), "duplex") {
				t.Fatalf("strict schema validation for duplex %q = %v, want a duplex rejection", value, err)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "duplex") {
				t.Fatalf("strict compile for duplex %q = %v, want a duplex rejection", value, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected stored duplex %q: %v", value, err)
			}
			if got := cfg.Interfaces.Interfaces["ge-0/0/0"].Duplex; got != "" {
				t.Fatalf("lenient compile retained invalid duplex %q", got)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), `interfaces ge-0/0/0 duplex "`+value+`"`) {
				t.Fatalf("lenient compile did not warn naming invalid duplex %q: %v", value, cfg.Warnings)
			}
		})
	}
}
