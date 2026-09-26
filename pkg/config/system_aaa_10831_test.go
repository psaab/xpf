package config

import (
	"strings"
	"testing"
)

func aaaTree10831(t *testing.T, commands ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, command := range commands {
		path, err := ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	return tree
}

func assertAAARefused10831(t *testing.T, err error, leaf string) {
	t.Helper()
	if err == nil {
		t.Fatalf("system %s was accepted; unsupported AAA must not be silently dropped", leaf)
	}
	for _, want := range []string{"local-only authentication", leaf} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestJunosAAAStanzasRejectedAtStrictCompile10831(t *testing.T) {
	cases := []struct {
		leaf    string
		command string
	}{
		{"radius-server", "set system radius-server 192.0.2.10 secret example"},
		{"tacplus-server", "set system tacplus-server 192.0.2.20 secret example"},
		{"authentication-order", "set system authentication-order radius"},
	}
	for _, tc := range cases {
		t.Run(tc.leaf, func(t *testing.T) {
			tree := aaaTree10831(t, tc.command)
			checks := []struct {
				name string
				run  func() error
			}{
				{"CompileConfig", func() error { _, err := CompileConfig(tree); return err }},
				{"CompileConfigForNode", func() error { _, err := CompileConfigForNode(tree, 0); return err }},
			}
			for _, check := range checks {
				t.Run(check.name, func(t *testing.T) {
					assertAAARefused10831(t, check.run(), tc.leaf)
				})
			}
		})
	}
}

func TestJunosAAAStanzasWarnOnLenientCompile10831(t *testing.T) {
	cases := []struct {
		leaf    string
		command string
	}{
		{"radius-server", "set system radius-server 192.0.2.10 secret example"},
		{"tacplus-server", "set system tacplus-server 192.0.2.20 secret example"},
		{"authentication-order", "set system authentication-order radius"},
	}
	for _, tc := range cases {
		t.Run(tc.leaf, func(t *testing.T) {
			tree := aaaTree10831(t, tc.command)
			for _, compile := range []struct {
				name string
				run  func(*ConfigTree) (*Config, error)
			}{
				{"CompileConfigLenient", CompileConfigLenient},
				{"CompileConfigForNodeLenient", func(tree *ConfigTree) (*Config, error) {
					return CompileConfigForNodeLenient(tree, 0)
				}},
			} {
				t.Run(compile.name, func(t *testing.T) {
					cfg, err := compile.run(tree)
					if err != nil {
						t.Fatalf("lenient compile should preserve boot compatibility: %v", err)
					}
					for _, warning := range cfg.Warnings {
						if strings.Contains(warning, "local-only authentication") && strings.Contains(warning, tc.leaf) {
							return
						}
					}
					t.Fatalf("warnings do not disclose unsupported %s: %v", tc.leaf, cfg.Warnings)
				})
			}
		})
	}
}

func TestJunosAAAStanzaInAppliedGroupRejected10831(t *testing.T) {
	tree := aaaTree10831(t,
		"set groups aaa system tacplus-server 192.0.2.30 secret example",
		"set apply-groups aaa")
	assertAAARefused10831(t, func() error { _, err := CompileConfig(tree); return err }(), "tacplus-server")
	assertAAARefused10831(t, func() error { _, err := CompileConfigForNode(tree, 0); return err }(), "tacplus-server")
}

func TestLocalSystemConfigStillCompiles10831(t *testing.T) {
	tree := aaaTree10831(t, "set system host-name fw1")
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate local system config: %v", err)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig local system config: %v", err)
	}
}
