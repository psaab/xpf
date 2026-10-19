package config

import (
	"strings"
	"testing"
)

// #15019 (A13-02): AAA `secret` leaves rendered in cleartext on every
// RedactedClone display surface, and `system accounting` committed strictly
// with no refusal or warning even though it has no runtime consumer.
//
// The three secret cells are:
//   - `system radius-server <addr> secret <s>` (strict-refused since #10831,
//     but still reachable on tolerant Load/SyncApply trees)
//   - `system tacplus-server <addr> secret <s>` (same)
//   - `system accounting ... server <addr> secret <s>` (was accepted silently
//     on every path)
//
// Each must render as ##SECRET-DATA##, and `system accounting` must be
// strict-refused like its #10831 siblings while warning on the lenient path.

const aaaSecret15019 = "AAA-SECRET-15019-LEAK"

var aaaSecretCells15019 = []struct {
	name    string
	command string
}{
	{"radius-server", "set system radius-server 192.0.2.10 secret " + aaaSecret15019},
	{"tacplus-server", "set system tacplus-server 192.0.2.20 secret " + aaaSecret15019},
	{"accounting", "set system accounting destination radius server 192.0.2.10 secret " + aaaSecret15019},
}

func TestAAASecretsRedactedOnDisplay15019(t *testing.T) {
	for _, tc := range aaaSecretCells15019 {
		t.Run(tc.name, func(t *testing.T) {
			tree := aaaTree10831(t, tc.command)
			if !strings.Contains(tree.FormatSet(), aaaSecret15019) {
				t.Fatalf("premise broken: cleartext render lost the planted secret:\n%s", tree.FormatSet())
			}
			red := tree.RedactedClone()
			renders := map[string]string{
				"Format":      red.Format(),
				"FormatSet":   red.FormatSet(),
				"FormatJSON":  red.FormatJSON(),
				"FormatXML":   red.FormatXML(),
				"Inheritance": red.FormatInheritance(),
			}
			for format, out := range renders {
				if strings.Contains(out, aaaSecret15019) {
					t.Errorf("%s leaked AAA secret %q in cleartext:\n%s", format, aaaSecret15019, out)
				}
				if !strings.Contains(out, SecretDataPlaceholder) {
					t.Errorf("%s did not mask AAA secret with %s:\n%s", format, SecretDataPlaceholder, out)
				}
			}
			diff := FormatCompareRedacted(&ConfigTree{}, tree)
			if strings.Contains(diff, aaaSecret15019) {
				t.Errorf("FormatCompareRedacted leaked AAA secret:\n%s", diff)
			}
			if !strings.Contains(tree.FormatSet(), aaaSecret15019) {
				t.Errorf("RedactedClone mutated the live tree:\n%s", tree.FormatSet())
			}
		})
	}
}

func TestAAASecretPlaceholderIngestRejected15019(t *testing.T) {
	for _, tc := range aaaSecretCells15019 {
		t.Run(tc.name, func(t *testing.T) {
			redacted := aaaTree10831(t, tc.command).RedactedClone()
			if !strings.Contains(redacted.FormatSet(), SecretDataPlaceholder) {
				t.Fatalf("premise broken: redacted export carries no placeholder:\n%s", redacted.FormatSet())
			}
			if err := checkRedactionPlaceholder(redacted); err == nil {
				t.Fatalf("re-ingesting the redacted %s export was not rejected", tc.name)
			}
		})
	}
}

// Hierarchical spelling: the same secrets nested in braces must mask too.
func TestAAASecretsRedactedHierarchical15019(t *testing.T) {
	tree, errs := NewParser(`system {
    accounting {
        destination {
            radius {
                server 192.0.2.10 {
                    secret ` + aaaSecret15019 + `;
                }
            }
        }
    }
    radius-server 192.0.2.11 {
        secret ` + aaaSecret15019 + `;
    }
}`).Parse()
	if len(errs) != 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	out := tree.RedactedClone().Format()
	if strings.Contains(out, aaaSecret15019) {
		t.Errorf("hierarchical AAA secret leaked:\n%s", out)
	}
	if n := strings.Count(out, SecretDataPlaceholder); n != 2 {
		t.Errorf("expected 2 masked AAA secrets, got %d:\n%s", n, out)
	}
}

// The generic `secret` redaction must stay scoped: a `secret` leaf outside
// the AAA / api-auth contexts is not a known credential and stays visible,
// mirroring the context gates for `password` and `key`.
func TestSecretRedactionStaysScoped15019(t *testing.T) {
	tree := aaaTree10831(t, "set system login user bob secret visible-token-15019")
	out := tree.RedactedClone().FormatSet()
	if !strings.Contains(out, "visible-token-15019") {
		t.Errorf("non-AAA `secret` was over-masked:\n%s", out)
	}
	if strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("non-AAA `secret` rendered the placeholder:\n%s", out)
	}
}

func TestSystemAccountingRejectedAtStrictCompile15019(t *testing.T) {
	cases := []string{
		"set system accounting destination radius server 192.0.2.10 secret " + aaaSecret15019,
		"set system accounting order radius",
	}
	for _, command := range cases {
		tree := aaaTree10831(t, command)
		for _, check := range []struct {
			name string
			run  func() error
		}{
			{"CompileConfig", func() error { _, err := CompileConfig(tree); return err }},
			{"CompileConfigForNode", func() error { _, err := CompileConfigForNode(tree, 0); return err }},
		} {
			t.Run(check.name+"/"+command, func(t *testing.T) {
				assertAAARefused10831(t, check.run(), "accounting")
			})
		}
	}
}

func TestSystemAccountingWarnsOnLenientCompile15019(t *testing.T) {
	tree := aaaTree10831(t,
		"set system accounting destination radius server 192.0.2.10 secret "+aaaSecret15019)
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
				if strings.Contains(warning, "local-only authentication") && strings.Contains(warning, "accounting") {
					if strings.Contains(warning, aaaSecret15019) {
						t.Fatalf("lenient warning leaked the accounting secret: %q", warning)
					}
					return
				}
			}
			t.Fatalf("warnings do not disclose unsupported accounting: %v", cfg.Warnings)
		})
	}
}

func TestSystemAccountingInAppliedGroupRejected15019(t *testing.T) {
	tree := aaaTree10831(t,
		"set groups aaa system accounting destination radius server 192.0.2.30 secret "+aaaSecret15019,
		"set apply-groups aaa")
	assertAAARefused10831(t, func() error { _, err := CompileConfig(tree); return err }(), "accounting")
	assertAAARefused10831(t, func() error { _, err := CompileConfigForNode(tree, 0); return err }(), "accounting")
}

// Brace-elided / packed spelling on the `system` line itself must not bypass
// the strict refusal (the #2419 dual-shape class the direct-children walk
// missed for other open-world leaves).
func TestSystemAccountingPackedOnSystemLineRejected15019(t *testing.T) {
	tree, errs := NewParser("system accounting order radius;\n").Parse()
	if len(errs) != 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	assertAAARefused10831(t, func() error { _, err := CompileConfig(tree); return err }(), "accounting")
}
