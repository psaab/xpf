package config

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func routingInstanceTree11391(t *testing.T, names ...string) *ConfigTree {
	t.Helper()
	var text strings.Builder
	text.WriteString("routing-instances {\n")
	for _, name := range names {
		fmt.Fprintf(&text, "    %s { instance-type virtual-router; }\n", strconv.Quote(name))
	}
	text.WriteString("}\n")
	tree, errs := NewParser(text.String()).Parse()
	if len(errs) > 0 {
		t.Fatalf("routing-instance fixture must parse: %v\n%s", errs, text.String())
	}
	return tree
}

func setTree11391(t *testing.T, commands ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, command := range commands {
		path, err := ParseSetCommand(command)
		if err != nil {
			t.Fatalf("parse %q: %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("setpath %q: %v", command, err)
		}
	}
	return tree
}

func TestRoutingInstanceKernelNameStrictRejection_11391(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"Comcast-GigabitPro", []string{"vrf-Comcast-GigabitPro", "22 bytes", "IFNAMSIZ"}},
		{"abcdefghijkl", []string{"vrf-abcdefghijkl", "16 bytes", "IFNAMSIZ"}},
		{"éééééé", []string{"16 bytes", "IFNAMSIZ"}},
		{"bad/name", []string{"vrf-bad/name", "dev_valid_name", "0x2f"}},
		{"bad name", []string{"vrf-bad name", "dev_valid_name", "0x20"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := routingInstanceTree11391(t, tc.name)
			for _, compiler := range []struct {
				name string
				run  func(*ConfigTree) error
			}{
				{"CompileConfig", func(tree *ConfigTree) error {
					_, err := CompileConfig(tree)
					return err
				}},
				{"CompileConfigForNode", func(tree *ConfigTree) error {
					_, err := CompileConfigForNode(tree, 0)
					return err
				}},
			} {
				t.Run(compiler.name, func(t *testing.T) {
					err := compiler.run(tree)
					if err == nil {
						t.Fatalf("strict compile accepted routing-instance %q; "+
							"its derived VRF name must be rejected", tc.name)
					}
					for _, part := range tc.want {
						if !strings.Contains(err.Error(), part) {
							t.Errorf("strict error %q does not include %q", err, part)
						}
					}
				})
			}
		})
	}
}

func TestRoutingInstanceKernelNameASTUnion_11391(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree *ConfigTree
	}{
		{"applied group", setTree11391(t,
			"set groups g1 routing-instances abcdefghijkl instance-type virtual-router",
			"set apply-groups g1",
		)},
		{"node group expansion", setTree11391(t,
			"set groups node0 routing-instances abcdefghijkl instance-type virtual-router",
			"set groups node1 routing-instances blue instance-type virtual-router",
			`set apply-groups "${node}"`,
		)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, compiler := range []struct {
				name string
				run  func(*ConfigTree) error
			}{
				{"CompileConfig", func(tree *ConfigTree) error {
					_, err := CompileConfig(tree)
					return err
				}},
				{"CompileConfigForNode0", func(tree *ConfigTree) error {
					_, err := CompileConfigForNode(tree, 0)
					return err
				}},
				{"CompileConfigForNode1", func(tree *ConfigTree) error {
					_, err := CompileConfigForNode(tree, 1)
					return err
				}},
			} {
				t.Run(compiler.name, func(t *testing.T) {
					err := compiler.run(tc.tree)
					if err == nil ||
						!strings.Contains(err.Error(), "abcdefghijkl") ||
						!strings.Contains(err.Error(), "IFNAMSIZ") {
						t.Errorf("%s did not reject the invalid expanded routing-instance name: %v", compiler.name, err)
					}
				})
			}
		})
	}
}

func TestRoutingInstanceKernelNameExactLimitAccepted_11391(t *testing.T) {
	const name = "abcdefghijk"
	tree := routingInstanceTree11391(t, name)
	deviceName := routingInstanceVRFDevicePrefix + name
	_, reason := routingInstanceVRFDeviceNameIssue(name)
	if reason != "" || len(deviceName) != maxLinuxIfNameLen {
		t.Fatalf("boundary fixture derives %q (%d bytes), reason %q; "+
			"want exactly %d valid bytes", deviceName, len(deviceName), reason, maxLinuxIfNameLen)
	}
	for _, compiler := range []struct {
		name string
		run  func(*ConfigTree) (*Config, error)
	}{
		{"CompileConfig", CompileConfig},
		{"CompileConfigForNode", func(tree *ConfigTree) (*Config, error) {
			return CompileConfigForNode(tree, 0)
		}},
	} {
		t.Run(compiler.name, func(t *testing.T) {
			cfg, err := compiler.run(tree)
			if err != nil {
				t.Fatalf("strict compile rejected a %d-byte derived VRF name: %v", maxLinuxIfNameLen, err)
			}
			if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != name {
				t.Fatalf("compiled routing instances = %+v, want %q", cfg.RoutingInstances, name)
			}
		})
	}
}

func TestRoutingInstanceKernelNameQuarantinedLenient_11391(t *testing.T) {
	invalidNames := []string{"Comcast-GigabitPro", "bad/name", "bad name"}
	tree := routingInstanceTree11391(t, append(invalidNames, "blue")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must boot with invalid persisted routing-instance names: %v", err)
	}

	active := make(map[string]bool, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		active[ri.Name] = true
	}
	if len(active) != 1 || !active["blue"] {
		t.Fatalf("active routing instances = %v, want only [blue]", active)
	}

	quarantined := make(map[string]bool, len(cfg.QuarantinedRoutingInstances))
	for _, ri := range cfg.QuarantinedRoutingInstances {
		quarantined[ri.Name] = true
		if active[ri.Name] {
			t.Errorf("quarantined routing instance %q also remained active", ri.Name)
		}
	}
	if len(quarantined) != len(invalidNames) {
		t.Fatalf("quarantined routing instances = %v, want %v", quarantined, invalidNames)
	}
	for _, name := range invalidNames {
		if !quarantined[name] {
			t.Errorf("routing instance %q was not recorded as quarantined", name)
		}
	}

	wantWarnings := map[string][]string{
		"Comcast-GigabitPro": {"QUARANTINED", "IFNAMSIZ", "22 bytes", "#11391"},
		"bad/name":           {"QUARANTINED", "dev_valid_name", "0x2f", "#11391"},
		"bad name":           {"QUARANTINED", "dev_valid_name", "0x20", "#11391"},
	}
	seenWarnings := make(map[string]int, len(wantWarnings))
	for _, warning := range cfg.Warnings {
		for name, parts := range wantWarnings {
			if !strings.Contains(warning, fmt.Sprintf("routing-instance %q", name)) {
				continue
			}
			seenWarnings[name]++
			for _, part := range parts {
				if !strings.Contains(warning, part) {
					t.Errorf("warning for %q omits %q: %s", name, part, warning)
				}
			}
		}
	}
	for name := range wantWarnings {
		if seenWarnings[name] != 1 {
			t.Errorf("expected one quarantine warning for %q, got %d: %v", name, seenWarnings[name], cfg.Warnings)
		}
	}
}

func TestInvalidRoutingInstanceNameDoesNotClaimTableID_11391(t *testing.T) {
	const (
		validName   = "blue"
		invalidName = "badname621558"
	)
	if validID, invalidID := StableRoutingInstanceTableID(validName), StableRoutingInstanceTableID(invalidName); validID != invalidID {
		t.Fatalf("collision fixture drifted: table ids for %q and %q are %d and %d",
			validName, invalidName, validID, invalidID)
	}
	tree := routingInstanceTree11391(t, validName, invalidName)

	_, err := CompileConfig(tree.Clone())
	if err == nil || !strings.Contains(err.Error(), "#11391") ||
		!strings.Contains(err.Error(), invalidName) {
		t.Fatalf("strict compile must reject the invalid name, not report a table collision: %v", err)
	}

	cfg, err := CompileConfigLenient(tree.Clone())
	if err != nil {
		t.Fatalf("lenient compile should quarantine the invalid name: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != validName {
		t.Fatalf("active routing instances = %+v, want only %q", cfg.RoutingInstances, validName)
	}
	if len(cfg.QuarantinedRoutingInstances) != 1 ||
		cfg.QuarantinedRoutingInstances[0].Name != invalidName {
		t.Fatalf("quarantined routing instances = %+v, want only %q",
			cfg.QuarantinedRoutingInstances, invalidName)
	}
	if len(cfg.Warnings) != 1 ||
		!strings.Contains(cfg.Warnings[0], "#11391") ||
		!strings.Contains(cfg.Warnings[0], invalidName) ||
		strings.Contains(cfg.Warnings[0], "#3855") {
		t.Fatalf("invalid-name quarantine must emit only its #11391 warning: %v", cfg.Warnings)
	}
}
