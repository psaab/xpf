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
func TestForwardingRoutingInstanceSkipsVRFNameGate_12038(t *testing.T) {
	const name = "ISP-B-forward"
	for _, tc := range []struct {
		name         string
		instanceType string
		hasType      bool
		applyGroup   bool
		forwarding   bool
	}{
		{name: "direct forwarding", instanceType: "forwarding", hasType: true, forwarding: true},
		{name: "group forwarding", instanceType: "forwarding", hasType: true, applyGroup: true, forwarding: true},
		{name: "virtual-router", instanceType: "virtual-router", hasType: true},
		{name: "omitted instance-type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := routingInstanceTree12038(t, name, tc.instanceType, tc.hasType, tc.applyGroup)

			cfg, err := CompileConfig(tree.Clone())
			if tc.forwarding {
				if err != nil {
					t.Errorf("strict compile rejected forwarding instance: %v", err)
				} else {
					assertRoutingInstance12038(t, cfg, name, true, "forwarding")
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "#11391") {
					t.Fatalf("strict compile error = %v, want #11391 VRF-name rejection", err)
				}
			}

			cfg, err = CompileConfigLenient(tree.Clone())
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			assertRoutingInstance12038(t, cfg, name, tc.forwarding, tc.instanceType)
		})
	}
}

func routingInstanceTree12038(t *testing.T, name, instanceType string, hasType, applyGroup bool) *ConfigTree {
	t.Helper()
	if applyGroup {
		return setTree11391(t,
			fmt.Sprintf("set groups g1 routing-instances %s instance-type %s",
				strconv.Quote(name), strconv.Quote(instanceType)),
			"set apply-groups g1",
		)
	}
	var text strings.Builder
	fmt.Fprintf(&text, "routing-instances { %s { ", strconv.Quote(name))
	if hasType {
		fmt.Fprintf(&text, "instance-type %s; ", instanceType)
	}
	text.WriteString("} }\n")
	tree, errs := NewParser(text.String()).Parse()
	if len(errs) > 0 {
		t.Fatalf("routing-instance fixture must parse: %v\n%s", errs, text.String())
	}
	return tree
}

func assertRoutingInstance12038(t *testing.T, cfg *Config, name string, active bool, instanceType string) {
	t.Helper()
	activeNames := make(map[string]*RoutingInstanceConfig, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		activeNames[ri.Name] = ri
	}
	if got := activeNames[name]; active {
		if got == nil {
			t.Fatalf("routing-instance %q is not active: %+v", name, cfg.QuarantinedRoutingInstances)
		}
		if got.InstanceType != instanceType {
			t.Errorf("routing-instance %q instance-type = %q, want %q", name, got.InstanceType, instanceType)
		}
	} else if got != nil {
		t.Fatalf("routing-instance %q remained active: %+v", name, got)
	}
	quarantined := false
	for _, ri := range cfg.QuarantinedRoutingInstances {
		if ri.Name == name {
			quarantined = true
		}
	}
	if quarantined == active {
		t.Errorf("routing-instance %q quarantined = %t, want %t", name, quarantined, !active)
	}
	warning := false
	for _, message := range cfg.Warnings {
		if strings.Contains(message, fmt.Sprintf("routing-instance %q", name)) {
			warning = true
			if active {
				t.Errorf("active forwarding instance has a quarantine warning: %s", message)
			} else if !strings.Contains(message, "#11391") {
				t.Errorf("quarantine warning does not identify #11391: %s", message)
			}
		}
	}
	if warning == active {
		t.Errorf("routing-instance %q has quarantine warning = %t, want %t", name, warning, !active)
	}
}
func TestForwardingInvalidVRFNameStillClaimsTableID_12038(t *testing.T) {
	const (
		validName      = "blue"
		forwardingName = "badname621558"
	)
	if validID, forwardingID := StableRoutingInstanceTableID(validName), StableRoutingInstanceTableID(forwardingName); validID != forwardingID {
		t.Fatalf("collision fixture drifted: table ids for %q and %q are %d and %d",
			validName, forwardingName, validID, forwardingID)
	}
	tree := setTree11391(t,
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances badname621558 instance-type forwarding",
	)

	_, err := CompileConfig(tree.Clone())
	if err == nil || !strings.Contains(err.Error(), "#3855") || strings.Contains(err.Error(), "#11391") {
		t.Fatalf("strict compile error = %v, want #3855 table collision without #11391 VRF-name rejection", err)
	}

	cfg, err := CompileConfigLenient(tree.Clone())
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != forwardingName ||
		cfg.RoutingInstances[0].InstanceType != "forwarding" {
		t.Fatalf("active routing instances = %+v, want only forwarding instance %q",
			cfg.RoutingInstances, forwardingName)
	}
	if len(cfg.QuarantinedRoutingInstances) != 1 || cfg.QuarantinedRoutingInstances[0].Name != validName {
		t.Fatalf("quarantined routing instances = %+v, want only colliding VRF %q",
			cfg.QuarantinedRoutingInstances, validName)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, forwardingName) && strings.Contains(warning, "#11391") {
			t.Errorf("forwarding instance was incorrectly quarantined by #11391: %s", warning)
		}
	}
}
func TestNodeSpecificForwardingRoutingInstanceSkipsVRFNameGate_12038(t *testing.T) {
	tree := setTree11391(t,
		"set groups node0 routing-instances ISP-B-forward instance-type forwarding",
		"set groups node1 routing-instances ISP-B-forward instance-type forwarding",
		`set apply-groups "${node}"`,
	)
	for _, nodeID := range []int{0, 1} {
		t.Run(fmt.Sprintf("node%d", nodeID), func(t *testing.T) {
			cfg, err := CompileConfigForNode(tree.Clone(), nodeID)
			if err != nil {
				t.Fatalf("strict node compile rejected forwarding instance: %v", err)
			}
			assertRoutingInstance12038(t, cfg, "ISP-B-forward", true, "forwarding")

			cfg, err = CompileConfigForNodeLenient(tree.Clone(), nodeID)
			if err != nil {
				t.Fatalf("tolerant node compile: %v", err)
			}
			assertRoutingInstance12038(t, cfg, "ISP-B-forward", true, "forwarding")
		})
	}
}

// TestNodeDivergentInvalidNameNoSpuriousTableCollision_12038 covers the
// #12281 NEEDS-FOLD finding: a name that is forwarding on node0 but an invalid
// VRF on node1 must not collide in preflight with a peer-only table owner.
func TestNodeDivergentInvalidNameNoSpuriousTableCollision_12038(t *testing.T) {
	const (
		divergentName = "badname621558"
		peerOnlyName  = "blue"
	)
	if got, want := StableRoutingInstanceTableID(divergentName), 525590; got != want {
		t.Fatalf("fixture drifted: table id for %q = %d, want %d", divergentName, got, want)
	}
	if got := StableRoutingInstanceTableID(peerOnlyName); got != 525590 {
		t.Fatalf("fixture drifted: table id for %q = %d, want 525590", peerOnlyName, got)
	}
	tree := setTree11391(t,
		"set groups node0 routing-instances badname621558 instance-type forwarding",
		"set groups node1 routing-instances badname621558 instance-type virtual-router",
		"set groups node1 routing-instances blue instance-type virtual-router",
		`set apply-groups "${node}"`,
	)

	for _, compiler := range []struct {
		name string
		run  func(*ConfigTree) error
	}{
		{"union", func(tr *ConfigTree) error { _, err := CompileConfig(tr); return err }},
		{"node0", func(tr *ConfigTree) error { _, err := CompileConfigForNode(tr, 0); return err }},
		{"node1", func(tr *ConfigTree) error { _, err := CompileConfigForNode(tr, 1); return err }},
	} {
		t.Run("strict/"+compiler.name, func(t *testing.T) {
			err := compiler.run(tree.Clone())
			if err == nil || !strings.Contains(err.Error(), "#11391") ||
				!strings.Contains(err.Error(), divergentName) {
				t.Fatalf("strict %s compile must reject the invalid VRF name: %v", compiler.name, err)
			}
			if strings.Contains(err.Error(), "#3855") {
				t.Fatalf("strict %s compile reported a spurious #3855 table collision: %v", compiler.name, err)
			}
		})
	}

	for _, compiler := range []struct {
		name string
		run  func(*ConfigTree) (*Config, error)
	}{
		{"union", CompileConfigLenient},
		{"node0", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
	} {
		t.Run("lenient/"+compiler.name, func(t *testing.T) {
			cfg, err := compiler.run(tree.Clone())
			if err != nil {
				t.Fatalf("lenient %s compile: %v", compiler.name, err)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#3855") {
					t.Errorf("lenient %s compile reported a spurious table collision: %s", compiler.name, warning)
				}
			}
			if compiler.name == "node0" {
				assertRoutingInstance12038(t, cfg, divergentName, true, "forwarding")
				if len(cfg.Warnings) != 0 {
					t.Errorf("lenient node0 should be silent, got warnings: %v", cfg.Warnings)
				}
			}
		})
	}

	t.Run("lenient/node1", func(t *testing.T) {
		cfg, err := CompileConfigForNodeLenient(tree.Clone(), 1)
		if err != nil {
			t.Fatalf("lenient node1 compile: %v", err)
		}
		if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != peerOnlyName {
			t.Fatalf("active routing instances = %+v, want only %q", cfg.RoutingInstances, peerOnlyName)
		}
		assertRoutingInstance12038(t, cfg, divergentName, false, "virtual-router")
		if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "#11391") ||
			!strings.Contains(cfg.Warnings[0], divergentName) ||
			strings.Contains(cfg.Warnings[0], "#3855") {
			t.Fatalf("lenient node1 must emit only the #11391 quarantine warning: %v", cfg.Warnings)
		}
	})
}
