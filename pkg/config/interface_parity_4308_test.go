package config

// Regression tests for #4308 (fable-review-167 I-3): five common Junos
// interface knobs were accepted by the permissive parser but never modeled or
// compiled. They are now typed leaves; #11434 also enforces native-vlan-id,
// while the other four still surface an accepted-only advisory.
//
// RED-on-revert: drop the compiler assignments and each field reads back its
// zero value (the silent-drop); drop the validateInterfaceParityWarnings call
// and the advisory disappears.

import (
	"strings"
	"testing"
)

func compileTreeFromSet(t *testing.T, lines []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	// The knobs must also pass strict schema validation (typed leaves).
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Fatalf("SchemaValidate rejected the interface parity knobs: %v", err)
	}
	return cfg
}

// The knobs must survive compile (not silently dropped) and validate.
func TestInterfaceParityKnobsCompile_4308(t *testing.T) {
	cfg := compileTreeFromSet(t, []string{
		"set interfaces ge-0-0-0 native-vlan-id 100",
		"set interfaces ge-0-0-0 gratuitous-arp-reply",
		"set interfaces ge-0-0-0 no-gratuitous-arp-request",
		"set interfaces ge-0-0-0 unit 0 family inet unnumbered-address lo0.0",
		"set interfaces ge-0-0-0 unit 0 family inet targeted-broadcast",
	})

	ifc := cfg.Interfaces.Interfaces["ge-0-0-0"]
	if ifc == nil {
		t.Fatal("missing interface ge-0-0-0")
	}
	if ifc.NativeVlanID != 100 {
		t.Errorf("native-vlan-id = %d, want 100", ifc.NativeVlanID)
	}
	if !ifc.GratuitousARPReply {
		t.Error("gratuitous-arp-reply not compiled")
	}
	if !ifc.NoGratuitousARPRequest {
		t.Error("no-gratuitous-arp-request not compiled")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("missing unit 0")
	}
	if unit.UnnumberedInet != "lo0.0" {
		t.Errorf("unnumbered-address = %q, want lo0.0", unit.UnnumberedInet)
	}
	if !unit.TargetedBroadcast {
		t.Error("targeted-broadcast not compiled")
	}
}

// The remaining accepted-only knobs (not native-vlan-id) surface an advisory.
func TestInterfaceParityKnobsAdvisory_4308(t *testing.T) {
	cfg := compileTreeFromSet(t, []string{
		"set interfaces ge-0-0-0 native-vlan-id 100",
		"set interfaces ge-0-0-0 gratuitous-arp-reply",
		"set interfaces ge-0-0-0 no-gratuitous-arp-request",
		"set interfaces ge-0-0-0 unit 0 family inet unnumbered-address lo0.0",
		"set interfaces ge-0-0-0 unit 0 family inet targeted-broadcast",
	})

	var warn string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#4308") && strings.Contains(w, "ge-0-0-0") {
			warn = w
		}
	}
	if warn == "" {
		t.Fatalf("expected a #4308 accepted-only advisory for ge-0-0-0, got: %v", ValidateConfig(cfg))
	}
	for _, knob := range []string{
		"gratuitous-arp-reply", "no-gratuitous-arp-request",
		"unnumbered-address", "targeted-broadcast",
	} {
		if !strings.Contains(warn, knob) {
			t.Errorf("advisory missing %q: %s", knob, warn)
		}
	}
	if strings.Contains(warn, "native-vlan-id") {
		t.Errorf("enforced native-vlan-id still surfaced as accepted-only: %s", warn)
	}
}

func TestNativeVLANHasNoAcceptedOnlyAdvisory_11434(t *testing.T) {
	cfg := compileTreeFromSet(t, []string{
		"set interfaces ge-0-0-0 native-vlan-id 100",
		"set interfaces ge-0-0-0 unit 100 vlan-id 100",
	})
	for _, warning := range ValidateConfig(cfg) {
		if strings.Contains(warning, "native-vlan-id") {
			t.Fatalf("enforced native-vlan-id still warns as inert: %s", warning)
		}
	}
}

// An interface with none of the knobs must NOT trigger the advisory (guards
// against a false-positive warning firing on every interface).
func TestInterfaceParityNoAdvisoryWhenUnset_4308(t *testing.T) {
	cfg := compileTreeFromSet(t, []string{
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.1/24",
	})
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#4308") {
			t.Fatalf("unexpected #4308 advisory for a plain interface: %s", w)
		}
	}
}
