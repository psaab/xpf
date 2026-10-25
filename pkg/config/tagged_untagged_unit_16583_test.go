package config

import (
	"strings"
	"testing"
)

// Tests for #16583 (residual of #15034): a non-zero unit with no vlan-id
// (or vlan-id 0) on a vlan-tagging / flexible-vlan-tagging parent
// committed strict-clean. Tagging does not create its device: a VLAN
// child exists only for vlanID > 0, so ResolveKernelIfName still
// derives `parent.<unit>`, planPhysDesired still folds its addresses
// onto the parent, and its zone/input filter bind to a device nothing
// creates. The #15034 arm skipped tagging parents outright; it now
// applies regardless of parent tagging mode.
//
// FAIL-ON-REVERT: restoring the tagging-parent skip (or gating the
// #15034 arm on !tagging) makes the strict rejects below compile clean
// (RED) and drops the lenient warning. The vlan-id control, unit 0
// without vlan-id on a tagging parent (test/incus/xpf-vlan-test.conf),
// and tunnel-unit controls stay green either way.

func mustReject16583(t *testing.T, tree *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict compile to reject untagged non-zero unit on tagging parent, got nil error")
	}
	if !strings.Contains(err.Error(), "#15034") || !strings.Contains(err.Error(), "unit 5") {
		t.Fatalf("reject error %q does not name #15034 / unit 5", err.Error())
	}
	if !strings.Contains(err.Error(), "ge-0/0/1") {
		t.Fatalf("reject error %q does not name ge-0/0/1", err.Error())
	}
}

func mustAccept16583(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected strict compile to accept, got %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#15034") {
			t.Fatalf("accepted config must not warn #15034, got %q", w)
		}
	}
	return cfg
}

func TestTaggedParentUntaggedNonzeroUnitRejected16583(t *testing.T) {
	// Issue's exact shape: vlan-tagging parent, unit 5 with an input
	// filter and no vlan-id, bound to zone dmz as ge-0/0/1.5.
	for _, tagging := range []string{"vlan-tagging", "flexible-vlan-tagging"} {
		mustReject16583(t, flatTreeFromSets(t,
			"set interfaces ge-0/0/1 "+tagging,
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0/0/1 unit 5 family inet address 10.0.5.1/24",
			"set interfaces ge-0/0/1 unit 5 family inet filter input F",
			"set firewall family inet filter F term t then accept",
			"set security zones security-zone lan interfaces ge-0/0/1.0",
			"set security zones security-zone dmz interfaces ge-0/0/1.5",
		))
	}
	// vlan-id 0 is still no positive tag on a tagging parent.
	mustReject16583(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 5 vlan-id 0",
		"set interfaces ge-0/0/1 unit 5 family inet address 10.0.5.1/24",
	))
	// Hierarchical shape on a flexible-vlan-tagging parent.
	func() {
		_, err := CompileConfig(hierTree(t, `interfaces {
    ge-0/0/1 {
        flexible-vlan-tagging;
        unit 0 { family inet { address 10.0.0.1/24; } }
        unit 5 { family inet { address 10.0.5.1/24; } }
    }
}`))
		if err == nil || !strings.Contains(err.Error(), "#15034") || !strings.Contains(err.Error(), "unit 5") {
			t.Fatalf("hierarchical flexible-tagging untagged unit 5 must reject #15034 naming ge-0/0/1 unit 5, got %v", err)
		}
	}()
}

func TestTaggedParentUnitControlsAccepted16583(t *testing.T) {
	// The vlan-id control: tagged non-zero unit under vlan-tagging.
	mustAccept16583(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 5 vlan-id 5",
		"set interfaces ge-0/0/1 unit 5 family inet address 10.0.5.1/24",
		"set security zones security-zone dmz interfaces ge-0/0/1.5",
	))
	// Unit 0 without vlan-id on a tagging parent is the native unit
	// (test/incus/xpf-vlan-test.conf shape, with its tagged sibling).
	mustAccept16583(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.100.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set security zones security-zone dmz interfaces ge-0/0/1.100",
	))
	// Tunnel units still compile: the per-unit tunnel device is the
	// owner, tagging mode aside.
	mustAccept16583(t, flatTreeFromSets(t,
		"set interfaces gr-0/0/0 vlan-tagging",
		"set interfaces gr-0/0/0 unit 5 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 5 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 unit 5 family inet address 10.1.0.1/30",
	))
}

func TestTaggedParentUntaggedUnitLenientWarns16583(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 5 family inet address 10.0.5.1/24",
	))
	if err != nil {
		t.Fatalf("lenient must not brick: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#15034") && strings.Contains(w, "ge-0/0/1") && strings.Contains(w, "unit 5") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn #15034; warnings=%v", cfg.Warnings)
	}
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/1"]; ifc == nil || ifc.Units[5] == nil {
		t.Fatalf("lenient compiled shape changed: %+v", cfg.Interfaces.Interfaces["ge-0/0/1"])
	}
}
