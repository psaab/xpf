package config

import (
	"strings"
	"testing"
)

// Tests for #15034 (residual of #14574): a non-zero unit with no VLAN
// tag on an untagged parent committed clean. The networkd writer folds
// the unit's addresses onto the untagged parent while
// ResolveKernelIfName / snapshotLinuxName derive `parent.<unit>` — a
// device nothing creates — so the unit's zone and input filter bind to
// a phantom device and the subnet is attributed to unit 0's zone. The
// #14574 gate keyed only on a positive tag; validateVlanIDTaggingAST
// now also strict-rejects the untagged non-zero unit (lenient warns).
//
// FAIL-ON-REVERT: removing the untaggedNonzeroUnit15034 arm (or the
// validateVlanIDTaggingAST call sites) makes the strict rejects below
// compile clean (RED) and drops the lenient warning. The tunnel, lo0,
// st0, irb, tagged and unit-0 controls stay green either way — they
// prove the gate keys on the untagged non-zero unit, not on any
// multi-unit or tunnel presence.

func mustReject15034(t *testing.T, tree *ConfigTree) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict compile to reject untagged non-zero unit, got nil error")
	}
	if !strings.Contains(err.Error(), "#15034") || !strings.Contains(err.Error(), "unit 1") {
		t.Fatalf("reject error %q does not name #15034 / unit 1", err.Error())
	}
}

func mustAccept15034(t *testing.T, tree *ConfigTree) *Config {
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

func TestUntaggedNonzeroUnitRejected15034(t *testing.T) {
	// Issue's exact acceptance shape: unit 0 in zone lan, unit 1 in
	// zone dmz with an input filter — the filter's device never exists.
	mustReject15034(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 1 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 1 family inet filter input F",
		"set firewall family inet filter F term t then accept",
		"set security zones security-zone lan interfaces ge-0/0/1.0",
		"set security zones security-zone dmz interfaces ge-0/0/1.1",
	))
	// Hierarchical shape.
	func() {
		_, err := CompileConfig(hierTree(t, `interfaces {
    ge-0/0/1 {
        unit 0 { family inet { address 10.0.0.1/24; } }
        unit 1 { family inet { address 10.0.1.1/24; } }
    }
}`))
		if err == nil || !strings.Contains(err.Error(), "#15034") {
			t.Fatalf("hierarchical untagged unit 1 must reject #15034, got %v", err)
		}
	}()
	// vlan-id 0 is still no positive tag: unit 1 with the untagged
	// sentinel splits the same way.
	mustReject15034(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 1 vlan-id 0",
		"set interfaces ge-0/0/1 unit 1 family inet address 10.0.1.1/24",
	))
	// A reth unit resolves onto the member's `.<unit>` device, which
	// only tagging creates — not exempt.
	func() {
		_, err := CompileConfig(flatTreeFromSets(t,
			"set interfaces reth1 unit 1 family inet address 10.0.1.1/24",
		))
		if err == nil || !strings.Contains(err.Error(), "#15034") {
			t.Fatalf("untagged reth1 unit 1 must reject #15034, got %v", err)
		}
	}()
}

func TestUntaggedUnitControlsAccepted15034(t *testing.T) {
	// Unit 0 alone on an untagged parent.
	mustAccept15034(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	))
	// Tagged non-zero unit under vlan-tagging (the #14574 control).
	mustAccept15034(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 100 vlan-id 100",
		"set interfaces ge-0/0/1 unit 100 family inet address 10.0.1.1/24",
	))
	// Unit-level tunnel: the per-unit tunnel device is the owner.
	mustAccept15034(t, flatTreeFromSets(t,
		"set interfaces gr-0/0/0 unit 1 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 1 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.1.0.1/30",
	))
	// Interface-level tunnel: units share the interface tunnel device.
	mustAccept15034(t, flatTreeFromSets(t,
		"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.1.0.1/30",
	))
	// WireGuard unit tunnel.
	mustAccept15034(t, flatTreeFromSets(t,
		"set interfaces wg0 unit 1 tunnel wireguard peer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= allowed-ips 10.91.0.0/24",
		"set interfaces wg0 unit 1 family inet address 10.91.0.1/24",
	))
	// lo0 multi-unit loopback (Junos lo0.N) still compiles.
	mustAccept15034(t, flatTreeFromSets(t,
		"set interfaces lo0 unit 0 family inet address 127.0.0.1/8",
		"set interfaces lo0 unit 1 family inet address 127.0.1.1/8",
	))
	// st0 unit: the xfrmi device is the owner.
	mustAccept15034(t, flatTreeFromSets(t,
		"set interfaces st0 unit 1 family inet address 198.51.100.1/24",
	))
	// irb unit: the bridge-domain routing-interface device is the owner.
	mustAccept15034(t, flatTreeFromSets(t,
		"set interfaces irb unit 2 family inet address 10.0.2.1/24",
	))
	// Tagged reth unit under vlan-tagging (ordinary HA trunk shape).
	mustAccept15034(t, flatTreeFromSets(t,
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 100 vlan-id 100",
		"set interfaces reth1 unit 100 family inet address 10.0.100.1/24",
	))
}

func TestUntaggedUnitPeerOnlyGroup15034(t *testing.T) {
	src := `groups {
    node0 {
        interfaces {
            ge-0/0/1 { unit 1 { family inet { address 10.0.1.1/24; } } }
        }
    }
    node1 {
        interfaces {
            ge-0/0/1 { vlan-tagging; unit 1 { vlan-id 1; family inet { address 10.0.1.1/24; } } }
        }
    }
}
apply-groups "${node}";
chassis { cluster { node 0; authentication-key test-cluster-psk-6611; } }`
	tree := hierTree(t, src)
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatalf("commit as node0 must reject: node0 view is the untagged unit (node1 tagging must not excuse it)")
	} else if !strings.Contains(err.Error(), "#15034") && !strings.Contains(err.Error(), "#14574") {
		t.Fatalf("node0 reject %q not #15034/#14574", err.Error())
	}
	if _, err := CompileConfigForNode(tree, 1); err == nil {
		t.Fatalf("commit as node1 must reject: both-node union includes node0's untagged view")
	}
}

func TestUntaggedUnitLenientWarns15034(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 1 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("lenient must not brick: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#15034") && strings.Contains(w, "ge-0/0/1") && strings.Contains(w, "unit 1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn #15034; warnings=%v", cfg.Warnings)
	}
	// Lenient keeps the historical compiled shape (both units present);
	// the warning is the only new behaviour on the tolerant path.
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/1"]; ifc == nil || ifc.Units[1] == nil {
		t.Fatalf("lenient compiled shape changed: %+v", cfg.Interfaces.Interfaces["ge-0/0/1"])
	}
}
