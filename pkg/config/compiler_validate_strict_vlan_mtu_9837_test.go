package config

import (
	"strings"
	"testing"
)

// The #9837 repro: a tagged unit's family MTU above the interface-level mtu
// must be refused at commit, naming the interface, the unit, and both
// values. Before the gate this committed clean and every apply logged
// `failed to set VLAN sub-interface MTU` while the child kept its old MTU.
func TestVlanUnitMTUAboveParentRejected9837(t *testing.T) {
	_, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1400",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
		"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
	))
	if err == nil {
		t.Fatal("strict commit ACCEPTED a tagged unit MTU above the parent MTU")
	}
	for _, want := range []string{"ge-0-0-2", "unit 50", "9000", "1400", "#9837"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err.Error(), want)
		}
	}
}

// The hierarchical spelling reaches the same gate: the flat and hier shapes
// differ upstream (packed-run expansion), so one spelling's rejection does
// not prove the other's.
func TestVlanUnitMTUHierarchicalRejected9837(t *testing.T) {
	assertCommitRejects(t, hierTree(t, `interfaces {
    ge-0-0-2 {
        vlan-tagging;
        mtu 1400;
        unit 50 {
            vlan-id 50;
            family inet {
                address 172.16.50.8/24;
                mtu 9000;
            }
        }
    }
}`), "family mtu 9000 exceeds interface mtu 1400")
}

// The two no-check cases from the issue, plus the boundary, all still
// commit. The two-family interaction lives in
// TestVlanUnitMTUFamilyOrderMatchesRuntime9837, where family ORDER decides
// the compiled value.
func TestVlanUnitMTUControlsAccepted9837(t *testing.T) {
	cases := map[string][]string{
		// An untagged unit's MTU replaces the parent's: cannot exceed it.
		"untagged unit above interface mtu": {
			"set interfaces ge-0-0-0 mtu 1400",
			"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0-0-0 unit 0 family inet mtu 9000",
		},
		// No interface-level mtu: limited by the parent's RUNNING MTU,
		// which the commit cannot see — stays a runtime warning.
		"tagged unit without parent mtu": {
			"set interfaces ge-0-0-2 vlan-tagging",
			"set interfaces ge-0-0-2 unit 50 vlan-id 50",
			"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
		},
		// Boundary: the kernel refuses ABOVE, not equal.
		"tagged unit equal to parent mtu": {
			"set interfaces ge-0-0-2 vlan-tagging",
			"set interfaces ge-0-0-2 mtu 1400",
			"set interfaces ge-0-0-2 unit 50 vlan-id 50",
			"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 1400",
		},
		"tagged unit below parent mtu": {
			"set interfaces ge-0-0-2 vlan-tagging",
			"set interfaces ge-0-0-2 mtu 1400",
			"set interfaces ge-0-0-2 unit 50 vlan-id 50",
			"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 1300",
		},
	}
	for name, sets := range cases {
		t.Run(name, func(t *testing.T) {
			assertCommitAccepts(t, flatTreeFromSets(t, sets...))
		})
	}
}

// Family ORDER decides the compiled unit MTU — a pre-existing compiler
// quirk, out of scope here: the inet arm OVERWRITES unit.MTU unconditionally
// while the inet6 arm takes the MIN, so inet-before-inet6 (the conventional
// order) compiles the lower of the two family values and inet6-before-inet
// compiles the inet value. The gate judges exactly the compiled value the
// dataplane would write (applyVLANSubInterfaceMTU9757 reads the same
// unit.MTU), so gate and runtime agree in BOTH orders: accept with 1300
// compiled, reject with 9000 compiled. The reject leg reads the compiled
// value back through the lenient path, where strict returns no config.
func TestVlanUnitMTUFamilyOrderMatchesRuntime9837(t *testing.T) {
	base := []string{
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1400",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
	}
	t.Run("inet before inet6 compiles min, gate accepts", func(t *testing.T) {
		sets := append(append([]string{}, base...),
			"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
			"set interfaces ge-0-0-2 unit 50 family inet6 mtu 1300",
		)
		cfg := assertCommitAccepts(t, flatTreeFromSets(t, sets...))
		if got := cfg.Interfaces.Interfaces["ge-0-0-2"].Units[50].MTU; got != 1300 {
			t.Errorf("compiled unit.MTU = %d, want 1300 (the min the dataplane would write)", got)
		}
	})
	t.Run("inet6 before inet compiles overwrite, gate rejects", func(t *testing.T) {
		sets := append(append([]string{}, base...),
			"set interfaces ge-0-0-2 unit 50 family inet6 mtu 1300",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
		)
		assertCommitRejects(t, flatTreeFromSets(t, sets...),
			"family mtu 9000 exceeds interface mtu 1400")
		cfg, err := CompileConfigLenient(flatTreeFromSets(t, sets...))
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if got := cfg.Interfaces.Interfaces["ge-0-0-2"].Units[50].MTU; got != 9000 {
			t.Errorf("compiled unit.MTU = %d, want 9000 (the overwrite the dataplane would write)", got)
		}
	})
}

// `family inet6 mtu` compiles into the same unit.MTU: an inet6-only
// offender must trip the gate, not just the inet spelling.
func TestVlanUnitMTUInet6OnlyRejected9837(t *testing.T) {
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1400",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet6 address fd00:50::8/64",
		"set interfaces ge-0-0-2 unit 50 family inet6 mtu 9000",
	), "family mtu 9000 exceeds interface mtu 1400")
}

// The tolerant load / peer-sync path downgrades to a warning (#1960
// no-brick): an already-persisted config an older binary accepted still
// boots, and the runtime warning already covers it. The downgraded warning
// carries the full gate message, so it names both values just like the
// strict rejection.
func TestVlanUnitMTULenientWarns9837(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1400",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
		"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
	))
	if err != nil {
		t.Fatalf("expected lenient compile to accept, got %v", err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"9000", "1400", "#9837"} {
		if !strings.Contains(joined, want) {
			t.Errorf("lenient warnings %q do not name %q", joined, want)
		}
	}
}

// First-error stability: interfaces and units are visited sorted, so the
// commit-check diagnostic names ge-0-0-2 unit 50 however the maps iterate.
func TestVlanUnitMTUFirstErrorStable9837(t *testing.T) {
	_, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0-0-3 vlan-tagging",
		"set interfaces ge-0-0-3 mtu 1400",
		"set interfaces ge-0-0-3 unit 7 vlan-id 7",
		"set interfaces ge-0-0-3 unit 7 family inet mtu 9000",
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1400",
		"set interfaces ge-0-0-2 unit 60 vlan-id 60",
		"set interfaces ge-0-0-2 unit 60 family inet mtu 9000",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
	))
	if err == nil {
		t.Fatal("strict commit ACCEPTED two offending tagged units")
	}
	if !strings.Contains(err.Error(), "ge-0-0-2 unit 50") {
		t.Errorf("first error %q does not name ge-0-0-2 unit 50", err.Error())
	}
}

// An untagged sibling's unit MTU overrides the interface level on the parent
// (planPhysDesired; pinned by TestAnUntaggedUnitStillOverridesTheInterfaceMTU_9761),
// so the gate compares against that EFFECTIVE parent: ifc 1400 + untagged
// unit0 1500 + tagged unit50 1500 runs fine (parent 1500), and rejecting it
// would be a NEW false refusal vs base. Only a REFERENCED sibling counts —
// the planner never sees an unzoned unit — and between referenced siblings
// the LOWEST number wins. A referenced sibling pins the parent even with no
// interface-level `mtu`, so that sub-case is checked too.
func TestVlanUnitMTUUntaggedSiblingOverride9837(t *testing.T) {
	t.Run("sibling override accepts runtime-fine shape", func(t *testing.T) {
		assertCommitAccepts(t, flatTreeFromSets(t,
			"set interfaces ge-0-0-2 vlan-tagging",
			"set interfaces ge-0-0-2 mtu 1400",
			"set interfaces ge-0-0-2 unit 0 family inet address 10.0.9.1/24",
			"set interfaces ge-0-0-2 unit 0 family inet mtu 1500",
			"set interfaces ge-0-0-2 unit 50 vlan-id 50",
			"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 1500",
			"set security zones security-zone trust interfaces ge-0-0-2.0",
			"set security zones security-zone trust interfaces ge-0-0-2.50",
		))
	})
	t.Run("override raises the bar, still rejects above it", func(t *testing.T) {
		assertCommitRejects(t, flatTreeFromSets(t,
			"set interfaces ge-0-0-2 vlan-tagging",
			"set interfaces ge-0-0-2 mtu 1400",
			"set interfaces ge-0-0-2 unit 0 family inet address 10.0.9.1/24",
			"set interfaces ge-0-0-2 unit 0 family inet mtu 1500",
			"set interfaces ge-0-0-2 unit 50 vlan-id 50",
			"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 1600",
			"set security zones security-zone trust interfaces ge-0-0-2.0",
			"set security zones security-zone trust interfaces ge-0-0-2.50",
		), "family mtu 1600 exceeds effective parent mtu 1500 (from untagged unit 0; interface mtu 1400)")
	})
	t.Run("unreferenced sibling does not count", func(t *testing.T) {
		assertCommitRejects(t, flatTreeFromSets(t,
			"set interfaces ge-0-0-2 vlan-tagging",
			"set interfaces ge-0-0-2 mtu 1400",
			"set interfaces ge-0-0-2 unit 0 family inet address 10.0.9.1/24",
			"set interfaces ge-0-0-2 unit 0 family inet mtu 1500",
			"set interfaces ge-0-0-2 unit 50 vlan-id 50",
			"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 1500",
			"set security zones security-zone trust interfaces ge-0-0-2.50",
		), "family mtu 1500 exceeds interface mtu 1400")
	})
	t.Run("lowest sibling number wins", func(t *testing.T) {
		assertCommitRejects(t, flatTreeFromSets(t,
			"set interfaces ge-0-0-2 vlan-tagging",
			"set interfaces ge-0-0-2 mtu 1400",
			"set interfaces ge-0-0-2 unit 0 family inet address 10.0.9.1/24",
			"set interfaces ge-0-0-2 unit 0 family inet mtu 1300",
			"set interfaces ge-0-0-2 unit 1 family inet address 10.0.9.2/24",
			"set interfaces ge-0-0-2 unit 1 family inet mtu 1600",
			"set interfaces ge-0-0-2 unit 50 vlan-id 50",
			"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 1500",
			"set security zones security-zone trust interfaces ge-0-0-2.0",
			"set security zones security-zone trust interfaces ge-0-0-2.1",
			"set security zones security-zone trust interfaces ge-0-0-2.50",
		), "family mtu 1500 exceeds effective parent mtu 1300 (from untagged unit 0; interface mtu 1400)")
	})
	t.Run("sibling pins parent with no interface mtu, rejects above it", func(t *testing.T) {
		assertCommitRejects(t, flatTreeFromSets(t,
			"set interfaces ge-0-0-2 vlan-tagging",
			"set interfaces ge-0-0-2 unit 0 family inet address 10.0.9.1/24",
			"set interfaces ge-0-0-2 unit 0 family inet mtu 1400",
			"set interfaces ge-0-0-2 unit 50 vlan-id 50",
			"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 9000",
			"set security zones security-zone trust interfaces ge-0-0-2.0",
			"set security zones security-zone trust interfaces ge-0-0-2.50",
		), "family mtu 9000 exceeds effective parent mtu 1400 (from untagged unit 0; no interface mtu)")
	})
	t.Run("sibling pins parent with no interface mtu, accepts below it", func(t *testing.T) {
		assertCommitAccepts(t, flatTreeFromSets(t,
			"set interfaces ge-0-0-2 vlan-tagging",
			"set interfaces ge-0-0-2 unit 0 family inet address 10.0.9.1/24",
			"set interfaces ge-0-0-2 unit 0 family inet mtu 1400",
			"set interfaces ge-0-0-2 unit 50 vlan-id 50",
			"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
			"set interfaces ge-0-0-2 unit 50 family inet mtu 1300",
			"set security zones security-zone trust interfaces ge-0-0-2.0",
			"set security zones security-zone trust interfaces ge-0-0-2.50",
		))
	})
}
