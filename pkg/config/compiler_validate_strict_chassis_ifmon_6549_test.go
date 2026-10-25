package config

import (
	"fmt"
	"strings"
	"testing"
)

// #6549: `chassis cluster redundancy-group <n> interface-monitor <if> weight
// <w>` had NO range gate at any layer. The leaf packs `<ifname> weight <n>`
// onto one node key so it has no typed schema leaf (unlike the ip-monitoring
// weight siblings, which are ValidateInteger(0,255)), and compileChassis reads
// the weight with strconv.Atoi under no bound.
//
// Out of range, the weight breaks the HA election: it is the debt subtracted
// from the redundancy-group weight, which starts at 255, so `weight -100` on a
// down monitor puts rg.Weight at 355 — read raw by the local election but
// advertised through the single-byte heartbeat weight field as uint8(355) ==
// 99. Both nodes then elect primary from identical state: duplicate VIP and
// duplicate RETH virtual MAC on the LAN.
//
// FAIL-ON-REVERT: remove the interface-monitor weight loop from
// validateChassisClusterStrict and the out-of-range subtests go green on the
// BAD config. The in-range subtests pin that the gate does not over-reject, and
// the tolerant-path subtest pins #1960 no-brick.

// ifMonSetLines returns the flat-set lines for one redundancy group carrying a
// single interface-monitor with the given weight.
func ifMonSetLines(weight int) []string {
	return []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		fmt.Sprintf("set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0 weight %d", weight),
	}
}

func TestChassisInterfaceMonitorWeightOutOfRangeFailsCommit_6549(t *testing.T) {
	for _, weight := range []int{-100000, -256, -100, -1, 256, 300, 100000} {
		t.Run(fmt.Sprintf("weight_%d", weight), func(t *testing.T) {
			tree := buildTree(t, ifMonSetLines(weight))

			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject interface-monitor weight %d "+
					"(the heartbeat weight field is one byte while the local election "+
					"reads the raw int), got nil error", weight)
			}
			msg := err.Error()
			if !strings.Contains(msg, "interface-monitor ge-0/0/0") {
				t.Fatalf("error %q does not name the offending interface-monitor", msg)
			}
			if !strings.Contains(msg, fmt.Sprintf("weight %d", weight)) {
				t.Fatalf("error %q does not name the out-of-range weight %d", msg, weight)
			}
			if !strings.Contains(msg, "out of range 0..255") {
				t.Fatalf("error %q does not state the admitted range", msg)
			}
		})
	}
}

func TestChassisInterfaceMonitorWeightInRangeCommits_6549(t *testing.T) {
	// Over-reach guard: every legal weight, including both boundaries, must
	// still commit AND still compile to exactly the configured value.
	for _, weight := range []int{0, 1, 128, 254, 255} {
		t.Run(fmt.Sprintf("weight_%d", weight), func(t *testing.T) {
			tree := buildTree(t, ifMonSetLines(weight))

			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("interface-monitor weight %d must commit, got %v", weight, err)
			}
			mons := onlyRGInterfaceMonitors(t, cfg)
			if len(mons) != 1 {
				t.Fatalf("expected 1 interface-monitor, got %d", len(mons))
			}
			if mons[0].Interface != "ge-0/0/0" {
				t.Fatalf("interface = %q, want ge-0/0/0", mons[0].Interface)
			}
			if mons[0].Weight != weight {
				t.Fatalf("weight = %d, want %d (the gate must not alter an in-range value)",
					mons[0].Weight, weight)
			}
		})
	}
}

// TestChassisInterfaceMonitorWeightMissingCommits_6549 pins that an
// interface-monitor with no `weight` token at all is untouched by the gate — it
// compiles to the pre-existing 0 default rather than being rejected.
func TestChassisInterfaceMonitorWeightMissingCommits_6549(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 interface-monitor ge-0/0/0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("interface-monitor with no weight must commit, got %v", err)
	}
	mons := onlyRGInterfaceMonitors(t, cfg)
	if len(mons) != 1 || mons[0].Weight != 0 {
		t.Fatalf("expected one monitor with the default weight 0, got %+v", mons)
	}
}

// TestChassisInterfaceMonitorWeightTolerantPathNoBrick_6549 pins the #1960
// posture: an already-persisted / peer-synced config carrying an out-of-range
// weight must still BOOT, with a warning — not fail the load and blackout the
// node. pkg/cluster clamps it (ClampInterfaceMonitorWeight / rgWeightFromDebt)
// so the leniently-loaded value still cannot diverge the two nodes.
func TestChassisInterfaceMonitorWeightTolerantPathNoBrick_6549(t *testing.T) {
	tree := buildTree(t, ifMonSetLines(-100))

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject an out-of-range interface-monitor "+
			"weight (no-brick), got %v", err)
	}
	if !warningsContain(cfg.Warnings, "interface-monitor ge-0/0/0") {
		t.Fatalf("lenient compile should have warned about the out-of-range weight; warnings=%v",
			cfg.Warnings)
	}
	// The lenient path deliberately keeps compiling the raw value — the runtime
	// clamp, not the compiler, is what bounds it (see ClampInterfaceMonitorWeight).
	mons := onlyRGInterfaceMonitors(t, cfg)
	if len(mons) != 1 || mons[0].Weight != -100 {
		t.Fatalf("lenient compile should preserve the raw weight for the runtime clamp, got %+v",
			mons)
	}
	if got, clamped := ClampInterfaceMonitorWeight(mons[0].Weight); got != 0 || !clamped {
		t.Fatalf("ClampInterfaceMonitorWeight(%d) = (%d, %v), want (0, true)",
			mons[0].Weight, got, clamped)
	}
}

// TestChassisInterfaceMonitorWeightHierarchicalShape_6549 pins that the gate
// covers the braces spelling too — the shape a persisted config is rendered
// and re-parsed in (ConfigTree.Format emits `interface-monitor { ge-0/0/0
// weight <n>; }`), which is how an out-of-range weight survives a reboot.
func TestChassisInterfaceMonitorWeightHierarchicalShape_6549(t *testing.T) {
	const text = `chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        redundancy-group 1 {
            node 0 priority 200;
            interface-monitor {
                ge-0/0/0 weight -100;
            }
        }
    }
}`
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject the hierarchical out-of-range weight, got nil error")
	}
}

// onlyRGInterfaceMonitors returns the interface monitors of the single
// redundancy group the test configs above define.
func onlyRGInterfaceMonitors(t *testing.T, cfg *Config) []*InterfaceMonitor {
	t.Helper()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("compiled config carries no chassis cluster")
	}
	rgs := cfg.Chassis.Cluster.RedundancyGroups
	if len(rgs) != 1 {
		t.Fatalf("expected 1 redundancy-group, got %d", len(rgs))
	}
	return rgs[0].InterfaceMonitors
}
