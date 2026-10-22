package config

import "testing"

// #2850 — VRRP `preempt hold-time <seconds>`. Junos supports a configurable
// preempt hold-time: a higher-priority backup that comes back up waits
// hold-time seconds before reclaiming mastership from a still-live
// lower-priority master (so dynamic routing converges before failback).
// These tests prove the leaf parses in BOTH config shapes and that bare
// `preempt` (no hold-time) still compiles to PreemptHoldTime 0 (immediate).

// TestVRRPPreemptHoldTime_FlatSet drives the flat-set path
// (ParseSetCommand + SetPath) — the only valid way to test set syntax.
func TestVRRPPreemptHoldTime_FlatSet(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 priority 200",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 preempt hold-time 60",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatal("flat-set vrrp-group did not compile its VIP")
	}
	if !vg.Preempt {
		t.Error("Preempt = false, want true")
	}
	// FAIL-ON-REVERT: dropping the flat-set hold-time parse leaves this 0.
	if vg.PreemptHoldTime != 60 {
		t.Errorf("PreemptHoldTime = %d, want 60", vg.PreemptHoldTime)
	}
}

const vrrpPreemptHoldHier = `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                        priority 200;
                        preempt {
                            hold-time 120;
                        }
                    }
                }
            }
        }
    }
}`

// TestVRRPPreemptHoldTime_Hierarchical drives the braced `preempt {
// hold-time <n>; }` shape.
func TestVRRPPreemptHoldTime_Hierarchical(t *testing.T) {
	cfg, err := CompileConfig(parseHierText(t, vrrpPreemptHoldHier))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatal("hierarchical vrrp-group did not compile its VIP")
	}
	if !vg.Preempt {
		t.Error("Preempt = false, want true")
	}
	// FAIL-ON-REVERT: dropping the hierarchical hold-time parse leaves this 0.
	if vg.PreemptHoldTime != 120 {
		t.Errorf("PreemptHoldTime = %d, want 120", vg.PreemptHoldTime)
	}
}

// TestVRRPPreemptHoldTime_BarePreemptUnchanged proves bare `preempt` (no
// hold-time) still compiles to immediate preemption (PreemptHoldTime 0) —
// today's behavior, unchanged.
func TestVRRPPreemptHoldTime_BarePreemptUnchanged(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 preempt",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatal("flat-set bare-preempt vrrp-group did not compile its VIP")
	}
	if !vg.Preempt {
		t.Error("Preempt = false, want true")
	}
	if vg.PreemptHoldTime != 0 {
		t.Errorf("PreemptHoldTime = %d, want 0 (bare preempt = immediate)", vg.PreemptHoldTime)
	}
}

// TestVRRPPreemptHoldTime_SchemaRange verifies the schema typed-leaf
// validation accepts an in-range hold-time and rejects out-of-range / non-
// numeric values (1..3600 seconds).
func TestVRRPPreemptHoldTime_SchemaRange(t *testing.T) {
	base := "set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 preempt hold-time "
	cases := []struct {
		val     string
		wantErr bool
	}{
		{"60", false},
		{"1", false},
		{"3600", false},
		{"0", true},
		{"3601", true},
		{"abc", true},
	}
	for _, c := range cases {
		tree := &ConfigTree{}
		path, err := ParseSetCommand(base + c.val)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c.val, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", c.val, err)
		}
		verr := SchemaValidate(tree)
		if c.wantErr && verr == nil {
			t.Errorf("hold-time %q: want validation error, got nil", c.val)
		}
		if !c.wantErr && verr != nil {
			t.Errorf("hold-time %q: want no error, got %v", c.val, verr)
		}
	}
}
