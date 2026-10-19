package config

import "testing"

// #15047 (A05-05): a generic vrrp-group without `preempt` compiled
// Preempt=false. Junos and RFC 5798 default Preempt_Mode to TRUE, so a
// backup never took over from a track-demoted master (track.go only
// lowers the advertised priority; instance_rx.go resets the master-down
// timer on every advert when !getPreempt()). Fix: the group constructor
// defaults Preempt=true and `no-preempt` is parsed to clear it.
//
// FAIL-ON-REVERT: reverting the constructor default (or dropping either
// `no-preempt` arm) turns the corresponding cells RED.

func TestVRRPPreemptDefault15047_FlatSetNoPreemptKeyword(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 priority 200",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 track-interface ge-0/0/1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatal("vrrp-group did not compile its VIP")
	}
	if !vg.Preempt {
		t.Error("Preempt = false, want true (Junos/RFC 5798 default when `preempt` is not configured)")
	}
}

func TestVRRPPreemptDefault15047_HierarchicalNoPreemptKeyword(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                        priority 200;
                    }
                }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatal("vrrp-group did not compile its VIP")
	}
	if !vg.Preempt {
		t.Error("Preempt = false, want true (Junos/RFC 5798 default, hierarchical shape)")
	}
}

func TestVRRPPreemptDefault15047_NoPreemptFlatSet(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 priority 200",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 no-preempt",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatal("vrrp-group did not compile its VIP")
	}
	if vg.Preempt {
		t.Error("Preempt = true, want false (`no-preempt` configured)")
	}
}

func TestVRRPPreemptDefault15047_NoPreemptHierarchical(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                        priority 200;
                        no-preempt;
                    }
                }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatal("vrrp-group did not compile its VIP")
	}
	if vg.Preempt {
		t.Error("Preempt = true, want false (`no-preempt` configured, hierarchical shape)")
	}
}

// Controls: explicit `preempt` still compiles true in both shapes, and a
// packed hierarchical one-liner honours `no-preempt` as a delimiter
// (a following property must still parse).
func TestVRRPPreemptDefault15047_ExplicitPreemptAndPackedControl(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                        priority 200;
                        preempt;
                    }
                    vrrp-group 2 virtual-address 10.0.61.2/24 no-preempt priority 150;
                }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["reth0"]
	if ifc == nil || ifc.Units[0] == nil {
		t.Fatal("reth0 unit 0 not compiled")
	}
	var g1, g2 *VRRPGroup
	for _, vg := range ifc.Units[0].VRRPGroups {
		switch vg.ID {
		case 1:
			g1 = vg
		case 2:
			g2 = vg
		}
	}
	if g1 == nil || !g1.Preempt {
		t.Errorf("explicit `preempt` group: Preempt = %v, want true", g1)
	}
	if g2 == nil {
		t.Fatal("packed vrrp-group 2 not compiled")
	}
	if g2.Preempt {
		t.Error("packed `no-preempt` group: Preempt = true, want false")
	}
	if g2.Priority != 150 {
		t.Errorf("packed group after `no-preempt`: Priority = %d, want 150 (delimiter must not swallow the next property)", g2.Priority)
	}
}
