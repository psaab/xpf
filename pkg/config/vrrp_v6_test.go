package config

import (
	"testing"
)

// #2384 — IPv6 VRRP groups. The native VRRP engine already has full
// VRRPv3-IPv6 support and family-detects each VIP by parse
// (pkg/vrrp/instance.go ip.To4()==nil), but before #2384 there was NO
// config path to create one: vrrp-group existed only under family inet,
// and its virtual-address enforced ValidateIPv4CIDR. These tests prove
// the inet6 vrrp-group compiles into unit.VRRPGroups with the v6 VIP,
// that it coexists with an inet vrrp-group of the same group ID (dual
// stack, no key collision), and that the IPv4 path still works.

// firstVRRPGroupWithVIP returns the compiled vrrp-group on reth0 unit 0
// whose VirtualAddresses contains vip, or nil.
func firstVRRPGroupWithVIP(t *testing.T, cfg *Config, vip string) *VRRPGroup {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["reth0"]
	if ifc == nil {
		t.Fatal("reth0 not compiled")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("reth0 unit 0 not compiled")
	}
	for _, vg := range unit.VRRPGroups {
		for _, va := range vg.VirtualAddresses {
			if va == vip {
				return vg
			}
		}
	}
	return nil
}

const vrrp6Hier = `interfaces {
    reth0 {
        unit 0 {
            family inet6 {
                address 2001:db8::10/64 {
                    vrrp-group 1 {
                        virtual-address 2001:db8::1/64;
                        priority 200;
                        advertise-interval 1;
                        preempt;
                        accept-data;
                    }
                }
            }
        }
    }
}`

func TestVRRP6_HierarchicalCompiles(t *testing.T) {
	cfg, err := CompileConfig(parseHierText(t, vrrp6Hier))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "2001:db8::1/64")
	if vg == nil {
		t.Fatal("no vrrp-group carrying the IPv6 VIP 2001:db8::1/64 was compiled")
	}
	if vg.ID != 1 {
		t.Errorf("ID = %d, want 1", vg.ID)
	}
	if vg.Priority != 200 {
		t.Errorf("Priority = %d, want 200", vg.Priority)
	}
	if !vg.Preempt {
		t.Error("Preempt = false, want true")
	}
	if !vg.AcceptData {
		t.Error("AcceptData = false, want true")
	}
}

func TestVRRP6_FlatSetCompiles(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-group 1 virtual-address 2001:db8::1/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-group 1 priority 150",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-group 1 preempt",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "2001:db8::1/64")
	if vg == nil {
		t.Fatal("flat-set IPv6 vrrp-group did not compile its VIP")
	}
	if vg.Priority != 150 {
		t.Errorf("Priority = %d, want 150", vg.Priority)
	}
	if !vg.Preempt {
		t.Error("Preempt = false, want true")
	}
}

// A single unit carrying BOTH a v4 vrrp-group AND a v6 vrrp-group with
// the SAME group ID must compile into two distinct map entries — the key
// is `<address-CIDR>_grp<id>` and the v4/v6 address strings differ, so
// there is no collision. The engine family-detects each VIP, so a shared
// group ID across families is fine.
func TestVRRP6_DualStackNoCollision(t *testing.T) {
	cfg, err := CompileConfig(parseHierText(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.254/24;
                        priority 200;
                    }
                }
            }
            family inet6 {
                address 2001:db8::10/64 {
                    vrrp-group 1 {
                        virtual-address 2001:db8::1/64;
                        priority 150;
                    }
                }
            }
        }
    }
}`))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	unit := cfg.Interfaces.Interfaces["reth0"].Units[0]
	if len(unit.VRRPGroups) != 2 {
		t.Fatalf("expected 2 vrrp-groups (v4 + v6, same ID), got %d: %v", len(unit.VRRPGroups), unit.VRRPGroups)
	}
	v4 := firstVRRPGroupWithVIP(t, cfg, "10.0.61.254/24")
	v6 := firstVRRPGroupWithVIP(t, cfg, "2001:db8::1/64")
	if v4 == nil || v6 == nil {
		t.Fatalf("dual-stack: v4=%v v6=%v", v4, v6)
	}
	if v4.Priority != 200 {
		t.Errorf("v4 Priority = %d, want 200", v4.Priority)
	}
	if v6.Priority != 150 {
		t.Errorf("v6 Priority = %d, want 150", v6.Priority)
	}
}

// Regression: the IPv4 vrrp-group path is unchanged by the refactor.
func TestVRRP6_IPv4StillCompiles(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24 vrrp-group 5 virtual-address 10.0.61.254/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24 vrrp-group 5 priority 110",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.254/24")
	if vg == nil {
		t.Fatal("IPv4 vrrp-group regressed: VIP not compiled")
	}
	if vg.ID != 5 || vg.Priority != 110 {
		t.Errorf("got ID=%d Priority=%d, want 5/110", vg.ID, vg.Priority)
	}
}
