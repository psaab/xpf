package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// TestShowChassisClusterStatus_VRRPLogicalZoneInterface is the #4908
// (C175-HC-116) and #10844 RED-on-revert guard. A security zone binds a
// LOGICAL interface ("ge-0-0-0.0"), but cfg.Interfaces.Interfaces is keyed by
// the BASE name ("ge-0-0-0"), so the old direct lookup silently dropped the
// VRRP row. The fixture also reports its configured VRRP group as non-master:
// both facts must be visible, and the row must be labelled `configured:`.
func TestShowChassisClusterStatus_VRRPLogicalZoneInterface(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 7 {
                        virtual-address 10.0.61.254/24;
                        priority 200;
                    }
                }
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0-0-0.0;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	manager := cluster.NewManager(0, 1)
	manager.UpdateConfig(&config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{{
			ID:             7,
			NodePriorities: map[int]int{0: 200, 1: 100},
		}},
	})
	manager.SetRGForwardingFunc(func(rgID int) (cluster.RGForwarding, bool) {
		return cluster.RGForwarding{}, rgID == 7
	})
	c := &CLI{store: store, cluster: manager}
	out := captureStdout(t, func() {
		if err := c.showChassisClusterStatus(); err != nil {
			t.Fatalf("showChassisClusterStatus: %v", err)
		}
	})

	for _, want := range []string{
		"vrrp-master=none",
		"VRRP on ge-0-0-0.0: configured: group 7, priority 200, VIP 10.0.61.254/24",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("configured non-master VRRP detail missing %q:\n%s", want, out)
		}
	}
}

// TestValidatePolicyZoneFilter is the #4908 (C175-HC-126) RED-on-revert guard
// for the local CLI: a from-zone/to-zone selector missing its zone value must
// be rejected rather than silently dropped (which returned a broader/one-sided
// inventory). Removing the validation call makes the malformed cases pass with
// nil errors.
func TestValidatePolicyZoneFilter(t *testing.T) {
	good := [][]string{
		{},
		{"from-zone", "trust"},
		{"from-zone", "trust", "to-zone", "untrust"},
		{"global"},
		{"detail", "from-zone", "trust", "to-zone", "untrust"},
	}
	for _, args := range good {
		if err := validatePolicyZoneFilter(args); err != nil {
			t.Errorf("validatePolicyZoneFilter(%v) = %v, want nil", args, err)
		}
	}
	bad := [][]string{
		{"from-zone"},
		{"to-zone"},
		{"from-zone", "trust", "to-zone"},
		{"from-zone", "to-zone", "untrust"},
	}
	for _, args := range bad {
		if err := validatePolicyZoneFilter(args); err == nil {
			t.Errorf("validatePolicyZoneFilter(%v) = nil, want an error (malformed selector)", args)
		}
	}
}
