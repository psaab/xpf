package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestTunnelKernelBindMatchesUserspaceInstance12082(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{
			name: "stanza-only",
			lines: []string{
				"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
			},
		},
		{
			name: "list-only",
			lines: []string{
				"set routing-instances blue interface gr-0/0/0",
			},
		},
		{
			name: "list-only-unit",
			lines: []string{
				"set routing-instances blue interface gr-0/0/0.0",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set system dataplane-type userspace",
				"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
				"set routing-instances blue instance-type virtual-router",
			}
			lines = append(lines, tc.lines...)
			cfg, err := config.CompileConfig(tree12082(t, lines))
			if err != nil {
				t.Fatalf("strict compile: %v", err)
			}

			// The tunnel manager binds TunnelConfig.RoutingInstance directly;
			// list-only membership is bound by apply's step-0a pass and copied
			// onto the tunnel as RIListMember for its claim/veto logic.
			applied := collectAppliedTunnels(cfg)
			if len(applied) != 1 {
				t.Fatalf("applied tunnels = %d, want 1: %+v", len(applied), applied)
			}
			kernelTarget := applied[0].RoutingInstance
			if kernelTarget == "" {
				kernelTarget = applied[0].RIListMember
			}
			if kernelTarget != "blue" {
				t.Fatalf("kernel bind target = %q, want blue (tunnel=%+v)", kernelTarget, applied[0])
			}

			snaps := dpuserspace.BuildInterfaceSnapshots(cfg)
			matched := 0
			for _, snap := range snaps {
				if snap.LinuxName != applied[0].Name {
					continue
				}
				matched++
				if snap.RoutingInstance != kernelTarget {
					t.Errorf("kernel bind target %q != InterfaceSnapshot %q (row=%q, linux=%q)",
						kernelTarget, snap.RoutingInstance, snap.Name, snap.LinuxName)
				}
			}
			if matched == 0 {
				t.Fatalf("no interface snapshot row for tunnel device %q: %+v", applied[0].Name, snaps)
			}
		})
	}
}

func tree12082(t *testing.T, lines []string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}
