package routing

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestTunnelVRFStanzaBindsValidTargetNotManagement12520(t *testing.T) {
	ops := newFakeLinkOps()
	seedVRF(ops, "blue", 410)
	tm, _ := newReconcileManager(ops)
	tc := anchorTC("gr-0-0-0")
	tc.RoutingInstance = "blue"
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := ops.links[tc.Name].Attrs().MasterIndex; got != 410 {
		t.Fatalf("tunnel master index = %d, want valid target vrf-blue index 410", got)
	}
	if got := tm.appliedRI[tc.Name]; got != "blue" {
		t.Fatalf("recorded tunnel VRF claim = %q, want blue", got)
	}
}

func tunnelRITargetTreeForKernel12520(t *testing.T, target, instanceType string) *config.ConfigTree {
	lines := []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination " + target,
		"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30",
	}
	if instanceType != "" {
		lines = append(lines, "set routing-instances "+target+" instance-type "+instanceType)
	}
	return tunnelRITargetTreeFromLines12520(t, lines)
}

func tunnelRITargetTreeFromLines12520(t *testing.T, lines []string) *config.ConfigTree {
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

func TestRejectedAndTolerantTunnelRITargetsRemoveTunnel12520(t *testing.T) {
	cases := []struct {
		name         string
		target       string
		instanceType string
	}{
		{name: "undefined", target: "missing"},
		{name: "forwarding", target: "fwd", instanceType: "forwarding"},
		{name: "reserved management", target: "mgmt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := config.CompileConfig(tunnelRITargetTreeForKernel12520(t, tc.target, tc.instanceType)); err == nil || !strings.Contains(err.Error(), "#12520") {
				t.Errorf("strict compile error = %v, want #12520 rejection", err)
			}
			cfg, err := config.CompileConfigLenient(tunnelRITargetTreeForKernel12520(t, tc.target, tc.instanceType))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			warnings := 0
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "#12520") && strings.Contains(warning, tc.target) {
					warnings++
				}
			}
			if warnings != 1 {
				t.Errorf("got %d target warnings, want one for %q: %v", warnings, tc.target, cfg.Warnings)
			}
			if tunnel := cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel; tunnel != nil {
				t.Fatalf("tolerant tunnel survived bad-target removal: %+v, want removed (#14390)", tunnel)
			}
		})
	}
}

func TestTolerantMultiTargetQuarantineRemovesTunnels12520(t *testing.T) {
	tree := tunnelRITargetTreeFromLines12520(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination missing",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.3",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.4",
		"set interfaces gr-0/0/1 tunnel routing-instance destination mgmt",
		"set interfaces gr-0/0/1 unit 0 family inet address 10.0.1.1/30",
	})
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	var warnings []string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12520") {
			warnings = append(warnings, warning)
		}
	}
	if len(warnings) != 2 {
		t.Errorf("got %d #12520 warnings, want one per unsupported target: %v",
			len(warnings), warnings)
	}
	for _, ifName := range []string{"gr-0/0/0", "gr-0/0/1"} {
		if tc := cfg.Interfaces.Interfaces[ifName].Tunnel; tc != nil {
			t.Errorf("%s tunnel survived bad-target removal: %+v, want removed (#14390)", ifName, tc)
		}
	}
	// No tunnel reaches the kernel manager: nothing is created or bound.
	ops := newFakeLinkOps()
	seedVRF(ops, "missing", 500)
	seedVRF(ops, "mgmt", 501)
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply(nil); err != nil {
		t.Fatalf("Apply with no tunnels: %v", err)
	}
	for name := range ops.links {
		if name == "gr-0-0-0" || name == "gr-0-0-1" {
			t.Errorf("kernel tunnel link %q created for a removed tunnel", name)
		}
	}
}
