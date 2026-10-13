package userspace

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func tunnelTransportTable12520(t *testing.T, cfg *config.Config, ifName string) string {
	t.Helper()
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{{
		Name: ifName + ".0", LinuxName: config.LinuxIfName(ifName), Ifindex: 362,
	}})
	if len(endpoints) != 1 || endpoints[0].Interface != ifName+".0" {
		t.Fatalf("tunnel snapshots for %s = %+v, want exactly one endpoint",
			ifName, endpoints)
	}
	return endpoints[0].TransportTable
}

func TestTunnelRITargetSnapshotMatchesValidVRF12520(t *testing.T) {
	cfg, err := config.CompileConfig(treeFromSet6722(t, []string{
		"set system dataplane-type userspace",
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
		"set routing-instances blue instance-type virtual-router",
	}))
	if err != nil {
		t.Fatalf("strict compile of valid VRF target: %v", err)
	}

	previous := buildLinkSnapshot
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return 362, 1500, "", nil
	}
	t.Cleanup(func() { buildLinkSnapshot = previous })

	row := snapshotByName9132(t, BuildInterfaceSnapshots(cfg), "gr-0/0/0.0")
	wantDomain := uint32(config.StableRoutingInstanceTableID("blue"))
	if row.RoutingInstance != "blue" || row.RoutingDomain != wantDomain {
		t.Fatalf("valid tunnel snapshot owner = (%q, %d), want (blue, %d)",
			row.RoutingInstance, row.RoutingDomain, wantDomain)
	}
	if table := tunnelTransportTable12520(t, cfg, "gr-0/0/0"); table != "blue.inet.0" {
		t.Errorf("valid transport table = %q, want blue.inet.0", table)
	}

}

func TestRejectedAndTolerantTunnelRITargetsUseDefaultSnapshot12520(t *testing.T) {
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
			lines := []string{
				"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/0 tunnel routing-instance destination " + tc.target,
				"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30",
			}
			if tc.instanceType != "" {
				lines = append(lines, "set routing-instances "+tc.target+" instance-type "+tc.instanceType)
			}
			tree := treeFromSet6722(t, lines)
			if _, err := config.CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#12520") {
				t.Errorf("strict compile error = %v, want #12520 rejection", err)
			}
			cfg, err := config.CompileConfigLenient(treeFromSet6722(t, lines))
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
			if got := cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel.RoutingInstance; got != "" {
				t.Errorf("tolerant target = %q, want quarantine to default", got)
			}
			row := snapshotByName9132(t, BuildInterfaceSnapshots(cfg), "gr-0/0/0.0")
			if row.RoutingInstance != "" || row.RoutingDomain != 0 {
				t.Fatalf("quarantined snapshot owner = (%q, %d), want default domain (empty, 0)",
					row.RoutingInstance, row.RoutingDomain)
			}
			if table := tunnelTransportTable12520(t, cfg, "gr-0/0/0"); table != "inet.0" {
				t.Errorf("quarantined transport table = %q, want inet.0", table)
			}
		})
	}
}

func TestTolerantMultiTargetQuarantineUsesDefaultSnapshots12520(t *testing.T) {
	cfg, err := config.CompileConfigLenient(treeFromSet6722(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination missing",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.3",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.4",
		"set interfaces gr-0/0/1 tunnel routing-instance destination mgmt",
		"set interfaces gr-0/0/1 unit 0 family inet address 10.0.1.1/30",
	}))
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
	rows := BuildInterfaceSnapshots(cfg)
	for _, tc := range []struct {
		ifName string
		target string
	}{
		{ifName: "gr-0/0/0", target: "missing"},
		{ifName: "gr-0/0/1", target: "mgmt"},
	} {
		ifName, target := tc.ifName, tc.target
		if got := cfg.Interfaces.Interfaces[ifName].Tunnel.RoutingInstance; got != "" {
			t.Errorf("%s target = %q, want quarantined default", ifName, got)
		}
		found := false
		for _, warning := range warnings {
			if strings.Contains(warning, ifName) && strings.Contains(warning, target) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("warnings omit %s target %q: %v", ifName, target, warnings)
		}
		row := snapshotByName9132(t, rows, ifName+".0")
		if row.RoutingInstance != "" || row.RoutingDomain != 0 {
			t.Errorf("%s snapshot owner = (%q, %d), want default domain (empty, 0)",
				ifName, row.RoutingInstance, row.RoutingDomain)
		}
		if table := tunnelTransportTable12520(t, cfg, ifName); table != "inet.0" {
			t.Errorf("%s transport table = %q, want inet.0", ifName, table)
		}
	}
}

// TestQuarantinedGRECollisionKeepsValidSnapshot12520: gr-0/0/0 (undefined
// target) and gr-0/0/1 (no target) share one outer tuple. Without the
// post-clear identity check, the builder kept the first-sorting, quarantined
// gr-0/0/0.0 and dropped the valid gr-0/0/1.0 (#10654 ERROR).
func TestQuarantinedGRECollisionKeepsValidSnapshot12520(t *testing.T) {
	cfg, err := config.CompileConfigLenient(treeFromSet6722(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination missing",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/1 unit 0 family inet address 10.0.1.1/30",
	}))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel != nil {
		t.Errorf("quarantined GRE collider remains active")
	}

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{Name: "gr-0/0/0.0", LinuxName: "gr-0-0-0", Ifindex: 362},
		{Name: "gr-0/0/1.0", LinuxName: "gr-0-0-1", Ifindex: 363},
	})
	if len(endpoints) != 1 || endpoints[0].Interface != "gr-0/0/1.0" {
		t.Fatalf("snapshot endpoints = %+v, want only the valid gr-0/0/1.0; logs: %s",
			endpoints, logs.String())
	}
	if endpoints[0].TransportTable != "inet.0" {
		t.Fatalf("valid endpoint transport table = %q, want inet.0",
			endpoints[0].TransportTable)
	}
	if strings.Contains(logs.String(), "#10654") {
		t.Fatalf("snapshot builder still resolved a duplicate GRE outer: %s", logs.String())
	}
	var targetWarning, duplicateWarning bool
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12520") && strings.Contains(warning, "missing") {
			targetWarning = true
		}
		if strings.Contains(warning, "is skipped on tolerant load") &&
			strings.Contains(warning, `"gr-0/0/0.0"`) &&
			strings.Contains(warning, `"gr-0/0/1.0"`) {
			duplicateWarning = true
		}
	}
	if !targetWarning || !duplicateWarning {
		t.Fatalf("warnings omit target/collision disposition: %v", cfg.Warnings)
	}
}
