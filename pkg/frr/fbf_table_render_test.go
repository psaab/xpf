package frr

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #1827 PR-2 — forwarding-instance table ownership and real FRR validation.
//
// Before PR-2, forwarding-instance statics rendered with vrfName == ""
// and therefore landed in the DEFAULT kernel table, while the userspace
// dataplane filed the same routes under `<ri>.inet.0` and the FBF/PBR
// `ip rule`s pointed at the instance's TableID (which stayed empty):
// kernel vs dataplane divergence, and main-table pollution. PR-2
// renders them with a trailing `table <id>`.

// TestRenderedRoutingConfigAcceptedByFRR11417 uses FRR's integrated command
// parser, not a second copy of the renderer's expected strings. Dry-run mode
// neither connects to routing daemons nor changes the host routing tables.
func TestRenderedRoutingConfigAcceptedByFRR11417(t *testing.T) {
	vtysh := os.Getenv("FRR_VTYSH_BINARY")
	if vtysh == "" {
		var err error
		vtysh, err = exec.LookPath("vtysh")
		if errors.Is(err, exec.ErrNotFound) {
			// LookPath also returns ErrNotFound when every candidate is
			// unusable. Only a genuinely absent installation may skip.
			for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
				candidate := filepath.Join(dir, "vtysh")
				_, statErr := os.Lstat(candidate)
				if statErr == nil {
					t.Fatalf("FRR vtysh exists on PATH but is unusable: %s", candidate)
				}
				if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("inspect FRR vtysh candidate %s: %v", candidate, statErr)
				}
			}
			t.Skip("FRR vtysh is absent from PATH; real routing-config validation cannot run")
		}
		if err != nil {
			t.Fatalf("resolve FRR vtysh executable: %v", err)
		}
	}
	tests := []struct {
		name    string
		config  FullConfig
		keyword string
	}{
		{
			name: "forwarding IPv4 IPv6 and preferred route",
			config: FullConfig{
				Instances: []InstanceConfig{{
					Name: "ISP-B", TableID: 100,
					StaticRoutes: []*config.StaticRoute{
						{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.80.1"}}, Preference: 5},
						{Destination: "10.66.0.0/16", Discard: true},
					},
					Inet6StaticRoutes: []*config.StaticRoute{
						{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:db8:80::1"}}},
					},
				}},
				PreferredRoutes: []config.RouteOverlayEntry{
					{RoutingInstance: "ISP-B", Destination: "0.0.0.0/0", NextHop: "172.16.50.1", Policy: "wan-failover"},
				},
			},
			keyword: "ip route ",
		},
		{
			name: "virtual router IPv4 and IPv6",
			config: FullConfig{
				Instances: []InstanceConfig{{
					Name: "BLUE", VRFName: "vrf-BLUE", TableID: 101,
					StaticRoutes: []*config.StaticRoute{
						{Destination: "10.9.0.0/16", NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}}},
					},
					Inet6StaticRoutes: []*config.StaticRoute{
						{Destination: "2001:db8:9::/48", NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}}},
					},
				}},
			},
			keyword: "ip route ",
		},
		{
			name: "BGP IPv4 and familyless IPv6 peers",
			config: FullConfig{BGP: &config.BGPConfig{
				LocalAS: 65000,
				Neighbors: []*config.BGPNeighbor{
					{Address: "192.0.2.1", PeerAS: 65001},
					{Address: "2001:db8::1", PeerAS: 65002},
				},
			}},
			keyword: "router bgp ",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rendered := New().buildManagedSection(&tc.config)
			if output, err := validateRenderedRouting11417(t, vtysh, rendered); err != nil {
				t.Fatalf("FRR validation failed: %v\n%s\nconfig:\n%s", err, output, rendered)
			}
			// Appending an invalid top-level line verifies vtysh parsed the
			// whole config, not just a prefix ending in an early exit.
			const sentinel = "xpf-end-of-config-sentinel"
			sentinelOutput, sentinelErr := validateRenderedRouting11417(t, vtysh, rendered+sentinel+"\n")
			if sentinelErr == nil {
				t.Fatalf("FRR accepted end-of-config sentinel; validation may have stopped at an early exit:\n%s", rendered)
			}
			if !bytes.Contains(sentinelOutput, []byte(sentinel)) {
				t.Fatalf("FRR sentinel failure did not identify the end-of-config line: %v\n%s", sentinelErr, sentinelOutput)
			}
			mutated := strings.Replace(rendered, tc.keyword, "xpf-invalid-routing-keyword ", 1)
			if mutated == rendered {
				t.Fatalf("fixture did not render the routing command needed for its invalid-keyword control")
			}
			output, err := validateRenderedRouting11417(t, vtysh, mutated)
			if err == nil {
				t.Fatalf("FRR accepted an invalid routing keyword; validation cannot detect a malformed renderer:\n%s", mutated)
			}
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() <= 0 {
				t.Fatalf("invalid-keyword control did not return a normal parser error: %v\n%s", err, output)
			}
			if !bytes.Contains(output, []byte("xpf-invalid-routing-keyword")) {
				t.Fatalf("FRR failure did not identify the invalid command: %v\n%s", err, output)
			}
			t.Logf("real FRR accepted rendered config and rejected its invalid-keyword mutation")
		})
	}
}

func validateRenderedRouting11417(t *testing.T, vtysh, rendered string) ([]byte, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, vtysh, "-C", "-f", path,
		"--config_dir", dir, "--vty_socket", dir).CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("FRR validation did not finish: %v\n%s", ctx.Err(), output)
	}
	return output, err
}

// TestApplyFullForwardingInstanceTable: ApplyFull renders forwarding
// instances (VRFName == "", TableID > 0) into their kernel table and
// keeps virtual-router instances on `vrf <name>`.
func TestApplyFullForwardingInstanceTable(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{
			{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
		},
		Instances: []InstanceConfig{
			{
				Name:    "ISP-B",
				TableID: 100, // forwarding: no VRF device
				StaticRoutes: []*config.StaticRoute{
					{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.80.1"}}},
					{Destination: "10.66.0.0/16", Discard: true},
				},
				Inet6StaticRoutes: []*config.StaticRoute{
					{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:db8:80::1"}}},
				},
			},
			{
				Name:    "BLUE",
				VRFName: "vrf-BLUE",
				TableID: 101, // an explicit VRF takes precedence over a table ID
				StaticRoutes: []*config.StaticRoute{
					{Destination: "10.9.0.0/16", NextHops: []config.NextHopEntry{{Address: "10.9.0.1"}}},
				},
			},
		},
	}
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("ApplyFull: %v", err)
	}

	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	wants := []string{
		"ip route 0.0.0.0/0 172.16.50.1\n",             // master untouched
		"ip route 0.0.0.0/0 172.16.80.1 table 100\n",   // forwarding v4
		"ip route 10.66.0.0/16 Null0 table 100\n",      // forwarding discard stays out of main
		"ipv6 route ::/0 2001:db8:80::1 table 100\n",   // forwarding v6
		"ip route 10.9.0.0/16 10.9.0.1 vrf vrf-BLUE\n", // VRF takes precedence
	}
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in rendered config:\n%s", want, got)
		}
	}
	// The forwarding-instance default must NOT also appear as a
	// default-table route (the pre-PR-2 divergence/pollution).
	if strings.Contains(got, "ip route 0.0.0.0/0 172.16.80.1\n") {
		t.Errorf("forwarding-instance static leaked into the default table:\n%s", got)
	}
}

// TestApplyFullPreferredRouteForwardingInstance: an ip-monitoring
// overlay entry targeting a forwarding instance renders as a
// distance-1 static in the instance's kernel table (PR-2 lifts the
// PR-1b commit-rejection that made this unreachable).
func TestApplyFullPreferredRouteForwardingInstance(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	fc := &FullConfig{
		Instances: []InstanceConfig{
			{
				Name:    "ISP-B",
				TableID: 100,
				StaticRoutes: []*config.StaticRoute{
					{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.80.1"}}},
				},
			},
		},
		PreferredRoutes: []config.RouteOverlayEntry{
			{RoutingInstance: "ISP-B", Destination: "0.0.0.0/0", NextHop: "172.16.80.254", Policy: "wan-failover"},
		},
	}
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("ApplyFull: %v", err)
	}
	data, _ := os.ReadFile(confPath)
	got := string(data)
	if !strings.Contains(got, "ip route 0.0.0.0/0 172.16.80.254 1 table 100\n") {
		t.Errorf("forwarding-instance preferred route not rendered into table 100:\n%s", got)
	}
	if strings.Contains(got, "vrf vrf-ISP-B") {
		t.Errorf("forwarding-instance preferred route rendered into a nonexistent VRF:\n%s", got)
	}
}
