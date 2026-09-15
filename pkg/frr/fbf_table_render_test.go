package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1827 PR-2 — `instance-type forwarding` divergence-fix goldens.
//
// Before PR-2, forwarding-instance statics rendered with vrfName == ""
// and therefore landed in the DEFAULT kernel table, while the userspace
// dataplane filed the same routes under `<ri>.inet.0` and the FBF/PBR
// `ip rule`s pointed at the instance's TableID (which stayed empty):
// kernel vs dataplane divergence, and main-table pollution. PR-2
// renders them with a trailing `table <id>`.

// TestGenerateStaticRouteInTable covers the new table-suffix emission.
func TestGenerateStaticRouteInTable(t *testing.T) {
	m := New()

	// Forwarding instance: table suffix, no vrf.
	sr := &config.StaticRoute{
		Destination: "0.0.0.0/0",
		NextHops:    []config.NextHopEntry{{Address: "172.16.80.1"}},
	}
	got := m.generateStaticRouteInTable(sr, "", 100, nil, nil, nil)
	if got != "ip route 0.0.0.0/0 172.16.80.1 table 100\n" {
		t.Errorf("v4 table route = %q", got)
	}

	// With preference (distance precedes table — both live in FRR's
	// order-free trailing keyword set).
	sr.Preference = 5
	got = m.generateStaticRouteInTable(sr, "", 100, nil, nil, nil)
	if got != "ip route 0.0.0.0/0 172.16.80.1 5 table 100\n" {
		t.Errorf("v4 table route with distance = %q", got)
	}

	// IPv6.
	sr6 := &config.StaticRoute{
		Destination: "::/0",
		NextHops:    []config.NextHopEntry{{Address: "2001:db8:80::1"}},
	}
	got = m.generateStaticRouteInTable(sr6, "", 101, nil, nil, nil)
	if got != "ipv6 route ::/0 2001:db8:80::1 table 101\n" {
		t.Errorf("v6 table route = %q", got)
	}

	// vrfName wins over tableID (virtual-router instances never emit
	// `table`).
	got = m.generateStaticRouteInTable(sr6, "vrf-BLUE", 101, nil, nil, nil)
	if got != "ipv6 route ::/0 2001:db8:80::1 vrf vrf-BLUE\n" {
		t.Errorf("vrf route = %q", got)
	}

	// tableID 0 == legacy default-table behavior.
	got = m.generateStaticRouteInTable(sr6, "", 0, nil, nil, nil)
	if got != "ipv6 route ::/0 2001:db8:80::1\n" {
		t.Errorf("default-table route = %q", got)
	}

	// Discard routes carry the table too.
	discard := &config.StaticRoute{Destination: "10.66.0.0/16", Discard: true}
	got = m.generateStaticRouteInTable(discard, "", 100, nil, nil, nil)
	if got != "ip route 10.66.0.0/16 Null0 table 100\n" {
		t.Errorf("discard table route = %q", got)
	}
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
				},
				Inet6StaticRoutes: []*config.StaticRoute{
					{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:db8:80::1"}}},
				},
			},
			{
				Name:    "BLUE",
				VRFName: "vrf-BLUE",
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
		"ip route 0.0.0.0/0 172.16.50.1\n",           // master untouched
		"ip route 0.0.0.0/0 172.16.80.1 table 100\n", // forwarding v4
		"ipv6 route ::/0 2001:db8:80::1 table 100\n", // forwarding v6
		"ip route 10.9.0.0/16 10.9.0.1 vrf vrf-BLUE", // virtual-router unchanged
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
