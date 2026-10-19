package frr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestApplyFullPreferredRoutes is the #1827 PR-1b FRR render golden:
// ip-monitoring overlay entries become DISTANCE-1 statics in master +
// VRF tables, v4 + v6, emitted between the cluster-mode defaults and
// the per-VRF statics (emission-order contract step 7).
func TestApplyFullPreferredRoutes(t *testing.T) {
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
				VRFName: "vrf-ISP-B",
				StaticRoutes: []*config.StaticRoute{
					{Destination: "10.9.0.0/16", NextHops: []config.NextHopEntry{{Address: "10.9.0.1"}}},
				},
			},
		},
		ClusterMode: true,
		PreferredRoutes: []config.RouteOverlayEntry{
			{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
			{Destination: "::/0", NextHop: "2001:db8:80::1", Policy: "wan-failover"},
			{RoutingInstance: "ISP-B", Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"},
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
		"ip route 0.0.0.0/0 172.16.80.1 1\n",             // master v4 distance 1
		"ipv6 route ::/0 2001:db8:80::1 1\n",             // master v6 distance 1
		"ip route 0.0.0.0/0 172.16.80.1 1 vrf vrf-ISP-B", // per-VRF distance 1
	}
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in rendered config:\n%s", want, got)
		}
	}

	// Emission order: cluster blackhole (step 6) before the injected
	// route (step 7) before the per-VRF static (step 8).
	blackhole := strings.Index(got, "ip route 0.0.0.0/0 Null0 tag 2500 250")
	injected := strings.Index(got, "ip route 0.0.0.0/0 172.16.80.1 1\n")
	perVRF := strings.Index(got, "ip route 10.9.0.0/16 10.9.0.1 vrf vrf-ISP-B")
	if blackhole < 0 || injected < 0 || perVRF < 0 {
		t.Fatalf("expected sections missing: blackhole=%d injected=%d perVRF=%d\n%s",
			blackhole, injected, perVRF, got)
	}
	if !(blackhole < injected && injected < perVRF) {
		t.Errorf("emission order violated: blackhole=%d injected=%d perVRF=%d\n%s",
			blackhole, injected, perVRF, got)
	}
}

// TestApplyFullPreferredRoutesOnly: an overlay with no other routing
// content still renders (hasContent gate includes PreferredRoutes).
func TestApplyFullPreferredRoutesOnly(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	fc := &FullConfig{
		PreferredRoutes: []config.RouteOverlayEntry{
			{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "p"},
		},
	}
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("ApplyFull: %v", err)
	}
	data, _ := os.ReadFile(confPath)
	if !strings.Contains(string(data), "ip route 0.0.0.0/0 172.16.80.1 1") {
		t.Fatalf("overlay-only config not rendered:\n%s", data)
	}

	// Withdrawing the overlay (nil) clears the managed section.
	if err := m.ApplyFull(&FullConfig{}); err != nil {
		t.Fatalf("ApplyFull(empty): %v", err)
	}
	data, _ = os.ReadFile(confPath)
	if strings.Contains(string(data), "172.16.80.1") {
		t.Fatalf("withdrawn overlay still present:\n%s", data)
	}
}

// TestApplyFullPreferredRoutesLinkLocalScope is the #3759 render
// contract: an ip-monitoring overlay entry with a link-local next-hop
// renders as a DISTANCE-1 static WITH the interface scope supplied via
// IPv6NextHopInterfaces (the map the daemon now populates from the
// overlay). FRR rejects a scopeless `ipv6 route ::/0 fe80::1`; with the
// scope it installs the failover route. A global-address overlay
// next-hop with no map entry still renders (bare, which FRR accepts).
func TestApplyFullPreferredRoutesLinkLocalScope(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "frr.conf")
	os.WriteFile(confPath, []byte("log syslog informational\n"), 0644)

	m := &Manager{frrConf: confPath, exec: &fakeExecutor{}}
	fc := &FullConfig{
		IPv6NextHopInterfaces: map[string]map[string]string{"": {"fe80::1": "ge-0-0-3.50"}},
		PreferredRoutes: []config.RouteOverlayEntry{
			{Destination: "::/0", NextHop: "fe80::1", Policy: "wan-failover"},
			{Destination: "2001:db8::/48", NextHop: "2001:db8:80::1", Policy: "wan-failover"},
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

	if !strings.Contains(got, "ipv6 route ::/0 fe80::1 ge-0-0-3.50 1\n") {
		t.Errorf("link-local overlay route missing interface scope in:\n%s", got)
	}
	// Global next-hop with no map entry renders bare (FRR-valid).
	if !strings.Contains(got, "ipv6 route 2001:db8::/48 2001:db8:80::1 1\n") {
		t.Errorf("global overlay route missing/altered in:\n%s", got)
	}
}
