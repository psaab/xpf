package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
)

func TestIPv6StaticNextHopSecureTunnelUnitRendersAuthoredNetdev12514(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st0": {Name: "st0", Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"2001:db8:12::1/64"}},
		}},
	}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn0": {Name: "vpn0", BindInterface: "st0.0"},
	}
	mkStatic := func() *config.StaticRoute {
		return &config.StaticRoute{
			Destination: "2001:db8:99::/64",
			NextHops:    []config.NextHopEntry{{Address: "2001:db8:12::2"}},
		}
	}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{mkStatic()}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "blue", InstanceType: "vrf", TableID: 100, Interfaces: []string{"st0.0"},
			Inet6StaticRoutes: []*config.StaticRoute{mkStatic()}},
	}

	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)
	if got := fc.IPv6NextHopInterfaces["vrf-blue"]["2001:db8:12::2"]; got != "st0.0" {
		t.Fatalf("inferred next-hop interface = %q, want authored secure-tunnel netdev st0.0", got)
	}
	if got := fc.DeclaredNetdevs["st0.0"]; got != "st0.0" {
		t.Fatalf("declared secure-tunnel netdev = %q, want st0.0", got)
	}

	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0640); err != nil {
		t.Fatal(err)
	}
	manager := frr.NewForTest(confPath, &frr.RecordingExecutor{})
	defer manager.Stop()
	if err := manager.ApplyFull(fc); err != nil {
		t.Fatalf("ApplyFull: %v", err)
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "ipv6 route 2001:db8:99::/64 2001:db8:12::2 st0.0 vrf vrf-blue\n"
	if !strings.Contains(string(data), want) {
		t.Fatalf("rendered FRR config missing authored-device route %q:\n%s", want, data)
	}
	if strings.Contains(string(data), "2001:db8:12::2 st0 vrf vrf-blue") {
		t.Fatalf("rendered FRR route still names collapsed st0:\n%s", data)
	}
}

func TestIPv6StaticNextHopInferenceUnitNameFallbackControls12514(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"2001:db8:1::1/64"}},
		}},
		"st0": {Name: "st0", Units: map[int]*config.InterfaceUnit{
			0: {Addresses: []string{"2001:db8:2::1/64"}},
		}},
	}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{
		{Destination: "2001:db8:10::/64", NextHops: []config.NextHopEntry{{Address: "2001:db8:1::2"}}},
		{Destination: "2001:db8:20::/64", NextHops: []config.NextHopEntry{{Address: "2001:db8:2::2"}}},
	}
	got := inferIPv6StaticNextHopInterfaces(cfg, nil)[""]
	if got["2001:db8:1::2"] != "ge-0-0-1" {
		t.Errorf("ordinary unit-zero next-hop interface = %q, want collapsed ge-0-0-1", got["2001:db8:1::2"])
	}
	if got["2001:db8:2::2"] != "st0" {
		t.Errorf("unbound secure-tunnel unit-zero next-hop interface = %q, want st0", got["2001:db8:2::2"])
	}
}
