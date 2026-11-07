package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18605: networkd needs KeepMaster=yes on every row the daemon binds to a
// routing-instance VRF. This drives compileZones through its model builders and
// post-build pass; pkg/networkd's KeepMaster18597 cells pin the rendered line.
func TestRoutingInstanceMembersKeepMaster18605(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0":     {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", Interfaces: []string{"ge-0/0/0", "fxp0"},
	}}
	result := compileNetworkdRows18605(t, cfg, "fxp0", "ge-0-0-0", "ge-0-0-1")
	assertVRFName18605(t, result, "ge-0-0-0", "vrf-blue")
	assertVRFName18605(t, result, "ge-0-0-1", "")
	assertVRFName18605(t, result, "fxp0", config.ManagementVRFDeviceName)
}

func TestSecureTunnelUnitMemberKeepsMaster18605(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn0": {Name: "vpn0", BindInterface: "st0.1"},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st0": {Name: "st0", Units: map[int]*config.InterfaceUnit{1: {Number: 1}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", Interfaces: []string{"st0.1"},
	}}
	result := compileNetworkdRows18605(t, cfg, "st0.1")
	assertVRFName18605(t, result, "st0.1", "vrf-blue")
}

func TestRemovedRoutingInstanceMemberDropsKeepMaster18605(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", Interfaces: []string{"ge-0/0/0"},
	}}
	first := compileNetworkdRows18605(t, cfg, "ge-0-0-0")
	assertVRFName18605(t, first, "ge-0-0-0", "vrf-blue")

	cfg.RoutingInstances[0].Interfaces = nil
	removed := compileNetworkdRows18605(t, cfg, "ge-0-0-0")
	assertVRFName18605(t, removed, "ge-0-0-0", "")
}

func TestRoutingInstanceKeepMasterExclusions18605(t *testing.T) {
	t.Run("dual claim", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}
		cfg.RoutingInstances = []*config.RoutingInstanceConfig{
			{Name: "blue", Interfaces: []string{"ge-0/0/2"}},
			{Name: "red", Interfaces: []string{"ge-0/0/2"}},
		}
		result := compileNetworkdRows18605(t, cfg, "ge-0-0-2")
		assertVRFName18605(t, result, "ge-0-0-2", "")
	})

	t.Run("forwarding and reserved", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/4": {Name: "ge-0/0/4", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
			"ge-0/0/5": {Name: "ge-0/0/5", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}
		cfg.RoutingInstances = []*config.RoutingInstanceConfig{
			{Name: "fwd", InstanceType: "forwarding", Interfaces: []string{"ge-0/0/4"}},
			{Name: config.ManagementVRFInstanceName, Interfaces: []string{"ge-0/0/5"}},
		}
		result := compileNetworkdRows18605(t, cfg, "ge-0-0-4", "ge-0-0-5")
		assertVRFName18605(t, result, "ge-0-0-4", "")
		assertVRFName18605(t, result, "ge-0-0-5", "")
	})

	t.Run("retained quarantined conflict", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}
		cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue"}}
		primary := config.RoutingInstanceMemberPrimaryClaim{
			Instance: "blue", InterfaceKey: "ge-0/0/3", LinuxName: "ge-0-0-3",
		}
		cfg.QuarantinedRIMemberPrimaryClaims = []config.RoutingInstanceMemberPrimaryClaim{primary}
		cfg.QuarantinedRIMemberDeviceConflicts = []config.RoutingInstanceMemberDeviceConflict{{
			LinuxName: "ge-0-0-3",
			Claims:    []config.RoutingInstanceMemberClaim{{Instance: "blue", Member: "ge-0/0/3"}},
		}}
		result := compileNetworkdRows18605(t, cfg, "ge-0-0-3")
		assertVRFName18605(t, result, "ge-0-0-3", "")
		cfg.QuarantinedRIMemberDeviceConflicts = nil
		withoutConflict := compileNetworkdRows18605(t, cfg, "ge-0-0-3")
		assertVRFName18605(t, withoutConflict, "ge-0-0-3", "vrf-blue")
	})

	t.Run("tunnel stanza owner", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"gr-0/0/0": {
				Name:   "gr-0/0/0",
				Tunnel: &config.TunnelConfig{Name: "gr-0-0-0", RoutingInstance: "blue"},
				Units:  map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
		}
		cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
			Name: "blue", Interfaces: []string{"gr-0/0/0"},
		}}
		result := compileNetworkdRows18605(t, cfg, "gr-0-0-0")
		assertVRFName18605(t, result, "gr-0-0-0", "")
	})
}

func compileNetworkdRows18605(t *testing.T, cfg *config.Config, names ...string) *CompileResult {
	t.Helper()
	oldLister := interfaceLister
	interfaceLister = func() ([]net.Interface, error) { return nil, nil }
	t.Cleanup(func() { interfaceLister = oldLister })

	result := newValidationResult()
	for index, name := range names {
		result.ifCache[name] = &net.Interface{
			Index: index + 1, Name: name,
			HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, byte(index + 1)},
		}
	}
	if err := compileZones(convergenceTestDP{}, cfg, result); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	return result
}

func assertVRFName18605(t *testing.T, result *CompileResult, name, want string) {
	t.Helper()
	for _, row := range result.ManagedInterfaces {
		if row.Name == name {
			if row.VRFName != want {
				t.Fatalf("networkd row %s VRFName = %q, want %q: %+v", name, row.VRFName, want, row)
			}
			return
		}
	}
	t.Fatalf("no networkd model for %s: %+v", name, result.ManagedInterfaces)
}
