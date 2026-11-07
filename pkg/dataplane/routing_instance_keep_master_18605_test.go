package dataplane

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
)

// #18605: networkd needs KeepMaster=yes on every row the daemon binds to a
// routing-instance VRF. These tests drive compileZones through its model
// builders and assert the rendered .network files produced by networkd.Apply.
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

func TestTunnelStanzaRoutingInstanceKeepsMaster18605(t *testing.T) {
	t.Run("stanza only", func(t *testing.T) {
		cfg := tunnelStanzaConfig18605("blue", &config.RoutingInstanceConfig{Name: "blue"})
		result := compileNetworkdRows18605(t, cfg, "gr-0-0-0")
		assertVRFName18605(t, result, "gr-0-0-0", "vrf-blue")
	})

	t.Run("unit-level stanza only", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"gr-0/0/0": {
				Name: "gr-0/0/0",
				Units: map[int]*config.InterfaceUnit{
					0: {
						Number: 0,
						Tunnel: &config.TunnelConfig{
							Name: "gr-0-0-0", Source: "192.0.2.1",
							Destination: "192.0.2.2", RoutingInstance: "blue",
						},
					},
				},
			},
		}
		cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue"}}
		result := compileNetworkdRows18605(t, cfg, "gr-0-0-0")
		assertVRFName18605(t, result, "gr-0-0-0", "vrf-blue")
	})

	t.Run("stanza and same RI list", func(t *testing.T) {
		cfg := tunnelStanzaConfig18605("blue", &config.RoutingInstanceConfig{
			Name: "blue", Interfaces: []string{"gr-0/0/0.0"},
		})
		result := compileNetworkdRows18605(t, cfg, "gr-0-0-0")
		assertVRFName18605(t, result, "gr-0-0-0", "vrf-blue")
	})

	t.Run("unit stanza overrides interface stanza on same device", func(t *testing.T) {
		cfg := tunnelStanzaConfig18605("blue",
			&config.RoutingInstanceConfig{Name: "blue"},
			&config.RoutingInstanceConfig{Name: "red"},
		)
		cfg.Interfaces.Interfaces["gr-0/0/0"].Units[0].Tunnel = &config.TunnelConfig{
			Name: "gr-0-0-0", RoutingInstance: "red",
		}
		result := compileNetworkdRows18605(t, cfg, "gr-0-0-0")
		assertVRFName18605(t, result, "gr-0-0-0", "vrf-red")
	})

	t.Run("different unit stanzas on same device conflict", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"gr-0/0/0": {
				Name: "gr-0/0/0",
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Tunnel: &config.TunnelConfig{
						Name: "gr-0-0-0", RoutingInstance: "blue",
					}},
					1: {Number: 1, Tunnel: &config.TunnelConfig{
						Name: "gr-0-0-0", RoutingInstance: "red",
					}},
				},
			},
		}
		cfg.RoutingInstances = []*config.RoutingInstanceConfig{
			{Name: "blue"},
			{Name: "red"},
		}
		result := compileNetworkdRows18605(t, cfg, "gr-0-0-0")
		assertVRFName18605(t, result, "gr-0-0-0", "")
	})

	t.Run("stanza removal", func(t *testing.T) {
		cfg := tunnelStanzaConfig18605("blue", &config.RoutingInstanceConfig{Name: "blue"})
		before := compileNetworkdRows18605(t, cfg, "gr-0-0-0")
		assertVRFName18605(t, before, "gr-0-0-0", "vrf-blue")

		cfg.Interfaces.Interfaces["gr-0/0/0"].Tunnel.RoutingInstance = ""
		after := compileNetworkdRows18605(t, cfg, "gr-0-0-0")
		assertVRFName18605(t, after, "gr-0-0-0", "")
	})
}

func TestBackslashRoutingInstanceNameRendersKeepMaster18605(t *testing.T) {
	const riName = "trailing\\"
	treeText := "routing-instances {\n    " + strconv.Quote(riName) +
		" { instance-type virtual-router; }\n}\n"
	tree, parseErrs := config.NewParser(treeText).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse RI fixture: %v", parseErrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile routing-instance name accepted by the kernel-name gate: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != riName {
		t.Fatalf("compiled routing instances = %+v, want one named %q", cfg.RoutingInstances, riName)
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/6": {Name: "ge-0/0/6", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.RoutingInstances[0].Interfaces = []string{"ge-0/0/6"}
	result := compileNetworkdRows18605(t, cfg, "ge-0-0-6")
	assertVRFName18605(t, result, "ge-0-0-6", "vrf-"+riName)
}

func tunnelStanzaConfig18605(
	stanzaRI string, routingInstances ...*config.RoutingInstanceConfig,
) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Tunnel: &config.TunnelConfig{
				Name: "gr-0-0-0", Source: "192.0.2.1",
				Destination: "192.0.2.2", RoutingInstance: stanzaRI,
			},
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
	}
	cfg.RoutingInstances = routingInstances
	return cfg
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

	t.Run("tunnel stanza/list conflict", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"gr-0/0/0": {
				Name: "gr-0/0/0",
				Tunnel: &config.TunnelConfig{
					Name: "gr-0-0-0", RoutingInstance: "red",
				},
				Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
		}
		cfg.RoutingInstances = []*config.RoutingInstanceConfig{
			{Name: "blue", Interfaces: []string{"gr-0/0/0"}},
			{Name: "red"},
		}
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
			assertRenderedKeepMaster18605(t, result, name, want != "")
			return
		}
	}
	t.Fatalf("no networkd model for %s: %+v", name, result.ManagedInterfaces)
}

func assertRenderedKeepMaster18605(t *testing.T, result *CompileResult, name string, want bool) {
	t.Helper()

	// Apply writes the generated files before reload. Fail the stubbed reload
	// deliberately so the test checks real output without running the tail's
	// host sysctl writes.
	networkd.ResetReloadDebtForTest()
	t.Cleanup(networkd.ResetReloadDebtForTest)
	binDir := t.TempDir()
	networkctl := filepath.Join(binDir, "networkctl")
	script := "#!/bin/sh\nif [ \"$1\" = reload ]; then exit 1; fi\nexit 0\n"
	if err := os.WriteFile(networkctl, []byte(script), 0o755); err != nil {
		t.Fatalf("write networkctl stub: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	networkDir := t.TempDir()
	err := networkd.NewInDir(networkDir).Apply(result.ManagedInterfaces)
	networkd.ResetReloadDebtForTest()
	if err == nil || err.Error() != "networkctl reload: exit status 1" {
		t.Fatalf("networkd Apply error = %v, want only the stubbed reload failure", err)
	}
	if err := networkd.NewInDir(networkDir).Apply(result.ManagedInterfaces); err != nil {
		t.Fatalf("byte-identical Apply after debt reset = %v, want no error", err)
	}

	path := filepath.Join(networkDir, networkd.FilePrefix+name+".network")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rendered networkd file for %s: %v", name, err)
	}
	got := strings.Contains(string(content), "KeepMaster=yes\n")
	if got != want {
		t.Fatalf("%s rendered KeepMaster = %v, want %v; file:\n%s", name, got, want, content)
	}
}

// #18607 combined shape (Kimi residual): a DISABLED routing-instance
// member row is compiled by the dataplane (Disable reaches the row via
// the interface config) and must render KeepMaster=yes through
// networkd.Apply — the daemon binds RI members without a disable check.
func TestDisabledRoutingInstanceMemberKeepsMaster18607(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Disable: true, Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", Interfaces: []string{"ge-0/0/0"},
	}}
	result := compileNetworkdRows18605(t, cfg, "ge-0-0-0")
	assertVRFName18605(t, result, "ge-0-0-0", "vrf-blue")
	// The combined cell must prove the compiled row really is the
	// always-down shape (Disable propagated), not merely a VRF row
	// that happens to render KeepMaster through the enabled arm.
	found := false
	for _, row := range result.ManagedInterfaces {
		if row.Name == "ge-0-0-0" {
			found = true
			if !row.Disable {
				t.Fatalf("compiled RI member row lost its Disable flag: %+v", row)
			}
		}
	}
	if !found {
		t.Fatal("compiled result has no ge-0-0-0 row")
	}
	assertRenderedKeepMaster18605(t, result, "ge-0-0-0", true)
}
