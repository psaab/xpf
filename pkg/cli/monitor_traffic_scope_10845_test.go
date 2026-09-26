package cli

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
)

func TestMonitorTrafficConfiguredInterfaceAllowlist10845(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
				80: {Number: 80, VlanID: 180},
			}},
			"fab0":      {Name: "fab0"},
			"nil-iface": nil,
		}},
	}

	for _, tc := range []struct {
		requested string
		want      string
	}{
		{"ge-0/0/0", "ge-0-0-0"},
		{"ge-0-0-0", "ge-0-0-0"},
		{"ge-0/0/0.80", "ge-0-0-0.180"},
		{"fab0", "fab0"},
	} {
		t.Run(tc.requested, func(t *testing.T) {
			got, err := resolveMonitorTrafficInterface(cfg, tc.requested, false)
			if err != nil {
				t.Fatalf("resolveMonitorTrafficInterface(%q): %v", tc.requested, err)
			}
			if got != tc.want {
				t.Errorf("resolveMonitorTrafficInterface(%q) = %q, want %q", tc.requested, got, tc.want)
			}
		})
	}
}

func TestMonitorTrafficHostOverrideIsCanonicalized10845(t *testing.T) {
	command, result := cmdtree.Canonicalize(cmdtree.OperationalTree,
		[]string{"monitor", "traffic", "interface", "fab0", "matching", "tcp", "port", "80",
			"allow-host-interface", "count", "4"})
	if result != cmdtree.CanonicalOK {
		t.Fatalf("host override command canonicalization = %v, want CanonicalOK", result)
	}
	if got, want := strings.Join(command, " "),
		"monitor traffic interface fab0 matching tcp port 80 allow-host-interface count 4"; got != want {
		t.Fatalf("canonical command = %q, want %q", got, want)
	}
}

func TestMonitorTrafficHostInterfaceRequiresOverride10845(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{}}}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list host interfaces: %v", err)
	}
	var hostInterface string
	for _, iface := range interfaces {
		if _, configured := resolveConfiguredMonitorTrafficInterface(cfg, iface.Name); !configured {
			hostInterface = iface.Name
			break
		}
	}
	if hostInterface == "" {
		t.Skip("no unconfigured host interface available")
	}

	if _, err := resolveMonitorTrafficInterface(cfg, hostInterface, false); err == nil || !strings.Contains(err.Error(), monitorTrafficHostInterfaceFlag) {
		t.Fatalf("unconfigured host interface without override error = %v, want an error naming %q", err, monitorTrafficHostInterfaceFlag)
	}
	if got, err := resolveMonitorTrafficInterface(cfg, hostInterface, true); err != nil || got != hostInterface {
		t.Fatalf("explicit host override resolved to (%q, %v), want (%q, nil)", got, err, hostInterface)
	}
	if _, err := resolveMonitorTrafficInterface(nil, hostInterface, false); err == nil {
		t.Fatal("nil config allowed an unconfigured host interface without the override")
	}
}

func TestMonitorTrafficHandlerRejectsUnconfiguredInterface10845(t *testing.T) {
	c := &CLI{}
	err := c.handleMonitorTraffic([]string{"interface", "lo"})
	if err == nil || !strings.Contains(err.Error(), monitorTrafficHostInterfaceFlag) {
		t.Fatalf("handleMonitorTraffic on an unconfigured interface = %v, want rejection naming %q",
			err, monitorTrafficHostInterfaceFlag)
	}
}
func TestMonitorTrafficHostOverrideFlagAndCaptureMapping10845(t *testing.T) {
	args, allowHost := splitMonitorTrafficHostOverride([]string{
		"interface", "lo", "matching", "tcp", "port", "80", "allow-host-interface", "count", "4",
	})
	if !allowHost {
		t.Fatal("allow-host-interface flag was not recognized")
	}
	iface, filter, count, err := parseMonitorTrafficArgs(args)
	if err != nil {
		t.Fatalf("parse after removing host override: %v", err)
	}
	if iface != "lo" || filter != "tcp port 80" || count != "4" {
		t.Fatalf("parsed (iface=%q, filter=%q, count=%q), want (lo, tcp port 80, 4)", iface, filter, count)
	}

	got := monitorTrafficCaptureLine("enp2s0", "fab0")
	want := "Capturing on enp2s0 (requested fab0) (Ctrl+C to stop)..."
	if got != want {
		t.Fatalf("capture mapping line = %q, want %q", got, want)
	}
}
