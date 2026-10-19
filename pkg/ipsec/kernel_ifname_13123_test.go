package ipsec

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13123 (D10-06): resolveInterfaceAddressFamily resolved a gateway's
// external-interface to a kernel address through config.LinuxIfName, which
// only rewrites "/" -> "-". It therefore PRESERVES the Junos unit suffix:
// `ge-0/0/0.0` -> `ge-0-0-0.0`, `irb.0` -> `irb.0`, a unit whose vlan-id
// differs from its number -> `ge-0-0-0.10` for vlan-id 100. None of those
// is a kernel netdev, so net.InterfaceByName missed, the DHCP/SLAAC/runtime
// address on the unit was never found, and the #11689 fail-closed render
// then skipped (unloaded) the VPN. cfg.ResolveKernelIfName is the resolver
// that knows the unit-0 collapse, the vlan-id device, the IRB bridge and
// the tunnel device.
//
// The sibling defect in the same finding: resolveConfiguredInterfaceAddress
// qualified a link-local result with the UNIT-LESS base name, so a VLAN
// unit produced %ge-0-0-0 and an IRB unit %irb — neither a netdev charon
// can if_nametoindex. The zone must be the unit's own kernel device.
//
// The kernel cells are hermetic in the same way the probe that validated
// this finding was: they discover a live host interface with an address
// and drive PrepareConfig with its `.0` spelling, so they need no fixture
// addresses and no network. On a host with no addressed non-loopback
// interface they skip rather than pass vacuously — and the configured
// zone cells below still bind the fix on such a host.

func hostAddressedIface13123(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if resolveKernelInterfaceAddress(iface.Name, 0) != "" {
			return iface.Name
		}
	}
	t.Skip("no addressed non-loopback host interface; kernel cells cannot run")
	return ""
}

func gatewayCfg13123(ifaceRef string) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{},
		},
		Security: config.SecurityConfig{IPsec: config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"gw": {Name: "gw", Address: "203.0.113.1", ExternalIface: ifaceRef},
			},
			VPNs: map[string]*config.IPsecVPN{
				"vpn": {PSK: "fixture-secret", Gateway: "gw", LocalID: "10.0.1.0/24", RemoteID: "10.0.2.0/24"},
			},
		}},
	}
}

// The canonical Junos unit-0 spelling of a live kernel interface must
// resolve the SAME runtime address the bare spelling does, through
// PrepareConfig — the entry point the daemon apply and CLI commit paths
// call — and the VPN must render rather than be skipped fail-closed.
func TestUnit0ExternalInterfaceResolvesKernelAddress13123(t *testing.T) {
	host := hostAddressedIface13123(t)

	bare := PrepareConfig(gatewayCfg13123(host))
	if bare.Gateways["gw"].LocalAddress == "" {
		t.Fatalf("control: bare %q did not resolve a kernel address", host)
	}

	unit0 := gatewayCfg13123(host + ".0")
	// Model the authored interface the way a real config carries it: a
	// DHCP unit with no static address, so the configured-address path
	// misses and only the kernel lookup can answer.
	unit0.Interfaces.Interfaces[host] = &config.InterfaceConfig{
		Name:  host,
		Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}},
	}
	prepared := PrepareConfig(unit0)
	if prepared.Gateways["gw"].LocalAddress != bare.Gateways["gw"].LocalAddress {
		t.Fatalf("external-interface %q resolved %q, want the bare spelling's %q: "+
			"the unit suffix reached net.InterfaceByName unresolved",
			host+".0", prepared.Gateways["gw"].LocalAddress, bare.Gateways["gw"].LocalAddress)
	}
	_, rendered, err := (&Manager{}).renderConfig(prepared)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	// #15024: rendered is keyed by gateway gw, not VPN vpn.
	if !rendered["gw"] {
		t.Fatalf("VPN on external-interface %q was skipped fail-closed despite a live kernel address", host+".0")
	}
}

// The resolver must name the unit's actual kernel device for every shape
// ResolveKernelIfName distinguishes from LinuxIfName. These pin the NAME
// derivation through the public resolver contract the fix must use; the
// live cells above prove the name is then looked up.
func TestKernelNameDerivation13123(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0, DHCP: true},
					10: {Number: 10, VlanID: 100, DHCP: true},
				}},
				"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth0"},
				"reth0":    {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}}},
				"irb": {Name: "irb", Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0, DHCP: true},
					10: {Number: 10, Addresses: []string{"fe80::1/64"}},
				}},
				"gr-0/0/0": {Name: "gr-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
			},
		},
		BridgeDomains: []*config.BridgeDomainConfig{
			{Name: "bd10", VlanIDs: []int{10}, RoutingInterface: "irb.10"},
		},
	}
	for ref, want := range map[string]string{
		"ge-0/0/0.0":  "ge-0-0-0",     // unit-0 collapse
		"reth0.0":     "ge-0-0-1",     // reth member, unit-0 collapse
		"ge-0/0/0.10": "ge-0-0-0.100", // vlan-id, not unit number
		"irb.0":       "irb",          // unit-0 collapse, no bridge for unit 0
		"irb.10":      "br-bd10",      // IRB bridge device
		"gr-0/0/0.0":  "gr-0-0-0",     // tunnel unit-0 collapse
	} {
		if got := cfg.ResolveKernelIfName(ref); got != want {
			t.Errorf("ResolveKernelIfName(%q) = %q, want %q", ref, got, want)
		}
		if got := config.LinuxIfName(cfg.ResolveReth(ref)); got == want {
			t.Errorf("fixture broken: LinuxIfName path already yields %q for %q, cell cannot discriminate", want, ref)
		}
	}
}

// A link-local address configured on a VLAN or IRB unit must be qualified
// with THAT UNIT's kernel device — the device charon binds by — not the
// unit-less base.
func TestConfiguredLinkLocalZoneUsesUnitKernelDevice13123(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					10: {Number: 10, VlanID: 100, Addresses: []string{"fe80::2/64"}},
				}},
				"irb": {Name: "irb", Units: map[int]*config.InterfaceUnit{
					10: {Number: 10, Addresses: []string{"fe80::1/64"}},
				}},
			},
		},
		BridgeDomains: []*config.BridgeDomainConfig{
			{Name: "bd10", VlanIDs: []int{10}, RoutingInterface: "irb.10"},
		},
	}
	for ref, want := range map[string]string{
		"ge-0/0/0.10": "fe80::2%ge-0-0-0.100",
		"irb.10":      "fe80::1%br-bd10",
	} {
		if got := resolveConfiguredInterfaceAddress(cfg, ref, 6); got != want {
			t.Errorf("resolveConfiguredInterfaceAddress(%q, 6) = %q, want %q", ref, got, want)
		}
	}

	// Control: unit 0 keeps the bare device zone, byte-identical to the
	// pre-fix spelling for the case that already worked.
	unit0 := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"fe80::3/64"}},
				}},
			},
		},
	}
	if got := resolveConfiguredInterfaceAddress(unit0, "ge-0/0/0.0", 6); got != "fe80::3%ge-0-0-0" {
		t.Errorf("unit-0 control = %q, want fe80::3%%ge-0-0-0", got)
	}
}
