package config

import "testing"

const (
	wg6941Priv  = "3de6404700006875ca73c26dfc1f4a50fa627601e24664d40310b975b40514c2"
	wg6941PeerX = "5a9303297e0c6babb14de8cfcc2a84491da7f760ec8bd9729494f71d17829980"
	wg6941PeerA = "6e2cc0919a4d6127938b531ab7cd6e69a908a780fd2b73083b31cba690abc177"
)

func wg6941Base() []string {
	return []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wg6941Priv,
		"set interfaces wg0 tunnel wireguard peer " + wg6941PeerX + " allowed-ips 10.100.0.0/24",
	}
}

func wg6941Compile(t *testing.T, extra ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range append(wg6941Base(), extra...) {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// TestWireguardUnitSharesTheInterfaceDevice6941 is the fail-on-revert gate for
// the shared-device rule.
//
// An interface-level `tunnel mode wireguard` is ONE persistent TUN with exactly
// ONE emitted endpoint (#1910), so at most one device can carry its traffic. A
// unit that stays on that mode must therefore resolve to the interface device;
// giving it its own uN device produced a netdev holding the unit's ADDRESSES
// that could never hold an endpoint.
func TestWireguardUnitSharesTheInterfaceDevice6941(t *testing.T) {
	cfg := wg6941Compile(t,
		"set interfaces wg0 unit 3 family inet address 10.66.3.1/24",
		"set interfaces wg0 unit 3 tunnel wireguard peer "+wg6941PeerA+" allowed-ips 10.200.1.0/24")

	if got := cfg.TunnelNameMap()["wg0.3"]; got != "wg0" {
		t.Errorf("TunnelNameMap[wg0.3] = %q, want %q — a unit on the interface's WireGuard "+
			"mode shares the interface device, because the interface has exactly one "+
			"endpoint and so at most one device that can carry it", got, "wg0")
	}
	if got := cfg.Interfaces.Interfaces["wg0"].Units[3].Tunnel.Name; got != "wg0" {
		t.Errorf("unit 3 tunnel device = %q, want %q", got, "wg0")
	}
}

// TestWireguardUnitAddressAndEndpointShareOneDevice6941 pins the property the
// divergence actually broke, on the shape that exposes it.
//
// With unit 0 plain and unit 3 carrying the tunnel stanza, the emitted endpoint
// is keyed to the LOWEST unit (0) and so resolved to unit 0's device. Unit 3's
// address resolved to unit 3's device. Before this fix those were `wg0` and
// `wg0u3`: unit 3's peer was installed on one netdev while unit 3's address sat
// on another that carried no endpoint at all. That only became reachable once
// #7786 made per-unit peers actually install — before it they were discarded,
// so the orphan device referenced nothing.
func TestWireguardUnitAddressAndEndpointShareOneDevice6941(t *testing.T) {
	cfg := wg6941Compile(t,
		"set interfaces wg0 unit 0 family inet address 10.66.0.1/24",
		"set interfaces wg0 unit 3 family inet address 10.66.3.1/24",
		"set interfaces wg0 unit 3 tunnel wireguard peer "+wg6941PeerA+" allowed-ips 10.200.1.0/24")

	nameMap := cfg.TunnelNameMap()
	eps := EmitTunnelEndpointNames(cfg)
	if len(eps) != 1 {
		t.Fatalf("interface-level WireGuard emits exactly one endpoint; got %d", len(eps))
	}
	// Precondition: the endpoint really is keyed to the OTHER unit, which is
	// what made the two devices diverge. Without this the fixture could drift
	// into keying on unit 3 and pass for the wrong reason.
	if eps[0].Name != "wg0.0" {
		t.Fatalf("fixture precondition: the endpoint must be keyed to unit 0, the lowest "+
			"configured unit, so that it is NOT the unit carrying the tunnel stanza; got %q",
			eps[0].Name)
	}

	endpointDevice := nameMap[eps[0].Name]
	unitDevice := nameMap["wg0.3"]
	if endpointDevice != unitDevice {
		t.Errorf("the endpoint binds %q while the unit whose peer it serves has its address "+
			"on %q. The WireGuard engine and that unit's address are on different netdevs, "+
			"and the second one can never carry an endpoint",
			endpointDevice, unitDevice)
	}
	if endpointDevice != "wg0" {
		t.Errorf("both must be the interface device %q; got %q", "wg0", endpointDevice)
	}
}

// TestWireguardModeOverridingUnitKeepsItsOwnDevice6941 is the scoping guard.
//
// A unit that writes its own non-WireGuard mode is a different kind of tunnel.
// collectAppliedTunnels submits a TunnelConfig per record and pkg/routing keys
// its desired set by Name, so sharing the name would hand routing two records
// for ONE device with DIFFERENT modes -- one taking the WireGuard path and one
// the kernel-tunnel/anchor path. That is a conflict, not the benign
// same-name/same-mode sharing that key already relies on.
func TestWireguardModeOverridingUnitKeepsItsOwnDevice6941(t *testing.T) {
	for _, mode := range []string{"gre", "ipip"} {
		t.Run(mode, func(t *testing.T) {
			cfg := wg6941Compile(t,
				"set interfaces wg0 unit 3 tunnel mode "+mode,
				"set interfaces wg0 unit 3 tunnel source 10.1.1.1",
				"set interfaces wg0 unit 3 tunnel destination 10.1.1.2")
			if got := cfg.TunnelNameMap()["wg0.3"]; got != "wg0u3" {
				t.Errorf("a `mode %s` unit must keep its own device: TunnelNameMap[wg0.3] = "+
					"%q, want %q. Sharing it would give routing two records for one device "+
					"with different modes", mode, got, "wg0u3")
			}
		})
	}
}

// TestPerUnitWireguardInterfaceUnaffected6941 pins that a WireGuard interface
// with NO interface-level stanza is untouched. Each of its units emits its own
// endpoint through the per-unit branch, so each genuinely needs its own device
// -- the shared-device rule must not reach them.
func TestPerUnitWireguardInterfaceUnaffected6941(t *testing.T) {
	tree := &ConfigTree{}
	for _, c := range []string{
		"set interfaces wg0 unit 0 tunnel mode wireguard",
		"set interfaces wg0 unit 0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 unit 0 tunnel wireguard private-key " + wg6941Priv,
		"set interfaces wg0 unit 0 tunnel wireguard peer " + wg6941PeerX + " allowed-ips 10.100.0.0/24",
		"set interfaces wg0 unit 1 tunnel mode wireguard",
		"set interfaces wg0 unit 1 tunnel wireguard listen-port 51999",
		"set interfaces wg0 unit 1 tunnel wireguard private-key " + wg6941Priv,
		"set interfaces wg0 unit 1 tunnel wireguard peer " + wg6941PeerA + " allowed-ips 10.200.1.0/24",
	} {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	nameMap := cfg.TunnelNameMap()
	if nameMap["wg0.0"] != "wg0" || nameMap["wg0.1"] != "wg0u1" {
		t.Errorf("per-unit WireGuard interfaces keep one device each: got wg0.0=%q wg0.1=%q, "+
			"want %q and %q", nameMap["wg0.0"], nameMap["wg0.1"], "wg0", "wg0u1")
	}
	if got := len(EmitTunnelEndpointNames(cfg)); got != 2 {
		t.Errorf("two per-unit WireGuard units emit two endpoints; got %d", got)
	}
}
